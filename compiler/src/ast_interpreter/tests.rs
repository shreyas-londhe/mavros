use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use crate::driver::Driver;
use crate::project::Project;

use super::{
    InterpretError, Value, expected_return_from_prover_toml, inputs_from_prover_toml, interpret,
    interpret_with_inputs,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../noir_tests")
        .join(name)
}

/// Compile a fixture through Noir's frontend + monomorphizer and interpret the resulting AST.
fn interpret_fixture(name: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let project = Project::new(fixture(name))?;
    let mut driver = Driver::new(project, false);
    driver.run_noir_compiler()?;
    let program = driver.monomorphized_program();
    Ok(interpret(program)?)
}

/// Baseline differential oracle under bn254: the self-checking corpus program interprets to a
/// clean `Unit` with every `assert` holding. This proves the interpreter agrees with Noir's
/// own semantics on real monomorphized output. Under `--features goldilocks` the same source
/// cannot yet be compiled (the auto-injected bn254 stdlib blocks it — CRY-9), so the Goldilocks
/// side of the differential is gated until the stdlib port lands; the interpreter itself is
/// already field-agnostic and will validate the Goldilocks AST unchanged once it does.
#[cfg(not(feature = "goldilocks"))]
#[test]
fn interprets_basic_corpus_program() {
    let result = interpret_fixture("interp_basic").expect("interpretation should succeed");
    assert_eq!(result, Value::Unit, "main returns unit");
}

/// The oracle must bite: a program whose (computed, non-const-folded) assertion is false
/// interprets to an `AssertionFailed`, not a clean pass. Without this the green result above
/// would be meaningless.
#[cfg(not(feature = "goldilocks"))]
#[test]
fn detects_false_assertion() {
    let project = Project::new(fixture("interp_assert_fail")).expect("project");
    let mut driver = Driver::new(project, false);
    driver.run_noir_compiler().expect("frontend compile");
    match interpret(driver.monomorphized_program()) {
        Err(InterpretError::AssertionFailed { .. }) => {}
        other => panic!("expected AssertionFailed, got {other:?}"),
    }
}

/// A program whose `main` takes inputs interprets correctly when those inputs are supplied from
/// `Prover.toml`. `assert_statement` is `main(x: Field, y: pub Field)` with `x == y == 3`, so a
/// clean `Unit` proves the input bridge feeds the right values.
#[cfg(not(feature = "goldilocks"))]
#[test]
fn interprets_program_with_inputs() {
    let program_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../noir/test_programs/execution_success/assert_statement");
    if !program_dir.is_dir() {
        return; // corpus not checked out; nothing to assert
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("pkg");
    copy_dir(&program_dir, &root);

    let project = Project::new(root.clone()).unwrap();
    let mut driver = Driver::new(project, false);
    driver.run_noir_compiler().unwrap();
    let program = driver.monomorphized_program();
    let toml = std::fs::read_to_string(root.join("Prover.toml")).unwrap();
    let inputs = inputs_from_prover_toml(program, driver.abi(), &toml).unwrap();

    let result = interpret_with_inputs(program, inputs).unwrap();
    assert_eq!(result, Value::Unit);
}

/// Differential correctness: the interpreter's computed return value matches the expected output
/// Noir's corpus records in `Prover.toml`. `arithmetic_binary_operations` returns 10 (a u64),
/// so this verifies the actual value, not merely that interpretation didn't error.
#[cfg(not(feature = "goldilocks"))]
#[test]
fn interpreter_return_matches_recorded_expected() {
    let program_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../noir/test_programs/execution_success/arithmetic_binary_operations");
    if !program_dir.is_dir() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("pkg");
    copy_dir(&program_dir, &root);

    let project = Project::new(root.clone()).unwrap();
    let mut driver = Driver::new(project, false);
    driver.run_noir_compiler().unwrap();
    let program = driver.monomorphized_program();
    let toml = std::fs::read_to_string(root.join("Prover.toml")).unwrap();

    let inputs = inputs_from_prover_toml(program, driver.abi(), &toml).unwrap();
    let value = interpret_with_inputs(program, inputs).unwrap();
    let expected = expected_return_from_prover_toml(program, driver.abi(), &toml)
        .unwrap()
        .expect("this program records a return value");

    assert_eq!(
        value, expected,
        "interpreter output must match Noir's recorded return"
    );
}

// ---------------------------------------------------------------------------
// Corpus survey (manual): run Noir's own `execution_success` programs through the
// interpreter and bucket the outcomes, to map the coverage frontier. Run with:
//   cargo test -p mavros-compiler --no-default-features --lib \
//       ast_interpreter::tests::survey -- --ignored --nocapture
// It is `#[ignore]`d because it compiles hundreds of external programs (slow) and is a
// reporting tool, not a pass/fail gate. Programs with a `Prover.toml` have their inputs fed in
// via `inputs_from_prover_toml`; multi-member workspaces are skipped.
// ---------------------------------------------------------------------------

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

/// Outcome bucket for one program. `Unsupported` keeps the message so the report shows which
/// constructs block coverage; `AssertFailed` on a known-passing Noir program is a red flag
/// (interpreter bug or a semantics mismatch), not expected.
fn classify(program_dir: &Path) -> String {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("pkg");
    copy_dir(program_dir, &root);

    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        let project = Project::new(root.clone()).map_err(|e| format!("project: {e}"))?;
        let mut driver = Driver::new(project, false);
        driver
            .run_noir_compiler()
            .map_err(|e| format!("compile: {e}"))?;
        let program = driver.monomorphized_program();
        let prover_src = std::fs::read_to_string(root.join("Prover.toml")).ok();

        let inputs = match &prover_src {
            Some(src) => inputs_from_prover_toml(program, driver.abi(), src)
                .map_err(|e| format!("inputs: {e}"))?,
            None => Vec::new(),
        };
        let value =
            interpret_with_inputs(program, inputs).map_err(|e| format!("interpret: {e}"))?;

        // Differential check: when the corpus records an expected return value, compare the
        // interpreter's computed output against it. This is the real correctness signal — a
        // genuine value mismatch (not just "did it error") surfaces here as MISMATCH.
        match &prover_src {
            Some(src) => match expected_return_from_prover_toml(program, driver.abi(), src)
                .map_err(|e| format!("expected: {e}"))?
            {
                Some(expected) if expected == value => Ok("pass: return verified".to_string()),
                Some(_) => Err("MISMATCH: return value disagrees with Noir".to_string()),
                None => Ok("pass: no recorded return".to_string()),
            },
            None => Ok("pass: no recorded return".to_string()),
        }
    }));

    match outcome {
        Err(payload) => {
            // A panic is a failure, not a neutral outcome: capture the message so interpreter
            // panics (e.g. an arithmetic helper that should have returned an error) are visible
            // in the report rather than lumped into one opaque bucket.
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            let first_line = msg.lines().next().unwrap_or("").trim();
            if first_line.is_empty() {
                "PANIC".to_string()
            } else {
                format!("PANIC: {first_line}")
            }
        }
        Ok(Ok(bucket)) => bucket,
        Ok(Err(msg)) => {
            if msg.starts_with("MISMATCH") {
                msg
            } else if let Some(rest) = msg.strip_prefix("interpret: unsupported construct: ") {
                // Normalise to the construct kind (drop any trailing detail like a name).
                let kind = rest.split([':', '\'']).next().unwrap_or(rest).trim();
                format!("unsupported: {kind}")
            } else if msg.starts_with("interpret: assertion failed") {
                "ASSERT_FAILED (unexpected!)".to_string()
            } else if msg.starts_with("compile:") {
                "compile_error".to_string()
            } else if let Some(rest) = msg.strip_prefix("expected: ") {
                let kind = rest.split(['(', ':']).next().unwrap_or(rest).trim();
                format!("expected_return_error: {kind}")
            } else if let Some(rest) = msg.strip_prefix("inputs: ") {
                let kind = rest.split(['(', ':']).next().unwrap_or(rest).trim();
                format!("input_error: {kind}")
            } else if let Some(rest) = msg.strip_prefix("interpret: ") {
                let kind = rest.split([':', '(']).next().unwrap_or(&rest).trim();
                format!("interpret_error: {kind}")
            } else {
                msg
            }
        }
    }
}

#[cfg(not(feature = "goldilocks"))]
#[test]
#[ignore = "manual coverage survey over Noir's execution_success corpus"]
fn survey_execution_success_corpus() {
    use std::collections::BTreeMap;

    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../noir/test_programs/execution_success");
    assert!(corpus.is_dir(), "corpus not found at {}", corpus.display());

    let mut buckets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut total = 0;
    for entry in std::fs::read_dir(&corpus).unwrap() {
        let dir = entry.unwrap().path();
        let manifest = dir.join("Nargo.toml");
        if !dir.is_dir() || !manifest.exists() {
            continue;
        }
        // Workspaces have multiple members; the driver picks one arbitrarily, which doesn't match
        // the workspace's default-member `main`, so skip them rather than report a false failure.
        if std::fs::read_to_string(&manifest)
            .map(|s| s.contains("[workspace]"))
            .unwrap_or(false)
        {
            continue;
        }
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        total += 1;
        buckets.entry(classify(&dir)).or_default().push(name);
    }

    println!("\n=== interpreter coverage over {total} execution_success programs ===");
    for (bucket, names) in &buckets {
        println!("\n[{}]  {}", names.len(), bucket);
        for name in names {
            println!("    {name}");
        }
    }
}
