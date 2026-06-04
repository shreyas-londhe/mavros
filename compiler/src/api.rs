use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    Project,
    abi_helpers::ordered_params_from_btreemap,
    compiler::{Field, codegen::hlssa_to_r1cs::R1CS},
    driver::Driver,
    vm::interpreter,
};
use mavros_artifacts::InputValueOrdered;
use noirc_abi::input_parser::Format;

type Error = Box<dyn std::error::Error>;

pub fn compile_to_r1cs(root: PathBuf, draw_graphs: bool) -> Result<(Driver, R1CS), Error> {
    let project = Project::new(root)?;
    let mut driver = Driver::new(project, draw_graphs);
    driver.run_noir_compiler()?;
    driver.make_struct_access_static()?;
    driver.monomorphize()?;
    driver.explictize_witness()?;

    let r1cs = driver.generate_r1cs()?;
    Ok((driver, r1cs))
}

pub fn read_prover_inputs(
    root: &Path,
    abi: &noirc_abi::Abi,
) -> Result<Vec<InputValueOrdered>, Error> {
    let file_path = root.join("Prover.toml");
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();

    let Some(format) = Format::from_ext(ext) else {
        return Err(format!("unsupported input file extension: {ext}").into());
    };

    let inputs_src = fs::read_to_string(&file_path)?;
    let inputs = format
        .parse(&inputs_src, abi)
        .map_err(|e| format!("failed to parse inputs: {e}"))?;
    let ordered_params = ordered_params_from_btreemap(abi, &inputs);

    Ok(ordered_params)
}

pub fn run_witgen_from_binary(
    binary: &mut [u64],
    r1cs: &R1CS,
    params: &[InputValueOrdered],
) -> interpreter::WitgenResult {
    interpreter::run(binary, r1cs.witness_layout, r1cs.constraints_layout, params)
}

/// Phase 1: execute the VM and produce the pre-commitment witness. Returns
/// intermediate state needed by [`run_witgen_phase2`].
pub fn run_witgen_phase1(
    binary: &mut [u64],
    r1cs: &R1CS,
    params: &[InputValueOrdered],
) -> interpreter::Phase1Result {
    interpreter::run_phase1(binary, r1cs.witness_layout, r1cs.constraints_layout, params)
}

/// Phase 2: given real Fiat-Shamir challenges, complete witness generation.
pub fn run_witgen_phase2(
    phase1: interpreter::Phase1Result,
    challenges: &[Field],
    r1cs: &R1CS,
) -> interpreter::WitgenResult {
    interpreter::run_phase2(
        phase1,
        challenges,
        r1cs.witness_layout,
        r1cs.constraints_layout,
    )
}

pub fn compile_witgen(driver: &mut Driver) -> Result<Vec<u64>, Error> {
    Ok(driver.compile_witgen()?)
}

pub fn compile_ad(driver: &Driver) -> Result<Vec<u64>, Error> {
    Ok(driver.compile_ad()?)
}

pub fn run_ad_from_binary(
    binary: &mut [u64],
    r1cs: &R1CS,
    coeffs: &[Field],
) -> (
    Vec<Field>,
    Vec<Field>,
    Vec<Field>,
    crate::vm::bytecode::AllocationInstrumenter,
) {
    interpreter::run_ad(binary, coeffs, r1cs.witness_layout, r1cs.constraints_layout)
}

pub fn random_ad_coeffs(r1cs: &R1CS) -> Vec<Field> {
    use ark_ff::UniformRand as _;
    let mut rng = rand::thread_rng();
    (0..r1cs.constraints.len())
        .map(|_| ark_bn254::Fr::rand(&mut rng))
        .collect()
}

pub fn check_witgen(r1cs: &R1CS, res: &interpreter::WitgenResult) -> bool {
    r1cs.check_witgen_output(
        &res.out_wit_pre_comm,
        &res.out_wit_post_comm,
        &res.out_a,
        &res.out_b,
        &res.out_c,
    )
}

pub fn check_ad(r1cs: &R1CS, coeffs: &[Field], a: &[Field], b: &[Field], c: &[Field]) -> bool {
    r1cs.check_ad_output(coeffs, a, b, c)
}

pub fn debug_output_dir(driver: &Driver) -> PathBuf {
    driver.get_debug_output_dir()
}

#[cfg(test)]
mod tier2_tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../noir_tests").join(name)
    }

    /// Mavros lowers a program whose integer constants exceed the Goldilocks modulus to a
    /// valid R1CS. The mono AST carries those constants exactly (field-agnostic `SignedField`)
    /// and Mavros lowers them natively (`to_u128` -> `Constant::U`), independent of the source
    /// field.
    ///
    /// Under bn254 this validates the full Noir -> mono AST -> R1CS lowering. Under
    /// `--features goldilocks` the crate still *builds* (proving the intake is field-agnostic
    /// — see `noir_field_to_bn254`), but end-to-end compilation is blocked by the auto-injected
    /// **bn254 stdlib**, which is not Goldilocks-compatible (254-bit `Field` literals, `Field`
    /// constants >= p, bn254 hashing). That stdlib port is Phase 2 / Cluster B, out of scope
    /// here; we assert the failure originates in the stdlib, not in Mavros's intake.
    #[test]
    fn compiles_beyond_field_u64_to_r1cs() {
        let result = compile_to_r1cs(fixture("goldilocks_u64"), false);

        #[cfg(not(feature = "goldilocks"))]
        {
            let (_driver, r1cs) = result.unwrap();
            assert!(!r1cs.constraints.is_empty(), "expected a non-empty R1CS");
            println!("goldilocks_u64 -> {} constraints", r1cs.constraints.len());
        }
        #[cfg(feature = "goldilocks")]
        {
            let err = match result {
                Ok(_) => panic!("expected the bn254 stdlib to block goldilocks compile"),
                Err(e) => e,
            };
            let msg = format!("{err:?}");
            assert!(
                msg.contains("cannot fit into `Field`") || msg.contains("Integer literal is too large"),
                "expected a stdlib field-range/literal error, got: {msg}"
            );
        }
    }
}
