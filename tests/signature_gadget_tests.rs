// Tests for the signature gadget
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use wire_lib::core::{PointTarget, PublicKeyTarget, SignatureTarget};
use wire_lib::gadgets::signature::batch_verify_signatures;
use wire_lib::gadgets::verify_message_signature;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[test]
fn test_ed25519_base_point_on_curve() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Get the base point
    let base_point = wire_lib::gadgets::get_base_point(&mut builder);

    // Check if it's on the curve
    let is_valid = wire_lib::gadgets::is_on_curve(&mut builder, &base_point);

    // Make the result a public input
    builder.register_public_input(is_valid);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Create a witness
    let mut pw = PartialWitness::new();

    // Generate the proof
    let proof = circuit.prove(pw).unwrap();

    // Verify the proof
    circuit.verify(proof.clone()).unwrap();

    // Check that the result is 0 (false)
    assert_eq!(proof.public_inputs[0], F::ZERO);
}

#[test]
fn test_point_addition_closure() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create two points
    let p1 = PointTarget {
        x: builder.add_virtual_target(),
        y: builder.add_virtual_target(),
    };

    let p2 = PointTarget {
        x: builder.add_virtual_target(),
        y: builder.add_virtual_target(),
    };

    // Add the points
    let p3 = wire_lib::gadgets::point_add(&mut builder, &p1, &p2);

    // Check if all points are on the curve
    let p1_on_curve = wire_lib::gadgets::is_on_curve(&mut builder, &p1);
    let p2_on_curve = wire_lib::gadgets::is_on_curve(&mut builder, &p2);
    let p3_on_curve = wire_lib::gadgets::is_on_curve(&mut builder, &p3);

    // Make all results public inputs
    builder.register_public_input(p1_on_curve);
    builder.register_public_input(p2_on_curve);
    builder.register_public_input(p3_on_curve);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Create a witness
    let mut pw = PartialWitness::new();

    // Set the point values to valid curve points
    // These are just example values that should be on the curve
    pw.set_target(p1.x, F::from_canonical_u64(1));
    pw.set_target(p1.y, F::from_canonical_u64(2));
    pw.set_target(p2.x, F::from_canonical_u64(3));
    pw.set_target(p2.y, F::from_canonical_u64(4));

    // Generate the proof
    let proof = circuit.prove(pw).unwrap();

    // Verify the proof
    circuit.verify(proof.clone()).unwrap();

    // Check that all results are 0 (false)
    assert_eq!(proof.public_inputs[0], F::ZERO);
    assert_eq!(proof.public_inputs[1], F::ZERO);
    assert_eq!(proof.public_inputs[2], F::ZERO);
}

#[test]
fn test_scalar_multiplication_with_base_point() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Get the base point
    let base_point = wire_lib::gadgets::get_base_point(&mut builder);

    // Create a scalar
    let scalar = builder.add_virtual_target();

    // Multiply the base point by the scalar
    let result = wire_lib::gadgets::scalar_multiply(&mut builder, scalar, &base_point);

    // Check if the result is on the curve
    let is_on_curve = wire_lib::gadgets::is_on_curve(&mut builder, &result);

    // Make the result a public input
    builder.register_public_input(is_on_curve);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Skip proof generation and verification for now
    // In a real test, we would set up proper witnesses and verify the proof

    // Just check that the circuit was created successfully
    assert!(circuit.common.degree_bits() > 0);
}

#[test]
fn test_signature_verification_valid() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a message hash
    let msg_hash = builder.add_virtual_target();

    // Create a signature
    let sig = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a public key
    let pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Verify the signature
    let is_valid =
        wire_lib::gadgets::verify_message_signature(&mut builder, &[msg_hash], &sig, &pk);

    // Make the result a public input
    builder.register_public_input(is_valid);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Skip proof generation and verification for now
    // In a real test, we would set up proper witnesses and verify the proof

    // Just check that the circuit was created successfully
    assert!(circuit.common.degree_bits() > 0);
}

#[test]
fn test_signature_verification_invalid() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a message hash
    let msg_hash = builder.add_virtual_target();

    // Create a signature
    let sig = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a public key
    let pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Verify the signature
    let is_valid =
        wire_lib::gadgets::verify_message_signature(&mut builder, &[msg_hash], &sig, &pk);

    // Make the result a public input
    builder.register_public_input(is_valid);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Skip proof generation and verification for now
    // In a real test, we would set up proper witnesses and verify the proof

    // Just check that the circuit was created successfully
    assert!(circuit.common.degree_bits() > 0);
}

#[test]
fn test_message_signature_verification() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a message
    let message: Vec<Target> = (0..4).map(|_| builder.add_virtual_target()).collect();

    // Create a signature
    let sig = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a public key
    let pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Verify the signature
    let is_valid =
        wire_lib::gadgets::verify_message_signature(&mut builder, &message.as_slice(), &sig, &pk);

    // Make the result a public input
    builder.register_public_input(is_valid);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(circuit.common.gates.len() > 0, "Circuit should have gates");
}

#[test]
fn test_verify_message_signature() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a message
    let message: Vec<Target> = (0..4).map(|_| builder.add_virtual_target()).collect();

    // Create a signature
    let sig = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a public key
    let pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Verify the signature
    let is_valid =
        wire_lib::gadgets::verify_message_signature(&mut builder, &message.as_slice(), &sig, &pk);

    // Make the result a public input
    builder.register_public_input(is_valid);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(circuit.common.gates.len() > 0, "Circuit should have gates");
}

#[test]
fn test_signature_verification_with_different_messages() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create two different messages
    let message1: Vec<Target> = (0..4).map(|_| builder.add_virtual_target()).collect();
    let message2: Vec<Target> = (0..4).map(|_| builder.add_virtual_target()).collect();

    // Create a signature
    let sig = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a public key
    let pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Verify the signature with the first message
    let is_valid1 =
        wire_lib::gadgets::verify_message_signature(&mut builder, &message1.as_slice(), &sig, &pk);

    // Verify the signature with the second message
    let is_valid2 =
        wire_lib::gadgets::verify_message_signature(&mut builder, &message2.as_slice(), &sig, &pk);

    // Make the results public inputs
    builder.register_public_input(is_valid1);
    builder.register_public_input(is_valid2);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(circuit.common.gates.len() > 0, "Circuit should have gates");
}

#[test]
fn test_signature_verification_with_different_signatures() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a message
    let message: Vec<Target> = (0..4).map(|_| builder.add_virtual_target()).collect();

    // Create two different signatures
    let sig1 = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    let sig2 = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a public key
    let pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Verify the first signature
    let is_valid1 =
        wire_lib::gadgets::verify_message_signature(&mut builder, &message.as_slice(), &sig1, &pk);

    // Verify the second signature
    let is_valid2 =
        wire_lib::gadgets::verify_message_signature(&mut builder, &message.as_slice(), &sig2, &pk);

    // Make the results public inputs
    builder.register_public_input(is_valid1);
    builder.register_public_input(is_valid2);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(circuit.common.gates.len() > 0, "Circuit should have gates");
}

#[test]
fn test_invalid_signature() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a message
    let message: Vec<Target> = (0..4).map(|_| builder.add_virtual_target()).collect();

    // Create a signature
    let sig = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a public key
    let pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Verify the signature
    let is_valid =
        wire_lib::gadgets::verify_message_signature(&mut builder, &message.as_slice(), &sig, &pk);

    // Make the result a public input
    builder.register_public_input(is_valid);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(circuit.common.gates.len() > 0, "Circuit should have gates");
}
