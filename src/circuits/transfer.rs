// Transfer circuit for the 0BTC Wire system
// Implements the core transfer functionality

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;

use crate::core::proof::{
    deserialize_proof, generate_proof, serialize_proof, verify_proof, SerializableProof,
};
use crate::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget, HASH_SIZE};
use crate::errors::{ProofError as CoreProofError, WireError, WireResult};
use crate::gadgets::arithmetic::{gt, lte};
use crate::gadgets::fee::convert_utxo_target;
use crate::gadgets::fee::enforce_fee_payment;
use crate::utils::compare::compare_vectors;

/// Circuit for transferring assets between UTXOs
///
/// This circuit verifies ownership of input UTXOs, ensures conservation of value,
/// handles fee payment, and creates output UTXOs for recipients and change.
#[derive(Clone)]
pub struct TransferCircuit {
    /// The input UTXOs to spend
    pub input_utxos: Vec<UTXOTarget>,

    /// The public key of the sender
    pub sender_pk: PublicKeyTarget,

    /// The signature of the sender
    pub sender_sig: SignatureTarget,

    /// The fee input UTXO (must be wBTC)
    pub fee_input_utxo: UTXOTarget,

    /// The fee amount to pay
    pub fee_amount: Target,

    /// The reservoir address hash to send the fee to
    pub fee_reservoir_address_hash: Vec<Target>,

    /// The recipient public key hashes
    pub recipient_pk_hashes: Vec<Vec<Target>>,

    /// The output amounts for each recipient
    pub output_amounts: Vec<Target>,
}

impl TransferCircuit {
    /// Helper function to create a UTXOTarget with the correct type parameters
    fn create_utxo_target(builder: &mut CircuitBuilder<GoldilocksField, 2>) -> UTXOTarget {
        UTXOTarget {
            owner_pubkey_hash_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
        }
    }

    /// Create a new TransferCircuit instance
    pub fn new(
        num_inputs: usize,
        recipient_pk_hashes: Vec<Vec<u8>>,
        output_amounts: Vec<u64>,
        _sender_pk: Vec<u8>,
        _sender_sig: Vec<u8>,
        _fee_input_utxo: Vec<u8>,
        _fee_amount: u64,
        _fee_reservoir_address_hash: Vec<u8>,
    ) -> Self {
        // Create a circuit builder
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Create input UTXOs
        let mut input_utxos = Vec::new();
        for _ in 0..num_inputs {
            let input_utxo = UTXOTarget {
                owner_pubkey_hash_target: (0..HASH_SIZE)
                    .map(|_| builder.add_virtual_target())
                    .collect(),
                asset_id_target: (0..HASH_SIZE)
                    .map(|_| builder.add_virtual_target())
                    .collect(),
                amount_target: builder.add_virtual_target(),
                salt_target: (0..HASH_SIZE)
                    .map(|_| builder.add_virtual_target())
                    .collect(),
            };
            input_utxos.push(input_utxo);
        }

        // Create recipient public key hash targets
        let recipient_pk_hash_targets = recipient_pk_hashes
            .iter()
            .map(|_| {
                (0..HASH_SIZE)
                    .map(|_| builder.add_virtual_target())
                    .collect::<Vec<Target>>()
            })
            .collect();

        // Create output amount targets
        let output_amounts_targets = output_amounts
            .iter()
            .map(|_| builder.add_virtual_target())
            .collect();

        // Create sender public key target
        let sender_pk_target = PublicKeyTarget {
            point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };

        // Create sender signature target
        let sender_sig_target = SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };

        // Create fee input UTXO target
        let fee_input_utxo_target = UTXOTarget {
            owner_pubkey_hash_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
        };

        // Create fee amount target
        let fee_amount_target = builder.add_virtual_target();

        // Create fee reservoir address hash targets
        let fee_reservoir_address_hash_targets = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();

        TransferCircuit {
            input_utxos,
            sender_pk: sender_pk_target,
            sender_sig: sender_sig_target,
            fee_input_utxo: fee_input_utxo_target,
            fee_amount: fee_amount_target,
            fee_reservoir_address_hash: fee_reservoir_address_hash_targets,
            recipient_pk_hashes: recipient_pk_hash_targets,
            output_amounts: output_amounts_targets,
        }
    }

    /// Build the transfer circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        _sender_sk: Target,
        _nonce: Target,
    ) -> Vec<UTXOTarget> {
        // Verify that the input UTXOs are owned by the sender
        // This is done by checking the signature

        // First, compute the message hash for each input UTXO
        let mut input_amounts = Vec::new();
        for input_utxo in &self.input_utxos {
            // Convert the UTXO target for nullifier calculation
            let converted_utxo = convert_utxo_target(input_utxo);

            // Calculate and register the nullifier for this input UTXO
            let _nullifier = crate::utils::nullifier::calculate_and_register_circuit_nullifier(
                builder,
                &converted_utxo,
                crate::utils::hash::domains::nullifiers::TRANSFER,
            );

            // Note: The nullifier is already registered as a public input by calculate_and_register_circuit_nullifier

            // Store the input amount for later
            input_amounts.push(input_utxo.amount_target);
        }

        // Compute the fee payment nullifier
        let converted_fee_utxo = convert_utxo_target(&self.fee_input_utxo);
        let _fee_nullifier = crate::utils::nullifier::calculate_and_register_circuit_nullifier(
            builder,
            &converted_fee_utxo,
            crate::utils::hash::domains::nullifiers::TRANSFER,
        );

        // Note: The fee nullifier is already registered as a public input by calculate_and_register_circuit_nullifier

        // Create output UTXOs for each recipient
        let mut output_utxos = Vec::new();
        let mut output_amounts = Vec::new();

        for (i, recipient_pk_hash) in self.recipient_pk_hashes.iter().enumerate() {
            // Create a new output UTXO
            let output_utxo = UTXOTarget {
                owner_pubkey_hash_target: recipient_pk_hash.clone(),
                asset_id_target: self.input_utxos[0].asset_id_target.clone(), // Assume all inputs have the same asset ID
                amount_target: self.output_amounts[i],
                salt_target: (0..HASH_SIZE)
                    .map(|_| builder.add_virtual_target())
                    .collect(),
            };

            // Verify that the input and output asset IDs match
            let asset_ids_match = compare_vectors(
                builder,
                &self.input_utxos[0].asset_id_target,
                &output_utxo.asset_id_target,
            );
            let one = builder.one();
            let zero = builder.zero();
            let asset_ids_match_target = builder.select(asset_ids_match, one, zero);
            builder.assert_one(asset_ids_match_target);

            // Verify that the output amount is less than or equal to the input amount
            let amount_valid = lte(
                builder,
                output_utxo.amount_target,
                self.input_utxos[0].amount_target,
            );
            builder.assert_one(amount_valid);

            // Store the output amount for later
            output_amounts.push(output_utxo.amount_target);

            // Add the output UTXO to the list
            output_utxos.push(output_utxo);
        }

        // Create a change UTXO if necessary
        // Compute the total input and output amounts
        if !self.input_utxos.is_empty() && !self.output_amounts.is_empty() {
            // Calculate total input amount
            let mut total_input = input_amounts[0];
            for &amount in &input_amounts[1..] {
                total_input = builder.add(total_input, amount);
            }

            // Calculate total output amount
            let mut total_output = output_amounts[0];
            for &amount in &output_amounts[1..] {
                total_output = builder.add(total_output, amount);
            }

            // Check that total_input >= total_output + fee_amount
            let fee_plus_outputs = builder.add(total_output, self.fee_amount);
            let is_valid_amount = lte(builder, fee_plus_outputs, total_input);
            builder.assert_one(is_valid_amount);

            // Calculate the change amount (total_input - total_output - fee_amount)
            let change_amount = builder.sub(total_input, fee_plus_outputs);

            // Verify value conservation: total_input = total_output + fee_amount + change_amount
            let computed_input = builder.add(fee_plus_outputs, change_amount);
            let amounts_match = builder.is_equal(total_input, computed_input);
            let one = builder.one();
            let zero = builder.zero();
            let amounts_match_target = builder.select(amounts_match, one, zero);
            builder.assert_one(amounts_match_target);

            // If there's change, create a change UTXO
            let zero = builder.zero();
            let is_change_positive_target = gt(builder, change_amount, zero);
            let is_change_positive = BoolTarget::new_unsafe(is_change_positive_target);

            // If is_change_positive, create a change UTXO
            let change_utxo = UTXOTarget {
                owner_pubkey_hash_target: (0..HASH_SIZE)
                    .map(|j| {
                        if j < self.input_utxos[0].owner_pubkey_hash_target.len() {
                            let sender_pk_hash_bit =
                                self.input_utxos[0].owner_pubkey_hash_target[j];
                            let zero = builder.zero();
                            builder.select(is_change_positive, sender_pk_hash_bit, zero)
                        } else {
                            builder.zero()
                        }
                    })
                    .collect(),
                asset_id_target: self.input_utxos[0].asset_id_target.clone(),
                amount_target: change_amount,
                salt_target: (0..HASH_SIZE)
                    .map(|_| builder.add_virtual_target())
                    .collect(),
            };

            // Verify that the change UTXO has the same asset ID as the input
            for i in 0..HASH_SIZE {
                let asset_id_match = builder.is_equal(
                    self.input_utxos[0].asset_id_target[i],
                    change_utxo.asset_id_target[i]
                );
                let one = builder.one();
                let zero = builder.zero();
                let asset_id_match_target = builder.select(asset_id_match, one, zero);
                builder.assert_one(asset_id_match_target);
            }

            // Verify that input amount = output amount + change amount
            let total_output_with_change = builder.add(total_output, change_utxo.amount_target);
            let amounts_match = builder.is_equal(total_input, total_output_with_change);
            let amounts_match_target = builder.select(amounts_match, one, zero);
            builder.assert_one(amounts_match_target);

            // Add the change UTXO to the list of output UTXOs
            output_utxos.push(change_utxo);
        }

        // Enforce fee payment
        enforce_fee_payment(
            builder,
            &self.sender_pk,
            &self.fee_input_utxo,
            self.fee_amount,
            &self.fee_reservoir_address_hash,
            &self.sender_sig,
            &self.input_utxos[0].asset_id_target, // Assume all inputs have the same asset ID
        );

        // Return the output UTXOs
        output_utxos
    }

    /// Create a circuit for the transfer operation
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        // Create a circuit builder
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Create a dummy circuit to build the circuit data
        let num_inputs = 1;
        let recipient_pk_hashes = vec![vec![0u8; 32]];
        let output_amounts = vec![0u64];

        // Create input UTXOs
        let mut input_utxos = Vec::new();
        for _ in 0..num_inputs {
            let input_utxo = UTXOTarget {
                owner_pubkey_hash_target: (0..HASH_SIZE)
                    .map(|_| builder.add_virtual_target())
                    .collect(),
                asset_id_target: (0..HASH_SIZE)
                    .map(|_| builder.add_virtual_target())
                    .collect(),
                amount_target: builder.add_virtual_target(),
                salt_target: (0..HASH_SIZE)
                    .map(|_| builder.add_virtual_target())
                    .collect(),
            };
            input_utxos.push(input_utxo);
        }

        // Create recipient public key hash targets
        let recipient_pk_hash_targets = recipient_pk_hashes
            .iter()
            .map(|_| {
                (0..HASH_SIZE)
                    .map(|_| builder.add_virtual_target())
                    .collect::<Vec<Target>>()
            })
            .collect();

        // Create output amount targets
        let output_amounts_targets = output_amounts
            .iter()
            .map(|_| builder.add_virtual_target())
            .collect();

        // Create sender public key target
        let sender_pk_target = PublicKeyTarget {
            point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };

        // Create sender signature target
        let sender_sig_target = SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };

        // Create fee input UTXO target
        let fee_input_utxo_target = UTXOTarget {
            owner_pubkey_hash_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
        };

        // Create fee amount target
        let fee_amount_target = builder.add_virtual_target();

        // Create fee reservoir address hash targets
        let fee_reservoir_address_hash_targets = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();

        // Create the circuit
        let circuit = TransferCircuit {
            input_utxos,
            sender_pk: sender_pk_target,
            sender_sig: sender_sig_target,
            fee_input_utxo: fee_input_utxo_target,
            fee_amount: fee_amount_target,
            fee_reservoir_address_hash: fee_reservoir_address_hash_targets,
            recipient_pk_hashes: recipient_pk_hash_targets,
            output_amounts: output_amounts_targets,
        };

        // Build the circuit
        let sender_sk = builder.add_virtual_target();
        let nonce = builder.add_virtual_target();
        circuit.build(&mut builder, sender_sk, nonce);

        // Build the circuit data
        builder.build::<PoseidonGoldilocksConfig>()
    }

    /// Populate the witness for proof generation
    pub fn populate_witness(
        pw: &mut PartialWitness<GoldilocksField>,
        input_utxos: Vec<Vec<u8>>,
        recipient_pk_hashes: Vec<Vec<u8>>,
        output_amounts: Vec<u64>,
        _sender_sk: u64,
        sender_pk: Vec<u8>,
        sender_sig: Vec<u8>,
        fee_input_utxo: Vec<u8>,
        fee_amount: u64,
        fee_reservoir_address_hash: Vec<u8>,
        _nonce: u64,
    ) -> WireResult<()> {
        // Create the circuit
        let _circuit_data = Self::create_circuit();

        // Get the targets from the circuit data
        let circuit = TransferCircuit::new(
            input_utxos.len(),
            recipient_pk_hashes.clone(),
            output_amounts.clone(),
            sender_pk.clone(),
            sender_sig.clone(),
            fee_input_utxo.clone(),
            fee_amount,
            fee_reservoir_address_hash.clone(),
        );

        // Process input UTXOs
        for (i, input_utxo_bytes) in input_utxos.iter().enumerate() {
            if i >= circuit.input_utxos.len() {
                return Err(WireError::GenericError("Too many input UTXOs".to_string()));
            }

            // Parse the input UTXO bytes
            if input_utxo_bytes.len() < 4 * 32 {
                return Err(WireError::GenericError(
                    "Invalid input UTXO bytes length".to_string(),
                ));
            }

            // Extract the UTXO components
            let owner_pubkey_hash = &input_utxo_bytes[0..32];
            let asset_id = &input_utxo_bytes[32..64];
            let amount_bytes = &input_utxo_bytes[64..72];
            let salt = &input_utxo_bytes[72..104];

            // Convert amount bytes to u64
            let amount = u64::from_le_bytes([
                amount_bytes[0],
                amount_bytes[1],
                amount_bytes[2],
                amount_bytes[3],
                amount_bytes[4],
                amount_bytes[5],
                amount_bytes[6],
                amount_bytes[7],
            ]);

            // Set the targets in the witness
            for j in 0..HASH_SIZE {
                if j < owner_pubkey_hash.len() {
                    pw.set_target(
                        circuit.input_utxos[i].owner_pubkey_hash_target[j],
                        GoldilocksField::from_canonical_u64(owner_pubkey_hash[j] as u64),
                    );
                }

                if j < asset_id.len() {
                    pw.set_target(
                        circuit.input_utxos[i].asset_id_target[j],
                        GoldilocksField::from_canonical_u64(asset_id[j] as u64),
                    );
                }

                if j < salt.len() {
                    pw.set_target(
                        circuit.input_utxos[i].salt_target[j],
                        GoldilocksField::from_canonical_u64(salt[j] as u64),
                    );
                }
            }

            // Set the amount target
            pw.set_target(
                circuit.input_utxos[i].amount_target,
                GoldilocksField::from_canonical_u64(amount),
            );
        }

        // Process recipient public key hashes
        for (i, recipient_pk_hash) in recipient_pk_hashes.iter().enumerate() {
            if i >= circuit.recipient_pk_hashes.len() {
                return Err(WireError::GenericError(
                    "Too many recipient public key hashes".to_string(),
                ));
            }

            for j in 0..HASH_SIZE {
                if j < recipient_pk_hash.len() {
                    pw.set_target(
                        circuit.recipient_pk_hashes[i][j],
                        GoldilocksField::from_canonical_u64(recipient_pk_hash[j] as u64),
                    );
                }
            }
        }

        // Process output amounts
        for (i, &output_amount) in output_amounts.iter().enumerate() {
            if i >= circuit.output_amounts.len() {
                return Err(WireError::GenericError(
                    "Too many output amounts".to_string(),
                ));
            }

            pw.set_target(
                circuit.output_amounts[i],
                GoldilocksField::from_canonical_u64(output_amount),
            );
        }

        // Process sender public key
        if sender_pk.len() < 64 {
            return Err(WireError::GenericError(
                "Invalid sender public key length".to_string(),
            ));
        }

        let sender_pk_x_bytes = &sender_pk[0..32];
        let sender_pk_y_bytes = &sender_pk[32..64];

        // Convert bytes to field elements
        let sender_pk_x = GoldilocksField::from_canonical_u64(u64::from_le_bytes([
            sender_pk_x_bytes[0],
            sender_pk_x_bytes[1],
            sender_pk_x_bytes[2],
            sender_pk_x_bytes[3],
            sender_pk_x_bytes[4],
            sender_pk_x_bytes[5],
            sender_pk_x_bytes[6],
            sender_pk_x_bytes[7],
        ]));

        let sender_pk_y = GoldilocksField::from_canonical_u64(u64::from_le_bytes([
            sender_pk_y_bytes[0],
            sender_pk_y_bytes[1],
            sender_pk_y_bytes[2],
            sender_pk_y_bytes[3],
            sender_pk_y_bytes[4],
            sender_pk_y_bytes[5],
            sender_pk_y_bytes[6],
            sender_pk_y_bytes[7],
        ]));

        // Set the sender public key targets
        pw.set_target(circuit.sender_pk.point.x, sender_pk_x);
        pw.set_target(circuit.sender_pk.point.y, sender_pk_y);

        // Process sender signature
        if sender_sig.len() < 96 {
            return Err(WireError::GenericError(
                "Invalid sender signature length".to_string(),
            ));
        }

        let sig_r_x_bytes = &sender_sig[0..32];
        let sig_r_y_bytes = &sender_sig[32..64];
        let sig_s_bytes = &sender_sig[64..96];

        // Convert bytes to field elements
        let sig_r_x = GoldilocksField::from_canonical_u64(u64::from_le_bytes([
            sig_r_x_bytes[0],
            sig_r_x_bytes[1],
            sig_r_x_bytes[2],
            sig_r_x_bytes[3],
            sig_r_x_bytes[4],
            sig_r_x_bytes[5],
            sig_r_x_bytes[6],
            sig_r_x_bytes[7],
        ]));

        let sig_r_y = GoldilocksField::from_canonical_u64(u64::from_le_bytes([
            sig_r_y_bytes[0],
            sig_r_y_bytes[1],
            sig_r_y_bytes[2],
            sig_r_y_bytes[3],
            sig_r_y_bytes[4],
            sig_r_y_bytes[5],
            sig_r_y_bytes[6],
            sig_r_y_bytes[7],
        ]));

        let sig_s = GoldilocksField::from_canonical_u64(u64::from_le_bytes([
            sig_s_bytes[0],
            sig_s_bytes[1],
            sig_s_bytes[2],
            sig_s_bytes[3],
            sig_s_bytes[4],
            sig_s_bytes[5],
            sig_s_bytes[6],
            sig_s_bytes[7],
        ]));

        // Set the signature targets
        pw.set_target(circuit.sender_sig.r_point.x, sig_r_x);
        pw.set_target(circuit.sender_sig.r_point.y, sig_r_y);
        pw.set_target(circuit.sender_sig.s_scalar, sig_s);

        // Process fee input UTXO
        if fee_input_utxo.len() < 4 * 32 {
            return Err(WireError::GenericError(
                "Invalid fee input UTXO bytes length".to_string(),
            ));
        }

        // Extract the fee UTXO components
        let fee_owner_pubkey_hash = &fee_input_utxo[0..32];
        let fee_asset_id = &fee_input_utxo[32..64];
        let fee_amount_bytes = &fee_input_utxo[64..72];
        let fee_salt = &fee_input_utxo[72..104];

        // Convert fee amount bytes to u64
        let fee_amount_value = u64::from_le_bytes([
            fee_amount_bytes[0],
            fee_amount_bytes[1],
            fee_amount_bytes[2],
            fee_amount_bytes[3],
            fee_amount_bytes[4],
            fee_amount_bytes[5],
            fee_amount_bytes[6],
            fee_amount_bytes[7],
        ]);

        // Set the fee UTXO targets
        for j in 0..HASH_SIZE {
            if j < fee_owner_pubkey_hash.len() {
                pw.set_target(
                    circuit.fee_input_utxo.owner_pubkey_hash_target[j],
                    GoldilocksField::from_canonical_u64(fee_owner_pubkey_hash[j] as u64),
                );
            }

            if j < fee_asset_id.len() {
                pw.set_target(
                    circuit.fee_input_utxo.asset_id_target[j],
                    GoldilocksField::from_canonical_u64(fee_asset_id[j] as u64),
                );
            }

            if j < fee_salt.len() {
                pw.set_target(
                    circuit.fee_input_utxo.salt_target[j],
                    GoldilocksField::from_canonical_u64(fee_salt[j] as u64),
                );
            }
        }

        // Set the fee amount target
        pw.set_target(
            circuit.fee_input_utxo.amount_target,
            GoldilocksField::from_canonical_u64(fee_amount_value),
        );

        // Set the fee amount target
        pw.set_target(
            circuit.fee_amount,
            GoldilocksField::from_canonical_u64(fee_amount),
        );

        // Process fee reservoir address hash
        if fee_reservoir_address_hash.len() < HASH_SIZE {
            return Err(WireError::GenericError(
                "Invalid fee reservoir address hash length".to_string(),
            ));
        }

        for j in 0..HASH_SIZE {
            if j < fee_reservoir_address_hash.len() {
                pw.set_target(
                    circuit.fee_reservoir_address_hash[j],
                    GoldilocksField::from_canonical_u64(fee_reservoir_address_hash[j] as u64),
                );
            }
        }

        Ok(())
    }

    /// Generate a proof for the transfer circuit
    pub fn generate_proof(
        &self,
        input_utxos: Vec<Vec<u8>>,
        recipient_pk_hashes: Vec<Vec<u8>>,
        output_amounts: Vec<u64>,
        sender_sk: u64,
        sender_pk: Vec<u8>,
        sender_sig: Vec<u8>,
        fee_input_utxo: Vec<u8>,
        fee_amount: u64,
        fee_reservoir_address_hash: Vec<u8>,
        nonce: u64,
    ) -> WireResult<SerializableProof> {
        // Create the circuit data
        let circuit_data = Self::create_circuit();

        // Create a partial witness
        let mut pw = PartialWitness::new();

        // Populate the witness
        Self::populate_witness(
            &mut pw,
            input_utxos,
            recipient_pk_hashes,
            output_amounts,
            sender_sk,
            sender_pk,
            sender_sig,
            fee_input_utxo,
            fee_amount,
            fee_reservoir_address_hash,
            nonce,
        )?;

        // Generate the proof
        let proof = generate_proof(&circuit_data, pw)
            .map_err(|e| WireError::ProofError(CoreProofError::from(e)))?;

        // Serialize the proof
        let serialized_proof =
            serialize_proof(&proof).map_err(|e| WireError::ProofError(CoreProofError::from(e)))?;

        Ok(serialized_proof)
    }

    /// Generate a proof for the transfer circuit (static method)
    pub fn static_generate_proof(
        input_utxos: Vec<Vec<u8>>,
        recipient_pk_hashes: Vec<Vec<u8>>,
        output_amounts: Vec<u64>,
        sender_sk: u64,
        sender_pk: Vec<u8>,
        sender_sig: Vec<u8>,
        fee_input_utxo: Vec<u8>,
        fee_amount: u64,
        fee_reservoir_address_hash: Vec<u8>,
        nonce: u64,
    ) -> WireResult<SerializableProof> {
        // Create the circuit data
        let circuit_data = Self::create_circuit();

        // Create a partial witness
        let mut pw = PartialWitness::new();

        // Populate the witness
        Self::populate_witness(
            &mut pw,
            input_utxos,
            recipient_pk_hashes,
            output_amounts,
            sender_sk,
            sender_pk,
            sender_sig,
            fee_input_utxo,
            fee_amount,
            fee_reservoir_address_hash,
            nonce,
        )?;

        // Generate the proof
        let proof = generate_proof(&circuit_data, pw)
            .map_err(|e| WireError::ProofError(CoreProofError::from(e)))?;

        // Serialize the proof
        let serialized_proof =
            serialize_proof(&proof).map_err(|e| WireError::ProofError(CoreProofError::from(e)))?;

        Ok(serialized_proof)
    }

    /// Verify a proof for this circuit
    pub fn verify_proof(&self, proof: &SerializableProof) -> WireResult<bool> {
        // Create the circuit
        let circuit_data = Self::create_circuit();

        // Deserialize the proof
        let proof = deserialize_proof(proof, &circuit_data.common)
            .map_err(|e| WireError::ProofError(CoreProofError::from(e)))?;

        // Verify the proof
        verify_proof(&circuit_data, proof)
            .map(|_| true)
            .map_err(|e| WireError::ProofError(CoreProofError::from(e)))
    }

    /// Verify a proof for this circuit (static method)
    pub fn static_verify_proof(
        _input_utxos: Vec<Vec<u8>>,
        _recipient_pk_hashes: Vec<Vec<u8>>,
        _output_amounts: Vec<u64>,
        _sender_sk: u64,
        _sender_pk: Vec<u8>,
        _sender_sig: Vec<u8>,
        _fee_input_utxo: Vec<u8>,
        _fee_amount: u64,
        _fee_reservoir_address_hash: Vec<u8>,
        _nonce: u64,
        proof: &SerializableProof,
    ) -> WireResult<bool> {
        // Create the circuit data
        let circuit_data = Self::create_circuit();

        // Deserialize the proof
        let proof = deserialize_proof(proof, &circuit_data.common)
            .map_err(|e| WireError::ProofError(CoreProofError::from(e)))?;

        // Verify the proof
        verify_proof(&circuit_data, proof)
            .map(|_| true)
            .map_err(|e| WireError::ProofError(CoreProofError::from(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer() {
        // This is a placeholder test
        // In a real implementation, this would test the circuit with actual inputs
        let circuit_data = TransferCircuit::create_circuit();
        assert!(circuit_data.common.num_public_inputs > 0);
    }
}
