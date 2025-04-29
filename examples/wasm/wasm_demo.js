// 0BTC Wire WASM Demo
// This example demonstrates how to use the Wire WASM module in a browser environment

// Import the Wire WASM module
// In a real application, you would import the module like this:
// import * as wire from 'wire_wasm';
// For this demo, we'll assume the module is loaded via a script tag

document.addEventListener('DOMContentLoaded', async () => {
    // Initialize the UI elements
    const outputConsole = document.getElementById('output-console');
    const generateKeypairBtn = document.getElementById('generate-keypair');
    const signMessageBtn = document.getElementById('sign-message');
    const proveTransferBtn = document.getElementById('prove-transfer');
    const verifyProofBtn = document.getElementById('verify-proof');
    const aggregateProofsBtn = document.getElementById('aggregate-proofs');
    const verifyAggregatedBtn = document.getElementById('verify-aggregated');
    
    // Function to log messages to the console
    function log(message, isError = false) {
        const line = document.createElement('div');
        line.textContent = message;
        if (isError) {
            line.classList.add('error');
        }
        outputConsole.appendChild(line);
        outputConsole.scrollTop = outputConsole.scrollHeight;
    }
    
    // Wait for the WASM module to initialize
    try {
        log('Initializing Wire WASM module...');
        
        // In a real application, you would await the module initialization
        // await wire.default();
        
        log('Wire WASM module initialized successfully');
        
        // Enable the buttons once the module is loaded
        enableButtons(true);
    } catch (error) {
        log(`Error initializing Wire WASM module: ${error.message}`, true);
        enableButtons(false);
    }
    
    // Function to enable/disable buttons
    function enableButtons(enabled) {
        const buttons = [
            generateKeypairBtn,
            signMessageBtn,
            proveTransferBtn,
            verifyProofBtn,
            aggregateProofsBtn,
            verifyAggregatedBtn
        ];
        
        for (const button of buttons) {
            button.disabled = !enabled;
        }
    }
    
    // Event listeners for the buttons
    generateKeypairBtn.addEventListener('click', async () => {
        try {
            log('Generating keypair...');
            
            // In a real application, you would call the WASM function
            // const result = await wire.generate_keypair();
            
            // For demo purposes, we'll simulate the result
            const result = {
                secretKey: '0x1a2b3c4d5e6f...',
                publicKey: '0x7e8d9c0b1a2b...'
            };
            
            log('Keypair generated successfully:');
            log(`Secret Key: ${result.secretKey}`);
            log(`Public Key: ${result.publicKey}`);
        } catch (error) {
            log(`Error generating keypair: ${error.message}`, true);
        }
    });
    
    signMessageBtn.addEventListener('click', async () => {
        try {
            log('Signing message...');
            
            // Get values from the form
            const secretKey = document.getElementById('secret-key').value;
            const message = document.getElementById('message').value;
            
            // In a real application, you would call the WASM function
            // const result = await wire.sign_message(secretKey, message);
            
            // For demo purposes, we'll simulate the result
            const result = {
                signature: '0x1a2b3c4d5e6f...',
                r: '0x7e8d9c0b1a2b...',
                s: '0x3c4d5e6f7a8b...'
            };
            
            log('Message signed successfully:');
            log(`Signature: ${result.signature}`);
        } catch (error) {
            log(`Error signing message: ${error.message}`, true);
        }
    });
    
    proveTransferBtn.addEventListener('click', async () => {
        try {
            log('Generating transfer proof...');
            
            // Get values from the form
            const senderPk = document.getElementById('sender-pk').value;
            const senderSig = document.getElementById('sender-sig').value;
            const inputUtxo = document.getElementById('input-utxo').value;
            const recipientPkHash = document.getElementById('recipient-pk-hash').value;
            const amount = document.getElementById('amount').value;
            
            // In a real application, you would call the WASM function
            // const result = await wire.prove_transfer({
            //     senderPk,
            //     senderSig,
            //     inputUtxo: JSON.parse(inputUtxo),
            //     recipientPkHash,
            //     amount: parseInt(amount)
            // });
            
            // For demo purposes, we'll simulate the result
            const result = {
                proof: {
                    publicInputs: [...Array(10)].map(() => Math.random().toString(16).slice(2)),
                    proof: [...Array(20)].map(() => Math.random().toString(16).slice(2))
                }
            };
            
            log('Transfer proof generated successfully');
            
            // Store the proof for later use
            window.lastProof = result.proof;
            
            // Display the proof (abbreviated)
            log('Proof (abbreviated):');
            log(JSON.stringify(result.proof).slice(0, 100) + '...');
        } catch (error) {
            log(`Error generating transfer proof: ${error.message}`, true);
        }
    });
    
    verifyProofBtn.addEventListener('click', async () => {
        try {
            log('Verifying proof...');
            
            if (!window.lastProof) {
                throw new Error('No proof available. Generate a proof first.');
            }
            
            // In a real application, you would call the WASM function
            // const result = await wire.verify_proof(window.lastProof, 'transfer');
            
            // For demo purposes, we'll simulate the result
            const result = { valid: true };
            
            if (result.valid) {
                log('Proof verified successfully');
            } else {
                log('Proof verification failed', true);
            }
        } catch (error) {
            log(`Error verifying proof: ${error.message}`, true);
        }
    });
    
    // Store multiple proofs for aggregation
    window.proofs = [];
    
    // Function to generate multiple proofs for aggregation
    async function generateMultipleProofs(count) {
        log(`Generating ${count} proofs for aggregation...`);
        
        window.proofs = [];
        
        for (let i = 0; i < count; i++) {
            log(`Generating proof ${i + 1}/${count}...`);
            
            // In a real application, you would call the WASM function
            // const result = await wire.prove_transfer({...});
            
            // For demo purposes, we'll simulate the result
            const proof = {
                publicInputs: [...Array(10)].map(() => Math.random().toString(16).slice(2)),
                proof: [...Array(20)].map(() => Math.random().toString(16).slice(2))
            };
            
            window.proofs.push(proof);
        }
        
        log(`Generated ${count} proofs successfully`);
    }
    
    aggregateProofsBtn.addEventListener('click', async () => {
        try {
            const count = parseInt(document.getElementById('proof-count').value) || 4;
            
            // Generate multiple proofs
            await generateMultipleProofs(count);
            
            log('Aggregating proofs...');
            
            // In a real application, you would call the WASM function
            // const result = await wire.aggregate_proofs(window.proofs);
            
            // For demo purposes, we'll simulate the result
            const aggregatedProof = {
                publicInputs: [...Array(10)].map(() => Math.random().toString(16).slice(2)),
                proof: [...Array(20)].map(() => Math.random().toString(16).slice(2)),
                numProofs: count
            };
            
            window.aggregatedProof = aggregatedProof;
            
            log(`Aggregated ${count} proofs successfully`);
            log('Aggregated proof (abbreviated):');
            log(JSON.stringify(aggregatedProof).slice(0, 100) + '...');
        } catch (error) {
            log(`Error aggregating proofs: ${error.message}`, true);
        }
    });
    
    verifyAggregatedBtn.addEventListener('click', async () => {
        try {
            log('Verifying aggregated proof...');
            
            if (!window.aggregatedProof) {
                throw new Error('No aggregated proof available. Aggregate proofs first.');
            }
            
            // In a real application, you would call the WASM function
            // const result = await wire.verify_aggregated_proof(window.aggregatedProof);
            
            // For demo purposes, we'll simulate the result
            const result = { 
                valid: true,
                numProofs: window.aggregatedProof.numProofs
            };
            
            if (result.valid) {
                log(`Aggregated proof verified successfully (contains ${result.numProofs} proofs)`);
            } else {
                log('Aggregated proof verification failed', true);
            }
        } catch (error) {
            log(`Error verifying aggregated proof: ${error.message}`, true);
        }
    });
});
