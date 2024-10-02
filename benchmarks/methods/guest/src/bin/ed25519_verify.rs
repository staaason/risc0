// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize)]
pub struct SignaturesBatch {
    pub signatures: Vec<Vec<u8>>,
    pub messages: Vec<Vec<u8>>,
    pub verifying_keys: Vec<[u8; 32]>,
}

fn main() {
    // Decode the verifying key, message, and signature from the inputs.
    let batch: SignaturesBatch = env::read();

    for i in 0..batch.signatures.len() {
        let verifying_key = VerifyingKey::from_bytes(&batch.verifying_keys[i]).unwrap();
        let signature: Signature = Signature::from_slice(&batch.signatures[i]).unwrap();
            verifying_key
                .verify(&batch.messages[i], &signature)
                .expect("Ed25519 signature verification failed");

    }

    // Commit to the journal the verifying key and message that was signed.
    env::commit(&(1));
}
