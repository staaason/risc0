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

use crate::Job;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{thread_rng, Rng};
use rand_core::OsRng;
use risc0_zkvm::serde::to_vec;
use serde::{Deserialize, Serialize};


fn generate_random_message(len: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

#[derive(Serialize, Deserialize)]
pub struct SignaturesBatch {
    pub signatures: Vec<Vec<u8>>,
    pub messages: Vec<Vec<u8>>,
    pub verifying_keys: Vec<[u8; 32]>,
}

pub fn new_jobs() -> Vec<Job> {
    // Generate a random ed25519 keypair and sign the message.
    let size = 100;
    let message_length = 50;

    let mut signatures = Vec::with_capacity(size);
    let mut messages = Vec::with_capacity(size);
    let mut verifying_keys = Vec::with_capacity(size);

    for _ in 0..size {
        let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let random_message = generate_random_message(message_length);
        let signature: Signature = signing_key.sign(&random_message);
        signatures.push(signature.to_bytes().to_vec());
        messages.push(random_message);
        verifying_keys.push(*verifying_key.as_bytes());
    }

    let batch = SignaturesBatch{
        signatures,
        messages,
        verifying_keys,
    };

    let guest_input = to_vec(&batch)
        .unwrap();

    vec![Job::new(
        "ed25519_verify".to_string(),
        risc0_benchmark_methods::ED25519_VERIFY_ELF,
        risc0_benchmark_methods::ED25519_VERIFY_ID.into(),
        guest_input,
        size,
    )]
}
