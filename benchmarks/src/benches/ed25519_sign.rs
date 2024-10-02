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

use ed25519_dalek::{SigningKey};
use rand_core::OsRng;
use risc0_zkvm::serde::to_vec;

use crate::Job;

pub fn new_jobs() -> Vec<Job> {
    // Generate a random ed25519 keypair and sign the message.
    let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
    let message = b"This is a message that will be signed, and verified within the zkVM".to_vec();

    let guest_input = to_vec(&(
        1,
        message,
        signing_key.to_bytes(),
    ))
    .unwrap();

    vec![Job::new(
        "ed25519_sign".to_string(),
        risc0_benchmark_methods::ED25519_SIGN_ELF,
        risc0_benchmark_methods::ED25519_SIGN_ID.into(),
        guest_input,
        1,
    )]
}
