/* Copyright 2023 Martin Grap

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */


use crate::fcrypt::AeadContext;
use cipher::consts::U12;
use aes_gcm::AesGcm;

const ALGO_AES256: &str = "AES-256 GCM";
const ALGO_AES192: &str = "AES-192 GCM";


pub struct Gcm256Context(AeadContext);
crate::make_creator!(Gcm256Context);
crate::cryptor_impl!(Gcm256Context, AesGcm::<aes::Aes256, U12>, ALGO_AES256);

pub struct Gcm192Context(AeadContext);
crate::make_creator!(Gcm192Context);
crate::cryptor_impl!(Gcm192Context, AesGcm::<aes::Aes192, U12>, ALGO_AES192);
