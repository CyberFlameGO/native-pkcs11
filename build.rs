// Copyright 2021 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bindgen::callbacks;
use std::env;
use std::path;

#[derive(Debug)]
pub struct CargoCallbacks;

impl callbacks::ParseCallbacks for CargoCallbacks {
    // https://github.com/rust-lang/rust-bindgen/issues/1594
    fn int_macro(&self, name: &str, _value: i64) -> Option<callbacks::IntKind> {
        if ["CK_TRUE", "CK_FALSE"].contains(&name) {
            Some(bindgen::callbacks::IntKind::U8)
        } else if name.starts_with("CK_")
            || name.starts_with("CKA_")
            || name.starts_with("CKF_")
            || name.starts_with("CKK_")
            || name.starts_with("CKM_")
            || name.starts_with("CKO_")
            || name.starts_with("CKR_")
            || name.starts_with("CKS_")
        {
            Some(bindgen::callbacks::IntKind::U64)
        } else {
            None
        }
    }

    fn include_file(&self, filename: &str) {
        println!("cargo:rerun-if-changed={}", filename);
    }
}

fn main() {
    println!("cargo:rerun-if-changed=third_party/pkcs11unix.h");

    let bindings = bindgen::Builder::default()
        .header("third_party/pkcs11unix.h")
        .parse_callbacks(Box::new(CargoCallbacks))
        .derive_default(true)
        .generate()
        .expect("failed to generate bindings");

    let out_path = path::PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("pkcs11.rs"))
        .expect("failed to write bindings");
}
