extern crate bindgen;

use std::env;
use std::path;

fn main() {
    // Largely copied from https://rust-lang.github.io/rust-bindgen/tutorial-3.html
    let bindings = bindgen::Builder::default()
        .header("third_party/pkcs11unix.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("failed to generate bindings");

    let out_path = path::PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("pkcs11.rs"))
        .expect("failed to write bindings");
}
