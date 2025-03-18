// Copyright 2023 The Briolette Authors.
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

extern crate cc;
use std::env;
use std::path::Path;
use std::process::Command;
use std::io::{self, Write};

fn main() {
    println!("cargo:rerun-if-changed=src/v0_wrapper.c");
    let output = Command::new("/bin/bash")
        .arg("-c")
        .arg("./build-deps.sh")
        .output()
        .expect("failed to execute process");
    // Log to stderr to make future maintenance easier.
    io::stderr().write_all(&output.stdout).unwrap();
    io::stderr().write_all(&output.stderr).unwrap();

    let out_dir = env::var("OUT_DIR").unwrap();
    println!(
        "cargo:rustc-link-search={}",
        Path::new(&out_dir)
            .join("deps/ecdaa/build/libecdaa")
            .display() // Path::new(&out_dir).join("libs").display()
    );
    println!(
        "cargo:rustc-link-search={}",
        Path::new(&out_dir)
            .join("deps/ecdaa/build/deps/lib")
            .display() // Path::new(&out_dir).join("libs").display()
    );

    println!("cargo:rustc-link-lib=static=ecdaa");
    println!("cargo:rustc-link-lib=static=amcl_core");
    println!("cargo:rustc-link-lib=static=amcl_curve_FP256BN");
    println!("cargo:rustc-link-lib=static=amcl_pairing_FP256BN");

    let amcl_include = Path::new(&out_dir).join("deps/ecdaa/build/deps/include");
    let ecdaa_gen_include = Path::new(&out_dir).join("deps/ecdaa/build/libecdaa/include");

    let ecdaa_include = Path::new(&out_dir).join("deps/ecdaa/libecdaa/include");
    cc::Build::new()
        .file("src/v0_wrapper.c")
        .include(amcl_include)
        .include(ecdaa_gen_include)
        .include(ecdaa_include)
        .compile("libv0_wrapper.a");
}
