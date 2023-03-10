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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");

    println!("cargo:rerun-if-changed=proto/token.proto");
    tonic_build::compile_protos("proto/token.proto")?;
    /* TODO: annotate with serde
    tonic_build::configure()
        .type_attribute(
            "briolette.token.Token",
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"snake_case\")]",
        )
        .type_attribute(
            ".briolette.token.Descriptor",
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"snake_case\")]",
        )
        .compile(&["proto/token.proto"], &["proto"])
        .unwrap();
    */

    println!("cargo:rerun-if-changed=proto/common.proto");
    tonic_build::compile_protos("proto/common.proto")?;

    println!("cargo:rerun-if-changed=proto/amount_type.proto");
    tonic_build::compile_protos("proto/amount_type.proto")?;

    println!("cargo:rerun-if-changed=proto/tokenmap.proto");
    tonic_build::compile_protos("proto/tokenmap.proto")?;

    println!("cargo:rerun-if-changed=proto/mint.proto");
    tonic_build::compile_protos("proto/mint.proto")?;

    println!("cargo:rerun-if-changed=proto/clerk.proto");
    tonic_build::compile_protos("proto/clerk.proto")?;

    println!("cargo:rerun-if-changed=proto/registrar.proto");
    tonic_build::compile_protos("proto/registrar.proto")?;

    println!("cargo:rerun-if-changed=proto/validate.proto");
    tonic_build::compile_protos("proto/validate.proto")?;

    println!("cargo:rerun-if-changed=proto/receiver.proto");
    tonic_build::compile_protos("proto/receiver.proto")?;

    Ok(())
}
