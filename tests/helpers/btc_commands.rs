// Copyright 2025 - See NOTICE file for copyright holders.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use std::env;
use std::path::PathBuf;
use std::process::Command;

pub async fn generate_blocks_to_address(
    mined_address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let home_dir = env::var("HOME")?;
    let bitcoin_cli_path = PathBuf::from(home_dir)
        .join("workrepos")
        .join("bitcoin-25.0")
        .join("bin")
        .join("bitcoin-cli");

    let output = Command::new(bitcoin_cli_path)
        .args(&[
            "-regtest",
            "-rpcwallet=testwallet",
            "-rpcuser=ic-btc-integration",
            "-rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E=",
            "generatetoaddress",
            "101",
            mined_address,
        ])
        .output()?;

    let stdout_str = str::from_utf8(&output.stdout).unwrap_or("<Invalid UTF-8>");
    let stderr_str = str::from_utf8(&output.stderr).unwrap_or("<Invalid UTF-8>");
    println!("Block generation stdout:\n{}", stdout_str);
    if !stderr_str.is_empty() {
        eprintln!("Block generation stderr:\n{}", stderr_str);
    }

    if !output.status.success() {
        return Err(format!(
            "Failed to generate blocks with exit code: {}",
            output.status
        )
        .into());
    }

    println!("Generated 101 blocks to confirm transactions");
    Ok(())
}
