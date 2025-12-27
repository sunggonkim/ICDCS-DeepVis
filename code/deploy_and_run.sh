#!/bin/bash
# set -e

# 1. Install Dependencies
sudo apt-get update
sudo apt-get purge -y postfix bsd-mailx aide-common || true
sudo apt-get autoremove -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential python3-pip tmux || true

# 2. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# 3. Setup AIDE
sudo mkdir -p /etc/aide /var/lib/aide
sudo bash -c 'cat > /etc/aide/aide.conf << EOF
database=file:/var/lib/aide/aide.db.gz
database_out=file:/var/lib/aide/aide.db.new.gz
gzip_dbout=yes
verbose=5
report_url=stdout
NORMAL = p+i+n+u+g+s+b+m+c+sha256
/ NORMAL
!/proc
!/sys
!/dev
!/run
!/tmp
!/var/log
!/var/tmp
!$HOME/deepvis_scan_results.csv
!$HOME/experiment_output.log
!$HOME/deepvis_resources.csv
!$HOME/aide_resources.csv
EOF'

# 4. Build Rust Scanner
mkdir -p ~/deepvis_scanner/src
cp ~/deepvis_scanner.rs ~/deepvis_scanner/src/lib.rs
# We need to create Cargo.toml
cat > ~/deepvis_scanner/Cargo.toml << EOF
[package]
name = "deepvis_scanner"
version = "0.1.0"
edition = "2021"

[dependencies]
io-uring = "0.7"
pyo3 = { version = "0.23", features = ["extension-module"] }
sha2 = "0.10"
rayon = "1.10"
anyhow = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[lib]
name = "deepvis_scanner"
crate-type = ["cdylib"]

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
EOF

# Wait for source code upload (manual step in orchestration, but here we assume it's done)
# Compile
cd ~/deepvis_scanner
cargo build --release
cp target/release/libdeepvis_scanner.so ~/deepvis_scanner.so

# 5. Run Experiment
cd ~
# (real_experiment.py will be uploaded separately)
tmux new-session -d -s exp "python3 ~/real_experiment.py 2>&1 | tee ~/experiment_output.log"
