# DeepVis: Deep Vision for Filesystem Integrity (ICDCS 2026)

> **ARCHITECTURAL CONSTRAINT**: Do NOT add new source files. All logic must reside in `code/src/lib.rs`, `code/deepvis.py`, or `code/plot.py`. The directory structure is frozen.

## Overview
DeepVis is a high-performance integrity verification system combining spatial hashing and max-pooling tensors.

## Directory Structure
- **code/**: All source code (Rust Core + Python Orchestrator).
  - `src/lib.rs`: Rust implementation of Spatial Hashing and Feature Extraction.
  - `deepvis.py`: Experiment orchestrator (Scalability, Sensitivity, Hyperscale).
  - `plot.py`: Figure generator.
- **paper/**: Generated figures.
  - `figures/`: PDF outputs.

## Usage

### 1. Build Rust Core
```bash
cd code
# Requires maturin: pip install maturin
maturin develop --release
```

### 2. Run Experiments
```bash
cd code
# Run all experiments
python3 deepvis.py --exp all

# Run specific experiment
python3 deepvis.py --exp scalability
```

### 3. Generate Figures
```bash
cd code
python3 plot.py
```
Figures will be saved to `../paper/figures/`.
