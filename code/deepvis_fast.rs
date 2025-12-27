//! DeepVis Fast Scanner - Optimized for Maximum Throughput
//! ========================================================
//! Header-only entropy calculation (NO full SHA-256 hash)
//! Target: 10,000+ files/sec on Mid-tier GCP
//!
//! Build: cargo build --release
//! Output: libdeepvis_scanner.so

use std::fs::{self, File};
use std::io::{Read, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Sha256, Digest};
use rayon::prelude::*;
use pyo3::prelude::*;

const HEADER_SIZE: usize = 64;
const IMG_SIZE: u32 = 128;

// ============================================================================
// HASH-BASED SPATIAL MAPPING (O(1) coordinate computation)
// ============================================================================

fn compute_hash_coords(path: &str) -> (u32, u32) {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let hash = hasher.finalize();
    
    let x = (hash[0] as u32) << 8 | (hash[1] as u32);
    let y = (hash[2] as u32) << 8 | (hash[3] as u32);
    
    (x % IMG_SIZE, y % IMG_SIZE)
}

// ============================================================================
// HEADER-ONLY ENTROPY (64 bytes only - 100x faster than full file)
// ============================================================================

fn calculate_entropy_fast(path: &Path) -> f64 {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return 0.0,
    };
    
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; HEADER_SIZE];
    
    let bytes_read = match reader.read(&mut buffer) {
        Ok(n) => n,
        Err(_) => return 0.0,
    };
    
    if bytes_read == 0 {
        return 0.0;
    }
    
    let mut freq = [0u32; 256];
    for &byte in &buffer[..bytes_read] {
        freq[byte as usize] += 1;
    }
    
    let total = bytes_read as f64;
    let mut entropy = 0.0;
    
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    
    entropy / 8.0  // Normalize to 0-1
}

// ============================================================================
// FILE ENTRY
// ============================================================================

#[pyclass]
#[derive(Clone, Debug)]
pub struct FileEntry {
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub size: u64,
    #[pyo3(get)]
    pub entropy: f64,
    #[pyo3(get)]
    pub coord_x: u32,
    #[pyo3(get)]
    pub coord_y: u32,
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct ScanResult {
    #[pyo3(get)]
    pub total_files: u64,
    #[pyo3(get)]
    pub scan_time_ms: f64,
    #[pyo3(get)]
    pub files_per_sec: f64,
}

// ============================================================================
// FAST SCANNER
// ============================================================================

fn collect_paths(root: &Path, limit: usize) -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(limit);
    collect_paths_recursive(root, &mut paths, limit);
    paths
}

fn collect_paths_recursive(dir: &Path, paths: &mut Vec<PathBuf>, limit: usize) {
    if paths.len() >= limit {
        return;
    }
    
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    
    for entry in entries.flatten() {
        if paths.len() >= limit {
            return;
        }
        
        let path = entry.path();
        
        // Skip special directories
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name == "proc" || name == "sys" || name == "dev" || name == "run" {
                continue;
            }
        }
        
        if path.is_file() {
            paths.push(path);
        } else if path.is_dir() {
            collect_paths_recursive(&path, paths, limit);
        }
    }
}

#[pyclass]
pub struct DeepVisScanner {}

#[pymethods]
impl DeepVisScanner {
    #[new]
    fn new() -> Self {
        DeepVisScanner {}
    }
    
    /// Fast scan - header-only entropy, no SHA-256 hash
    #[pyo3(signature = (root, limit=500000))]
    fn scan_fast(&self, root: &str, limit: usize) -> PyResult<ScanResult> {
        let start = Instant::now();
        
        // Collect paths
        let paths = collect_paths(Path::new(root), limit);
        
        // Parallel entropy calculation (header-only)
        let files: Vec<FileEntry> = paths
            .par_iter()
            .filter_map(|path| {
                let meta = fs::metadata(path).ok()?;
                if !meta.is_file() || meta.size() == 0 {
                    return None;
                }
                
                let entropy = calculate_entropy_fast(path);
                let path_str = path.to_string_lossy().to_string();
                let (x, y) = compute_hash_coords(&path_str);
                
                Some(FileEntry {
                    path: path_str,
                    size: meta.size(),
                    entropy,
                    coord_x: x,
                    coord_y: y,
                })
            })
            .collect();
        
        let elapsed = start.elapsed();
        let total_files = files.len() as u64;
        let scan_time_ms = elapsed.as_secs_f64() * 1000.0;
        let files_per_sec = if elapsed.as_secs_f64() > 0.0 {
            total_files as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        
        Ok(ScanResult {
            total_files,
            scan_time_ms,
            files_per_sec,
        })
    }
    
    /// Get high-entropy files (for anomaly detection)
    #[pyo3(signature = (root, threshold=0.9, limit=500000))]
    fn scan_anomalies(&self, root: &str, threshold: f64, limit: usize) -> PyResult<Vec<FileEntry>> {
        let paths = collect_paths(Path::new(root), limit);
        
        let anomalies: Vec<FileEntry> = paths
            .par_iter()
            .filter_map(|path| {
                let meta = fs::metadata(path).ok()?;
                if !meta.is_file() || meta.size() == 0 {
                    return None;
                }
                
                let entropy = calculate_entropy_fast(path);
                if entropy < threshold {
                    return None;
                }
                
                let path_str = path.to_string_lossy().to_string();
                let (x, y) = compute_hash_coords(&path_str);
                
                Some(FileEntry {
                    path: path_str,
                    size: meta.size(),
                    entropy,
                    coord_x: x,
                    coord_y: y,
                })
            })
            .collect();
        
        Ok(anomalies)
    }
}

#[pymodule]
fn deepvis_scanner(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DeepVisScanner>()?;
    m.add_class::<FileEntry>()?;
    m.add_class::<ScanResult>()?;
    Ok(())
}
