//! DeepVis High-Performance Scanner
//! ================================
//! io_uring-based asynchronous file system scanner for DeepVis
//! 
//! Build: cargo build --release
//! Output: libdeepvis_scanner.so (Python loadable)
//!
//! ICDCS 2026 - Production-Grade Research Artifact

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::collections::VecDeque;

use io_uring::{opcode, types, IoUring};
use sha2::{Sha256, Digest};

use rayon::prelude::*;
use pyo3::prelude::*;
use serde::{Serialize, Deserialize};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// File metadata for DeepVis tensor generation
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileEntry {
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub size: u64,
    #[pyo3(get)]
    pub mode: u32,
    #[pyo3(get)]
    pub mtime: i64,
    #[pyo3(get)]
    pub entropy: f64,
    #[pyo3(get)]
    pub hash: String, 
    #[pyo3(get)]
    pub hash_coord_x: u32,
    #[pyo3(get)]
    pub hash_coord_y: u32,
}

#[pymethods]
impl FileEntry {
    #[new]
    fn new(path: String, size: u64, mode: u32, mtime: i64, entropy: f64) -> Self {
        let (x, y) = compute_hash_coords(&path, 128);
        FileEntry {
            path,
            size,
            mode,
            mtime,
            entropy,
            hash: String::new(),
            hash_coord_x: x,
            hash_coord_y: y,
        }
    }
}

/// Scan result with timing breakdown
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    #[pyo3(get)]
    pub files: Vec<FileEntry>,
    #[pyo3(get)]
    pub scan_time_ms: f64,
    #[pyo3(get)]
    pub entropy_time_ms: f64,
    #[pyo3(get)]
    pub total_time_ms: f64,
    #[pyo3(get)]
    pub files_per_sec: f64,
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn compute_hash_coords(path: &str, img_size: u32) -> (u32, u32) {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let hash = hasher.finalize();
    let hash_val = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    let x = (hash_val % img_size as u64) as u32;
    let y = ((hash_val / img_size as u64) % img_size as u64) as u32;
    (x, y)
}

fn calculate_entropy_from_buffer(buffer: &[u8], len: usize) -> f64 {
    if len == 0 { return 0.0; }
    let mut freq = [0u64; 256];
    for &byte in &buffer[..len] {
        freq[byte as usize] += 1;
    }
    let total = len as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ============================================================================
// IO_URING SCANNER
// ============================================================================

const QUEUE_DEPTH: u32 = 512;
const READ_SIZE: usize = 64; // Header size for entropy

struct PendingFile {
    path: PathBuf,
    metadata: fs::Metadata,
}

pub struct AsyncScanner {
    ring: IoUring,
}

impl AsyncScanner {
    pub fn new() -> io::Result<Self> {
        let ring = IoUring::new(QUEUE_DEPTH)?;
        Ok(AsyncScanner { ring })
    }

    /// Recursively collect all paths (Rayon optimized)
    fn collect_paths_parallel(&self, root: &Path) -> Vec<PathBuf> {
        let entries: Vec<_> = match fs::read_dir(root) {
            Ok(e) => e.flatten().collect(),
            Err(_) => return Vec::new(),
        };

        let results: Vec<Vec<PathBuf>> = entries.par_iter().map(|entry| {
            let mut local_paths = Vec::new();
            let path = entry.path();
            if path.is_file() {
                local_paths.push(path);
            } else if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !name.starts_with('.') && name != "proc" && name != "sys" && name != "dev" && name != "run" {
                    self.collect_paths_recursive(&path, &mut local_paths);
                }
            }
            local_paths
        }).collect();

        results.into_iter().flatten().collect()
    }
    
    fn collect_paths_recursive(&self, dir: &Path, paths: &mut Vec<PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    paths.push(path);
                } else if path.is_dir() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if !name.starts_with('.') {
                        self.collect_paths_recursive(&path, paths);
                    }
                }
            }
        }
    }

    pub fn scan(&mut self, root: &str) -> ScanResult {
        let start = Instant::now();
        let root_path = Path::new(root);

        // Phase 1: Collect paths
        let paths = self.collect_paths_parallel(root_path);
        let scan_time = start.elapsed();

        // Phase 2: io_uring processing
        let entropy_start = Instant::now();
        
        // Prepare file list with metadata
        let mut pending_files: VecDeque<PendingFile> = paths.iter()
            .filter_map(|p| {
                fs::metadata(p).ok().map(|m| PendingFile { path: p.clone(), metadata: m })
            })
            .collect();
            
        let total_files_count = pending_files.len();
        let mut results: Vec<FileEntry> = Vec::with_capacity(total_files_count);
        let mut in_flight = 0;
        
        // Slab of pre-allocated buffers
        let mut buffers = vec![[0u8; READ_SIZE]; QUEUE_DEPTH as usize];
        // Slab mapping: index -> (file_idx_in_pending, FileHandle)
        // FileHandle is kept open until read completes
        let mut buf_file_map: Vec<Option<(usize, File)>> = (0..QUEUE_DEPTH as usize).map(|_| None).collect();
        
        let mut file_idx = 0;
        let pending_vec: Vec<PendingFile> = pending_files.into_iter().collect();

        // Process loop
        while results.len() < total_files_count {
            let mut submission = self.ring.submission();
            let mut submitted_any = false;
            
            // Fill submission queue
            while in_flight < QUEUE_DEPTH && file_idx < total_files_count {
                // Find a free buffer slot
                if let Some(slot) = buf_file_map.iter().position(|x| x.is_none()) {
                    // Synchronous Open (Optimized for safety/simplicity)
                    if let Ok(file) = File::open(&pending_vec[file_idx].path) {
                        let fd = file.as_raw_fd();
                        // Submit Async Read
                        let op = opcode::Read::new(types::Fd(fd), buffers[slot].as_mut_ptr(), READ_SIZE as _)
                            .offset(0);
                            
                        unsafe {
                            if submission.push(&op.build().user_data(slot as u64)).is_ok() {
                                buf_file_map[slot] = Some((file_idx, file)); // Keep file open!
                                in_flight += 1;
                                file_idx += 1;
                                submitted_any = true;
                            } else {
                                // Queue full unexpectedly or logic error
                                break;
                            }
                        }
                    } else {
                        // Open failed, skip
                        file_idx += 1;
                         let p = &pending_vec[file_idx-1];
                         results.push(FileEntry::new(
                                p.path.to_string_lossy().to_string(),
                                p.metadata.len(),
                                p.metadata.mode(),
                                p.metadata.mtime(),
                                0.0
                            ));
                    }
                } else {
                    break; // No free slots
                }
            }
            drop(submission); // Release borrow
            
            if submitted_any || in_flight > 0 {
                 self.ring.submit_and_wait(1).unwrap();
            }
            
            let mut completion = self.ring.completion();
            while let Some(cqe) = completion.next() {
                let slot = cqe.user_data() as usize;
                let res = cqe.result();
                
                if let Some((idx, _file)) = buf_file_map[slot].take() {
                    in_flight -= 1;
                    let p = &pending_vec[idx];
                    let entropy = if res > 0 {
                        calculate_entropy_from_buffer(&buffers[slot], res as usize)
                    } else {
                        0.0
                    };
                    
                    results.push(FileEntry::new(
                        p.path.to_string_lossy().to_string(),
                        p.metadata.len(),
                        p.metadata.mode(),
                        p.metadata.mtime(),
                        entropy
                    ));
                }
            }
        }

        let entropy_time = entropy_start.elapsed();
        let total_time = start.elapsed();
        let files_per_sec = if total_time.as_secs_f64() > 0.0 {
            results.len() as f64 / total_time.as_secs_f64()
        } else { 0.0 };

        ScanResult {
            files: results,
            scan_time_ms: scan_time.as_secs_f64() * 1000.0,
            entropy_time_ms: entropy_time.as_secs_f64() * 1000.0,
            total_time_ms: total_time.as_secs_f64() * 1000.0,
            files_per_sec,
        }
    }
}

// ============================================================================
// PYTHON BINDINGS (PyO3)
// ============================================================================

#[pyclass]
pub struct DeepVisScanner {
    scanner: AsyncScanner,
}

#[pymethods]
impl DeepVisScanner {
    #[new]
    fn new() -> PyResult<Self> {
        let scanner = AsyncScanner::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(DeepVisScanner { scanner })
    }
    
    fn scan(&mut self, root: &str, _limit: Option<usize>) -> PyResult<ScanResult> {
        Ok(self.scanner.scan(root))
    }

    /// Backwards compatibility stub for scan_to_csv (just calls scan)
    /// Ideally we would implement streaming io_uring too, but for now reuse memory scan
    fn scan_to_csv(&mut self, root: &str, output_path: &str, _limit: Option<usize>) -> PyResult<ScanResult> {
         let result = self.scanner.scan(root);
         
         // Write CSV here in Rust to avoid Python overhead
         let file = File::create(output_path)?;
         let mut writer = io::BufWriter::new(file);
         writeln!(writer, "path,size,mode,mtime,entropy,r,g,b,hash")?;
         
         for e in &result.files {
             writeln!(writer, "{},{},{},{},{:.4},{},{},{},{}", 
                 e.path, e.size, e.mode, e.mtime, e.entropy,
                 e.entropy, 0.0, 0.0, // Placeholder
                 e.hash
             )?;
         }
         
         // Return empty file list to save memory like before
         Ok(ScanResult {
             files: Vec::new(),
             scan_time_ms: result.scan_time_ms,
             entropy_time_ms: result.entropy_time_ms,
             total_time_ms: result.total_time_ms,
             files_per_sec: result.files_per_sec,
         })
    }
    
    #[staticmethod]
    fn hash_coords(path: &str, img_size: u32) -> (u32, u32) {
        compute_hash_coords(path, img_size)
    }
    
    #[staticmethod]
    fn entropy(_path: &str) -> f64 {
        // Stub for static method compatibility
        0.0 
    }
}

#[pymodule]
fn deepvis_scanner(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DeepVisScanner>()?;
    m.add_class::<FileEntry>()?;
    m.add_class::<ScanResult>()?;
    Ok(())
}
