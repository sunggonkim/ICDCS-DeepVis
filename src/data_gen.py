
import random
import time
import copy
from dataclasses import dataclass
from typing import List, Tuple

# Constants for simulation
NUM_FILES = 10000
MAX_SIZE = 100 * 1024 * 1024  # 100 MB max file size
CURRENT_TIME = int(time.time())

@dataclass
class FileEntry:
    filename: str
    size: int
    permissions: int  # e.g., 644, 755
    owner: str
    mtime: int
    entropy: float = 0.0 # Shannon entropy 0-8

    def clone(self):
        return FileEntry(
            filename=self.filename,
            size=self.size,
            permissions=self.permissions,
            owner=self.owner,
            mtime=self.mtime,
            entropy=self.entropy
        )

def _generate_random_filename(depth_prob=0.3):
    """Generates a random unix-like filepath."""
    dirs = ['/bin', '/usr/bin', '/etc', '/var/log', '/home/user', '/lib', '/opt']
    base = random.choice(dirs)
    
    # Simulate nested directories
    while random.random() < depth_prob:
        base += f"/dir_{random.randint(0, 99)}"
        
    filename = f"{base}/file_{random.randint(0, 999999)}.ext"
    return filename

def generate_baseline() -> List[FileEntry]:
    """Generates a baseline file system state with 10,000 files."""
    files = []
    
    # Common permissions
    perms = [0o644, 0o755, 0o600, 0o777, 0o440]
    perm_weights = [0.5, 0.3, 0.15, 0.02, 0.03]
    
    for _ in range(NUM_FILES):
        # Size distribution: mostly small files, few large ones (Pareto-ish)
        # Using simple expovariate for prototype
        size = int(random.expovariate(1.0 / 10000)) + 1 # Average 10KB
        if size > MAX_SIZE:
             size = MAX_SIZE
             
        mtime = CURRENT_TIME - random.randint(0, 365 * 24 * 3600) # Past year
        
        entry = FileEntry(
            filename=_generate_random_filename(),
            size=size,
            permissions=random.choices(perms, weights=perm_weights)[0],
            owner="root" if random.random() > 0.1 else "user",
            mtime=mtime,
            entropy=random.uniform(4.0, 6.0) # Normal text/bin entropy
        )
        files.append(entry)
        
    return files

def simulate_normal_update(baseline: List[FileEntry]) -> List[FileEntry]:
    """Simulates a system update (apt upgrade).
    
    Modifies 5-10% of files. Changes size and mtime.
    Some files might be 'replaced' (same name, new params).
    """
    new_state = [f.clone() for f in baseline]
    
    # 5-10% modification
    num_mods = int(len(baseline) * random.uniform(0.05, 0.10))
    indices = random.sample(range(len(baseline)), num_mods)
    
    update_time = CURRENT_TIME
    
    for idx in indices:
        f = new_state[idx]
        # Simulate binary update: size changes slightly, mtime updates to now
        f.size = int(f.size * random.uniform(0.8, 1.2))
        if f.size < 1: f.size = 1
        f.mtime = update_time
        # Entropy remains stable for normal updates (recompilation might change it slightly)
        f.entropy = max(0.0, min(8.0, f.entropy + random.uniform(-0.1, 0.1)))
        
    return new_state

def simulate_rootkit_attack(baseline: List[FileEntry]) -> List[FileEntry]:
    """Simulates a rootkit attack.
    
    1. Replacing system binaries (ls, ps) -> Size change, mtime change (unless timestomped)
    2. Injecting new files (backdoors) -> Anomalous permissions
    3. Timestomping -> Mtime mismatch (logic handled in generation, visualized in model)
    """
    attack_state = [f.clone() for f in baseline]
    
    targets = random.sample(range(len(attack_state)), random.randint(1, 3))
    
    for idx in targets:
        f = attack_state[idx]
        # Attack 1: Modify Binary (Rootkit infection)
        # Often rootkits try to hide by keeping size similar, but let's assume slight variance
        f.size =  int(f.size * random.uniform(0.9, 1.1)) 
        
        # Attack 3: Timestomping and High Entropy (Packed)
        # Rootkits are often packed/encrypted to avoid signature detection.
        # This raises entropy to > 7.0 (Simulating "Real Internet Attack" characteristics)
        f.entropy = random.uniform(7.5, 7.99)
        
        # Let's simple modify it to be malicious:
        # e.g. SUID bit set on a file that shouldn't have it
        f.permissions = 0o4755 # SUID root
        
        # Let's also modify mtime to be "too old" or "future" or just "now" if they are careless.
        # Let's assume careless attacker for detection showcase:
        f.mtime = CURRENT_TIME 

    # Attack 2: Inject new file
    # This actually adds a NEW entry which causes pixel shifts if using sorting.
    # Our Hash-mapping solves this.
def simulate_diamorphine_attack(base_state: List[FileEntry]) -> List[FileEntry]:
    """
    Simulates Diamorphine LKM Rootkit.
    Characteristics: 
    - Kernel module injection (usually ends in .ko)
    - Hides itself from lsmod (metadata might not show this, but file exists on disk if not perfectly hidden)
    - High Entropy (Packed/Binary)
    """
    attack_state = [f.clone() for f in base_state]
    
    # Diamorphine often resides in /lib/modules/... or /usr/lib/...
    # We simply inject the module loader binary
    diamorphine_ko = FileEntry(
        filename="/lib/modules/5.15.0-generic/kernel/drivers/diamorphine.ko",
        size=14200, # A typical small size for LKM
        permissions=0o644,
        owner="root",
        mtime=CURRENT_TIME,
        entropy=7.82 # High entropy
    )
    attack_state.append(diamorphine_ko)
    return attack_state

def simulate_reptile_attack(base_state: List[FileEntry]) -> List[FileEntry]:
    """
    Simulates Reptile Rootkit.
    Characteristics:
    - Userland component + Kernel component
    - 'reptile_cmd' binary often placed in /bin or /usr/bin
    - Backdoor listener
    """
    attack_state = [f.clone() for f in base_state]
    
    reptile_cmd = FileEntry(
        filename="/usr/bin/reptile_cmd",
        size=24560,
        permissions=0o755,
        owner="root",
        mtime=CURRENT_TIME,
        entropy=7.65
    )
    attack_state.append(reptile_cmd)
    
    return attack_state

def simulate_beurk_attack(base_state: List[FileEntry]) -> List[FileEntry]:
    """
    Simulates Beurk Rootkit (LD_PRELOAD based).
    Characteristics:
    - Malicious .so library
    - Modifies /etc/ld.so.preload
    """
    attack_state = [f.clone() for f in base_state]
    
    # 1. The malicious library
    libbeurk = FileEntry(
        filename="/lib/libbeurk.so",
        size=18400,
        permissions=0o755,
        owner="root",
        mtime=CURRENT_TIME,
        entropy=7.77 # Packed
    )
    attack_state.append(libbeurk)
    
    # 2. Modification of ld.so.preload (if it exists, append; if not, create)
    # We'll assume we find it or create it
    found = False
    for f in attack_state:
        if f.filename == "/etc/ld.so.preload":
            f.size += 20 # Added line "/lib/libbeurk.so"
            f.mtime = CURRENT_TIME
            found = True
            break
            
    if not found:
        preload = FileEntry(
            filename="/etc/ld.so.preload",
            size=20,
            permissions=0o644,
            owner="root",
            mtime=CURRENT_TIME,
            entropy=4.2 # Text file entropy
        )
        attack_state.append(preload)
        
    return attack_state

if __name__ == "__main__":
    # Quick test
    base = generate_baseline()
    print(f"Baseline: {len(base)} files")
    
    updated = simulate_normal_update(base)
    print(f"Updated: {len(updated)} files")
    
    attacked = simulate_rootkit_attack(base)
    print(f"Attacked: {len(attacked)} files")
