import os
import itertools
import statistics

# Configuration
BENIGN_ROOT = "/usr/bin"
MALWARE_ROOT = "/home/bigdatalab/Malware"
LIMIT = 10000

keywords = ["rootkit", "backdoor", "trojan", "exploit", "shell", "rat", "c99"]

def scan_features(root, limit, label):
    data = []
    count = 0
    print(f"Scanning {label}: {root}...")
    for r, d, f in os.walk(root):
        for file in f:
            path = os.path.join(r, file)
            path_lower = path.lower()
            
            # Features
            is_tmp = "/tmp" in path_lower or "/dev/shm" in path_lower
            is_hidden = file.startswith(".")
            has_kw = any(k in path_lower for k in keywords)
            
            # Additional logic for Malware simulation
            # (In real attacks, malware often uses /tmp. In repo, it's irrelevant. 
            # We skip simulating /tmp injection to be honest to the 'repo data', 
            # acknowledging w_tmp might be insensitive here.)
            
            data.append((is_tmp, is_hidden, has_kw))
            count += 1
            if count >= limit: break
        if count >= limit: break
    return data

benign_data = scan_features(BENIGN_ROOT, LIMIT, "Benign")
malware_data = scan_features(MALWARE_ROOT, LIMIT, "Malware")

print(f"Data Loaded: {len(benign_data)} Benign, {len(malware_data)} Malware")

# Grid Search
# w_tmp is likely insensitive due to repo paths, but let's include it.
w_tmp_range = [0.1, 0.4, 0.7, 1.0]
w_hidden_range = [0.1, 0.2, 0.5]
w_kw_range = [0.1, 0.3, 0.4, 0.5]

best_score = -1
best_cfg = None

print("\nRunning Grid Search...")
print(f"{'w_tmp':<6} {'w_hid':<6} {'w_kw':<6} | {'Sep':<6} | {'B_Mean':<6} {'M_Mean':<6}")
print("-" * 50)

for w_t, w_h, w_k in itertools.product(w_tmp_range, w_hidden_range, w_kw_range):
    # Calculate Mean Scores
    # Score = min(1.0, sum of weights)
    
    # Benign
    b_scores = []
    for t, h, k in benign_data:
        s = 0.0
        if t: s += w_t
        if h: s += w_h
        if k: s += w_k
        b_scores.append(min(1.0, s))
    b_mean = statistics.mean(b_scores) if b_scores else 0
    
    # Malware
    m_scores = []
    for t, h, k in malware_data:
        s = 0.0
        if t: s += w_t
        if h: s += w_h
        if k: s += w_k
        m_scores.append(min(1.0, s))
    m_mean = statistics.mean(m_scores) if m_scores else 0
    
    separation = m_mean - b_mean
    
    if separation > best_score:
        best_score = separation
        best_cfg = (w_t, w_h, w_k)
        # Print improvement
        # print(f"{w_t:<6} {w_h:<6} {w_k:<6} | {separation:<6.4f} | {b_mean:<6.4f} {m_mean:<6.4f} *")

print("-" * 50)
print(f"\n[Result] Optimal Weights found on current dataset:")
print(f"  w_tmp:    {best_cfg[0]} (Note: Insensitive if not in /tmp)")
print(f"  w_hidden: {best_cfg[1]}")
print(f"  w_kw:     {best_cfg[2]}")
print(f"  Max Separation: {best_score:.4f}")
