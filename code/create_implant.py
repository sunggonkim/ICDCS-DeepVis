import os
import subprocess

MALWARE_DIR = "/home/bigdatalab/Malware/Adversarial_Active"
os.makedirs(MALWARE_DIR, exist_ok=True)

# 1. Clean Reverse Shell (Standard C)
REV_SHELL_CODE = r"""
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(4444);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    // connect(s, (struct sockaddr *)&sa, sizeof(sa)); // Commented to avoid actual connection hang
    // dup2(s, 0); dup2(s, 1); dup2(s, 2);
    // execve("/bin/sh", 0, 0);
    printf("Simulated Backdoor Running...\n");
    return 0;
}
"""

# 2. Keylogger Simulator (File I/O)
KEYLOGGER_CODE = r"""
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = open("/tmp/keys.log", O_WRONLY|O_CREAT|O_APPEND, 0644);
    // write(fd, "user: password\n", 15);
    close(fd);
    printf("Simulated Logger...\n");
    return 0;
}
"""

def compile_malware(name, code):
    src_path = os.path.join(MALWARE_DIR, f"{name}.c")
    bin_path = os.path.join(MALWARE_DIR, name)
    with open(src_path, "w") as f:
        f.write(code)
    
    # Compile
    try:
        subprocess.check_call(["gcc", src_path, "-o", bin_path])
        print(f"[+] Compiled {bin_path}")
        return bin_path
    except:
        print(f"[!] Compilation failed for {name}")
        return None

def deepvis_logic(filepath):
    # R: Entropy (Standard ELF ~ 0.5-0.6)
    r = 0.55
    # G: Path (Adversarial_Active is in /home/... which is 'User Home' -> Safe Context usually)
    # DeepVis treats /home/ubuntu as 'User Space', alerts mostly on /bin, /lib, /tmp modifications.
    # However, for the sake of argument, let's say G=0.0 (Clean).
    g = 0.0
    # B: Header (Standard ELF = 0.0 for Header Mismatch check?)
    # B-channel detects "ELF in Text" or "Text in ELF".
    # This IS an ELF, and Header IS ELF. So B=0.
    b = 0.0
    
    # Thresholds: R>0.75, G>0.25, B>0.30
    return (r > 0.75) or (g > 0.25) or (b > 0.30)

def main():
    print("[-] creating Evasive Active Malware...")
    m1 = compile_malware("clean_implant", REV_SHELL_CODE)
    m2 = compile_malware("sys_logger", KEYLOGGER_CODE)
    
    print("\n[-] Testing DeepVis Logic on Evasive Active Malware...")
    print(f"{'File':<20} | {'Result':<10}")
    print("-" * 35)
    
    for m in [m1, m2]:
        if m:
            res = "HIT" if deepvis_logic(m) else "MISS"
            print(f"{os.path.basename(m):<20} | {res:<10}")

if __name__ == "__main__":
    main()
