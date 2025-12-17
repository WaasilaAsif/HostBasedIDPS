
#  `response.py` — Line-by-Line Technical Explanation  
> **Purpose**: Automated prevention engine — executes concrete defensive actions (quarantine, lock, kill, block) with OS-aware, safe, and auditable logic.

---

##  Imports & Dependencies

```python
import os
```
> Core OS operations: `os.path.*`, `os.chmod()`, `os.makedirs()`, `os.walk()`.

```python
import shutil
```
> High-level file operations: `shutil.move()` for atomic(ish) file quarantine.

```python
import psutil
```
> Cross-platform process and system monitoring — enables PID lookup, process termination, and open file inspection.

```python
import subprocess
```
> Executes OS-native firewall commands (`netsh`, `iptables`) for network-level blocking.

```python
import platform
```
> Detects OS (`platform.system()`) to select correct firewall syntax.

```python
import time
```
> Imported but *not used* — safe to remove unless future rate-limiting is added.

---

## Class: `ResponseEngine`

```python
class ResponseEngine:
```
> Encapsulates all *preventive actions* — designed for safety, auditability, and extensibility.

---

### `__init__()` — Setup & Safety

```python
    def __init__(self, quarantine_dir="./quarantine", dry_run=False):
```
> Constructor with two critical parameters:
> - `quarantine_dir`: Isolated storage for suspicious files (default: `./quarantine`).
> - `dry_run`: Safety switch — if `True`, *only logs* actions (no real changes). Essential for testing.

```python
        self.quarantine_dir = quarantine_dir
        self.dry_run = dry_run
```
> Store configuration for later use.

```python
        os.makedirs(self.quarantine_dir, exist_ok=True)
```

---

##   File Protection Methods

### `quarantine_file(path)`

```python
    def quarantine_file(self, path):
        if not os.path.exists(path):
            return
```
> Early exit if file already gone (e.g., deleted during detection → response race).

```python
        dest = os.path.join(self.quarantine_dir, os.path.basename(path))
```
> Preserves original filename in quarantine — aids forensics (e.g., `ransomware.exe` stays `ransomware.exe`).

```python
        print(f"[RESPONSE] Quarantining file: {path}")
```
> Auditable action log — critical for SOCs and debugging.

```python
        if not self.dry_run:
            try:
                shutil.move(path, dest)
            except Exception as e:
                print(f"[ERROR] Failed to quarantine file: {e}")
```
>  **Why `shutil.move()`?**  
> - On same filesystem: `rename()` → atomic, fast, preserves metadata.  
> - Across filesystems: copy+delete → safe fallback.  

---

###  `lock_file(path)`

```python
    def lock_file(self, path):
        if not os.path.exists(path):
            return
```
> Skip missing files.

```python
        print(f"[RESPONSE] Locking file permissions: {path}")
```
> Clear audit trail.

```python
        if not self.dry_run:
            try:
                os.chmod(path, 0o400)  # read-only
            except Exception as e:
                print(f"[ERROR] Failed to lock file: {e}")
```
> **Why `0o400`?**  
> - Owner: read-only (`r--`)  
> - Group/others: no access (`---`)  
> → Prevents *modification/deletion*, but allows *reading* (forensics, analysis).  
>  
> **Portability**: Works on Unix/Linux/macOS. **Fails silently on Windows** (NTFS ignores `chmod`).  
> **Fix later**: Use `win32security` for Windows ACLs.

---

##   Process Protection Methods

### `kill_process(pid)`

```python
    def kill_process(self, pid):
        try:
            proc = psutil.Process(pid)
            print(f"[RESPONSE] Killing process PID={pid}")
```
> Validates PID exists and is accessible (raises `psutil.NoSuchProcess` if not).

```python
            if not self.dry_run:
                proc.terminate()
        except Exception as e:
            print(f"[ERROR] Failed to kill process: {e}")
```
> **Why `terminate()` (not `kill()`)?**  
> - Sends `SIGTERM` (Unix) / `WM_CLOSE` (Windows) → allows graceful shutdown (e.g., save state, cleanup).  
> - Falls back to `kill()` internally if unresponsive (after 3s in `psutil`).  
>  
>  **Privilege note**: Requires same/elevated privileges as target process.

---

## Network Protection: `block_ip(ip)`

```python
    def block_ip(self, ip):
        print(f"[RESPONSE] Blocking IP: {ip}")
```
> Logs intent — even in `dry_run`.

```python
        if self.dry_run:
            return
```
> Safety first.

```python
        system = platform.system().lower()
```
> Detects OS: returns `"windows"`, `"linux"`, `"darwin"`.

```python
        try:
            if system == "windows":
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add",
                    "rule", f"name=Block_{ip}",
                    "dir=out", "action=block", f"remoteip={ip}"
                ], check=True)
```
> **Windows firewall rule**:  
> - Blocks *outbound* traffic to `ip` (prevents C2 callbacks).  
> - Named `Block_<ip>` → easy to list/remove later (`netsh ... delete rule name=...`).  
> - `check=True` → raises `CalledProcessError` on failure (e.g., non-admin).

```python
            elif system == "linux":
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"
                ], check=True)
```

```python
        except Exception as e:
            print(f"[ERROR] Failed to block IP: {e}")
```
> Graceful degradation — logs error but doesn’t crash IDPS.

---

##  Advanced Defense: Directory Lockdown & Process Killing

### `lock_directory(dir_path)`

```python
    def lock_directory(self, dir_path):
        print(f"[RESPONSE] Locking directory: {dir_path}")
        if self.dry_run:
            return
```
> Full-directory containment — critical for ransomware that hits folders.

```python
        # Lock all files
        for root, dirs, files in os.walk(dir_path):
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), 0o400)
                except Exception as e:
                    print(f"[ERROR] Failed to lock file in dir: {e}")
```
> Recursively applies `0o400` to *every file* — stops further encryption/modification.

```python
        # Lock folder itself (prevents new file creation)
        try:
            os.chmod(dir_path, 0o555)
        except Exception:
            pass
```
>  **Why `0o555`?**  
> - Owner/group/others: `r-x` (read + execute)  
> → Allows *listing directory contents* (`ls`), but **no write** → blocks new files.  
>  
>  `pass` on error: directory may be locked already, or permissions denied (e.g., `/proc`). Safe to ignore.

> **Defense-in-depth**: Files locked (`0o400`) + directory locked (`0o555`) = full containment.

---

###  `kill_offending_process(dir_path)`

```python
    def kill_offending_process(self, dir_path):
        import psutil
```
> Local import — avoids circular dependency if `psutil` were top-level and re-imported elsewhere.

```python
        for proc in psutil.process_iter(['pid', 'open_files', 'name']):
```
> Efficient iteration: fetches only needed fields (`pid`, `open_files`, `name`) — minimizes syscall overhead.

```python
            try:
                files = proc.info['open_files']
                if files:
                    for f in files:
                        if f.path.startswith(dir_path):
```
> **Smart targeting**:  
> - Checks if any open file path *starts with* `dir_path` (e.g., `/home/user/attack/` matches `/home/user/attack/payload.exe`).  
> - Uses `f.path` (full path) — not just filename.

```python
                            print(f"[RESPONSE] Killing process PID={proc.info['pid']} with open file {f.path}")
                            self.kill_process(proc.info['pid'])
                            break
```
> - Logs *which file* triggered the kill → forensic value.  
> - `break` after first match → kills process once (avoids duplicate logs/calls).

```python
            except Exception:
                continue
```
>  **Resilience**:  
> - Skips processes with no permissions (e.g., root-owned from user IDPS).  
> - Ignores zombies, terminated processes, or `open_files=None`.

>  **Why this matters**: Ransomware holds file handles open — killing it *mid-encryption* preserves unencrypted files.

---

##  Architectural Strengths

| Feature | Why It’s Smart |
|--------|----------------|
| **`dry_run` Safety** | Allows full testing without risk — essential for student projects and production staging. |
| **Error Containment** | `try/except` on every action — one failure (e.g., block IP) doesn’t stop quarantine. |
| **Audit-First Design** | Every action logs `[RESPONSE]` or `[ERROR]` — perfect for compliance. |
| **Cross-Platform Awareness** | OS detection + native tools (`netsh`/`iptables`) — not just Unix-centric. |
| **Escalating Defense** | File lock → quarantine → directory lockdown → process kill = layered response. |

---

