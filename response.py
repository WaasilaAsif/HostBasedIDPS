import os
import shutil
import psutil
import subprocess
import platform
import time

class ResponseEngine:
    def __init__(self, quarantine_dir="./quarantine", dry_run=False):
        self.quarantine_dir = quarantine_dir
        self.dry_run = dry_run
        os.makedirs(self.quarantine_dir, exist_ok=True)

    # 🔒 FILE PROTECTION
    def quarantine_file(self, path):
        if not os.path.exists(path):
            return

        dest = os.path.join(self.quarantine_dir, os.path.basename(path))

        print(f"[RESPONSE] Quarantining file: {path}")

        if not self.dry_run:
            try:
                shutil.move(path, dest)
            except Exception as e:
                print(f"[ERROR] Failed to quarantine file: {e}")

    def lock_file(self, path):
        if not os.path.exists(path):
            return

        print(f"[RESPONSE] Locking file permissions: {path}")

        if not self.dry_run:
            try:
                os.chmod(path, 0o400)  # read-only
            except Exception as e:
                print(f"[ERROR] Failed to lock file: {e}")

    # 🔥 PROCESS PROTECTION
    def kill_process(self, pid):
        try:
            proc = psutil.Process(pid)
            print(f"[RESPONSE] Killing process PID={pid}")

            if not self.dry_run:
                proc.terminate()
        except Exception as e:
            print(f"[ERROR] Failed to kill process: {e}")

    # 🚫 NETWORK PROTECTION
    def block_ip(self, ip):
        print(f"[RESPONSE] Blocking IP: {ip}")

        if self.dry_run:
            return

        system = platform.system().lower()

        try:
            if system == "windows":
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add",
                    "rule", f"name=Block_{ip}",
                    "dir=out", "action=block", f"remoteip={ip}"
                ], check=True)

            elif system == "linux":
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"
                ], check=True)

        except Exception as e:
            print(f"[ERROR] Failed to block IP: {e}")
    def lock_directory(self, dir_path):
        print(f"[RESPONSE] Locking directory: {dir_path}")
        if self.dry_run:
            return
        # Lock all files
        for root, dirs, files in os.walk(dir_path):
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), 0o400)
                except Exception as e:
                    print(f"[ERROR] Failed to lock file in dir: {e}")
        # Lock folder itself (prevents new file creation)
        try:
            os.chmod(dir_path, 0o555)
        except Exception:
            pass
        
    def kill_offending_process(self, dir_path):
        import psutil
        for proc in psutil.process_iter(['pid', 'open_files', 'name']):
            try:
                files = proc.info['open_files']
                if files:
                    for f in files:
                        if f.path.startswith(dir_path):
                            print(f"[RESPONSE] Killing process PID={proc.info['pid']} with open file {f.path}")
                            self.kill_process(proc.info['pid'])
                            break
            except Exception:
                continue
            