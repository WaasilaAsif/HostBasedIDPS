"""
Enhanced Comprehensive IDPS Test Script
=======================================
Tracks which files are quarantined or locked during testing.
"""

import os
import time
import shutil
import random
import string
import stat

IDPS_TEST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "idps_test")
BASE_DIR = IDPS_TEST_PATH
os.chmod(IDPS_TEST_PATH, stat.S_IWRITE)


def banner(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def random_text(size=100):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))


def log_files_state():
    """Logs current state of files in the test directory."""
    print("[STATE] Current files in idps_test:")
    for root, dirs, files in os.walk(BASE_DIR):
        for f in files:
            path = os.path.join(root, f)
            perms = oct(os.stat(path).st_mode)[-3:]
            print(f" - {path} | perms: {perms}")


# -------------------------------------------------
# 1️⃣ FILE CREATION TEST
# -------------------------------------------------
def test_file_creation():
    banner("TEST 1: File Creation")
    for i in range(3):
        path = os.path.join(BASE_DIR, f"create_test_{i}.txt")
        with open(path, "w") as f:
            f.write("Initial content")
        time.sleep(0.5)
    log_files_state()


# -------------------------------------------------
# 2️⃣ FILE MODIFICATION TEST
# -------------------------------------------------
def test_file_modification():
    banner("TEST 2: File Modification")
    path = os.path.join(BASE_DIR, "modify_test.txt")
    with open(path, "w") as f:
        f.write("Start")
    for i in range(5):
        with open(path, "a") as f:
            f.write(f"\nUpdate {i}")
        time.sleep(0.4)
    log_files_state()


# -------------------------------------------------
# 3️⃣ FILE DELETE TEST
# -------------------------------------------------
def test_file_deletion():
    banner("TEST 3: File Deletion")
    path = os.path.join(BASE_DIR, "delete_test.txt")
    with open(path, "w") as f:
        f.write("Delete me")
    time.sleep(1)
    try:
        os.chmod(path, stat.S_IWRITE)
    except Exception:
        pass
    os.remove(path)
    log_files_state()


# -------------------------------------------------
# 4️⃣ FILE MOVE / RENAME TEST
# -------------------------------------------------
def test_file_move():
    banner("TEST 4: File Move / Rename")
    src = os.path.join(BASE_DIR, "move_test.txt")
    dst = os.path.join(BASE_DIR, "moved_test.txt")
    with open(src, "w") as f:
        f.write("Moving file")
    time.sleep(1)
    shutil.move(src, dst)
    log_files_state()


# -------------------------------------------------
# 5️⃣ HIGH-FREQUENCY ANOMALY TEST
# -------------------------------------------------
def test_high_frequency_events():
    banner("TEST 5: High-Frequency Event Burst")
    path = os.path.join(BASE_DIR, "burst_test.txt")
    with open(path, "w") as f:
        f.write("Burst start")
    for i in range(20):
        with open(path, "a") as f:
            f.write(random_text(50))
        time.sleep(0.05)
    log_files_state()


# -------------------------------------------------
# 6️⃣ RANSOMWARE-LIKE BEHAVIOR
# -------------------------------------------------
def test_ransomware_simulation():
    banner("TEST 6: Ransomware-like Simulation")
    ransom_dir = os.path.join(BASE_DIR, "ransom_sim")
    os.makedirs(ransom_dir, exist_ok=True)
    files = []
    for i in range(10):
        path = os.path.join(ransom_dir, f"victim_{i}.txt")
        with open(path, "w") as f:
            f.write("IMPORTANT DATA")
        files.append(path)
    time.sleep(1)
    # simulate encryption (overwrite files rapidly)
    for path in files:
        with open(path, "w") as f:
            f.write(random_text(500))
        time.sleep(0.1)
    log_files_state()


# -------------------------------------------------
# 7️⃣ BENIGN BEHAVIOR TEST (LOW NOISE)
# -------------------------------------------------
def test_benign_behavior():
    banner("TEST 7: Benign Behavior (Low Noise)")
    path = os.path.join(BASE_DIR, "benign.txt")
    with open(path, "w") as f:
        f.write("Normal activity")
    time.sleep(2)
    with open(path, "a") as f:
        f.write("\nUser update")
    log_files_state()


# -------------------------------------------------
# 🚀 RUN ALL TESTS WITH ERROR HANDLING
# -------------------------------------------------
if __name__ == "__main__":
    if not os.path.exists(BASE_DIR):
        print("ERROR: idps_test directory not found")
        exit(1)

    banner("STARTING FULL IDPS TEST SUITE")

    test_functions = [
        test_file_creation,
        test_file_modification,
        test_file_deletion,
        test_file_move,
        test_high_frequency_events,
        test_ransomware_simulation,
        test_benign_behavior
    ]

    for test_func in test_functions:
        try:
            test_func()
            print(f"[INFO] {test_func.__name__} completed successfully.\n")
        except Exception as e:
            print(f"[WARNING] {test_func.__name__} encountered an error: {e}\n")
        time.sleep(1)

    banner("ALL TESTS COMPLETED")
