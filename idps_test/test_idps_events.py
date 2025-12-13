import os
import time

# Paths for testing
test_dir = os.path.join(os.path.dirname(__file__))
normal_file = os.path.join(test_dir, 'normal', 'normal_file1.txt')
suspicious_file = os.path.join(test_dir, 'suspicious', 'suspicious_file1.txt')

# Create a new file in normal/
with open(os.path.join(test_dir, 'normal', 'created_by_script.txt'), 'w') as f:
    f.write('This file was created by the test script.')

# Modify an existing file in normal/
with open(normal_file, 'a') as f:
    f.write('\nAppended line for modification test.')

# Move a file from suspicious/ to normal/
moved_dest = os.path.join(test_dir, 'normal', 'moved_from_suspicious.txt')
if os.path.exists(moved_dest):
    os.remove(moved_dest)
os.rename(suspicious_file, moved_dest)

# Wait and then delete a file in normal/
time.sleep(2)
os.remove(os.path.join(test_dir, 'normal', 'normal_file2.txt'))

print('Test file operations completed.')
