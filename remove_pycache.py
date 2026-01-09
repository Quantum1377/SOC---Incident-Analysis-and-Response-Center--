import os
import shutil

def remove_pycache_dirs(root_dir):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        if '__pycache__' in dirnames:
            pycache_path = os.path.join(dirpath, '__pycache__')
            print(f"Removing: {pycache_path}")
            try:
                shutil.rmtree(pycache_path)
            except OSError as e:
                print(f"Error removing {pycache_path}: {e}")

if __name__ == '__main__':
    script_dir = os.getcwd() # Start from the current working directory
    remove_pycache_dirs(script_dir)
print("Finished cleaning __pycache__ directories.")
