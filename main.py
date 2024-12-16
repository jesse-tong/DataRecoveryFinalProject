import os
import zipfile
from pathlib import Path
import shutil
import sys
import subprocess
import zipfile
import time
from Crypto.Hash import SHA256
from cli import main_program

def hash_file(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = SHA256.new()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def hash_all_python_source_files(directory = os.path.abspath(os.path.dirname(__file__))):
    """Hash all .py files in the specified directory and its subdirectories."""
    hash_values = []
    for root, _, files in os.walk(directory):
        for file in files:
            # Get all .py files except files with parents in the .venv directory
            if file.endswith(".py") and ".venv" not in Path(root).parts:
                file_path = os.path.join(root, file)
                hash_value = hash_file(file_path)
                hash_values.append(hash_value)
    concatenated_hashes = "".join(hash_values)
    sha256_hash = SHA256.new()
    sha256_hash.update(concatenated_hashes.encode())
    return sha256_hash.hexdigest()

def create_zip_with_py_files(zip_name):
    """Create a ZIP file containing this script and all .py files in the parent directory and subdirectories."""
    current_file = Path(__file__)  # Path to this script
    parent_dir = current_file.parent  # Parent directory of this script
    zip_path = parent_dir / zip_name  # Path for the ZIP file

    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add all .py files from the parent directory and subdirectories
            for root, _, files in os.walk(parent_dir):
                for file in files:
                    # Get all .py files except files with parents in the .venv directory
                    if file.endswith(".py") and ".venv" not in Path(root).parts:
                        file_path = Path(root) / file
                        # Add the file to the ZIP archive
                        # Use relative path to maintain directory structure
                        zipf.write(file_path, file_path.relative_to(parent_dir))
    except Exception as e:
        print(f"An error occurred: {e}")

def extract_zip(source_zip, extract_to):
    with zipfile.ZipFile(source_zip, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    print(f"Extracted '{source_zip}' to '{extract_to}'.")

def start_helper(source_zip, target_directory):
    helper_script = os.path.join(target_directory, 'replace_helper.py')
    
    if not os.path.exists(helper_script):
        print(f"Helper script '{helper_script}' not found.")
        sys.exit(1)
    
    # Construct the command to run the helper script
    command = ['python', helper_script, source_zip, target_directory]

    
    # Start the helper script as a separate process
    try:
        if sys.platform.startswith('win'):
            # Detach the process on Windows
            subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # Detach the process on Unix-like systems
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
        print("Helper script started for file replacement.")
    except Exception as e:
        print(f"Failed to start helper script: {e}")
        sys.exit(1)

def self_replace(source_zip):
    # Get the absolute path of the current script
    current_script = os.path.abspath(__file__)
    target_directory = os.path.dirname(current_script)
    
    # Start the helper script to perform replacement
    start_helper(source_zip, target_directory)
    
    # Exit the main script to allow the helper to replace it
    print("Exiting main script to allow replacement.")
    sys.exit(0)

def replace_own_source_with_zip_content(source_zip_name: str):
    # Path to the source.zip file (assumed to be in the same directory as repair.py)
    current_script = os.path.abspath(__file__)
    target_directory = os.path.dirname(current_script)
    source_zip = os.path.join(target_directory, source_zip_name)
    
    if not os.path.exists(source_zip):
        print(f"Source zip file '{source_zip}' not found.")
        sys.exit(1)
    
    self_replace(source_zip)

def init_and_check_integrity():
    source_copy_exists = os.path.exists('source.zip')
    if not source_copy_exists:
        create_zip_with_py_files('source.zip')
    
    source_hash_exists = os.path.exists('source_hash.sha256')
    source_copy_hash_exists = os.path.exists('source_copy_hash.sha256')

    #Create hash files for source code and source copy zip files if not exists
    if not source_hash_exists:
        source_hash = hash_all_python_source_files()
        with open('source_hash.sha256', 'w') as f:
            f.write(source_hash)
    
    if not source_copy_hash_exists:
        source_copy_hash = hash_all_python_source_files('source_copy')
        with open('source_copy_hash.sha256', 'w') as f:
            f.write(source_copy_hash)

    #Check integrity of source code and source copy zip files
    source_hash_file = "source_hash.sha256"
    source_copy_hash_file = "source_copy_hash.sha256"
    source_copy_zip_file = "source.zip"

    current_source_hash = hash_all_python_source_files()
    current_source_copy_hash = hash_all_python_source_files(source_copy_zip_file)

    with open(source_hash_file, 'r') as f:
        source_hash = f.read()
    
    with open(source_copy_hash_file, 'r') as f:
        source_copy_hash = f.read()
        
    if source_hash != current_source_hash:
        #If source code has been tampered, replace source code with source copy
        print("Source code has been tampered. Replacing with source copy.")
        #Check hash of source copy zip file
        if source_copy_hash != current_source_copy_hash:
            print("Source copy has been tampered. Exiting.")
            sys.exit(1)
        else:
            replace_own_source_with_zip_content(source_copy_zip_file)
            print("Source code has been replaced with source copy. Stoping...")
    
    # If source copy zip file has been tampered while the main program is intact, 
    # replace source copy zip file with zip file from source code
    if source_hash == current_source_hash and source_copy_hash != current_source_copy_hash:
        print("Source copy has been tampered. Replacing with source code.")
        os.remove(source_copy_hash_file)
        os.remove(source_copy_zip_file)
        create_zip_with_py_files(source_copy_zip_file)
        source_copy_hash = hash_file(source_copy_zip_file)
        with open('source_copy_hash.sha256', 'w') as f:
            f.write()
        return

if __name__ == "__main__":
    init_and_check_integrity()
    main_program()