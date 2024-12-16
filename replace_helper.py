# replace_helper.py
import sys
import time
import shutil
import os
import zipfile
import subprocess

def replace_files(source_zip, target_directory):
    with zipfile.ZipFile(source_zip, 'r') as zip_ref:
        zip_ref.extractall(target_directory)
    print("Files have been successfully replaced.")

def main():
    if len(sys.argv) != 3:
        print("Usage: python replace_helper.py <source_zip> <target_directory>")
        sys.exit(1)
    
    source_zip = sys.argv[1]
    target_directory = sys.argv[2]

    # Wait briefly to ensure the main script has fully exited
    time.sleep(2)

    try:
        replace_files(source_zip, target_directory)
    except Exception as e:
        print(f"An error occurred during file replacement: {e}")
        sys.exit(1)

    # Optionally, restart the main script after replacement
    main_script = os.path.join(target_directory, 'main.py')
    if os.path.exists(main_script):
        try:
            print("Đã thay thế các tập tin bằng copy mới. Vui lòng chạy lại chương trình bằng 'python main.py'")
        except Exception as e:
            print(f"Failed to restart the main script: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()