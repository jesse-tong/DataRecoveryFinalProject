import os
import struct
import hashlib
import datetime
from dateutil.parser import parse as date_parse
from schema import PlatformMetadata
from typing import Optional, List, Tuple
from encryption import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Các phương thức của các lớp:
# pack() - Chuyển đối tượng thành chuỗi bytes
# unpack() - Chuyển chuỗi bytes chứa thông tin đối tượng thành đối tượng

# Constants
VOLUME_INFO_SIZE = 88  # bytes
ENTRY_SIZE = 401        # bytes per entry
ENTRY_TABLE_SIZE = 100  # entries per table
MAIN_ENTRY_TABLE_OFFSET = VOLUME_INFO_SIZE
BACKUP_ENTRY_TABLE_OFFSET = VOLUME_INFO_SIZE + ENTRY_SIZE * ENTRY_TABLE_SIZE
DATA_TABLE_OFFSET = VOLUME_INFO_SIZE + 2 * ENTRY_SIZE * ENTRY_TABLE_SIZE
DATA_BLOCK_SIZE = 4096   # bytes
MAX_FILENAME_LENGTH = 32
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Special Addresses (Start data block address of an unused entry, and the next data block address of the last block of each entry)
ALL_ONES_ADDRESS = b'\xFF' * 8
ALL_ONES_ADDRESS_INT = 0xFFFFFFFFFFFFFFFF

# Helper Functions

#Function to create ISO 8601 formatted date string
def current_iso8601() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(DATE_FORMAT)


# Class storing and managing MyFS's volume information
class VolumeInfo:
    def __init__(self, signature: bytes = b'IVOLFILE', volume_size: int = 0, metadata_encryption_key: bytes = b'\x00' * 32, machine_info_hash: bytes = b'\x00' * 32):
        self.signature = signature.ljust(8, b'\x00')[:8]
        self.volume_size = volume_size  # 16 bytes, but we'll store as two unsigned long longs
        self.encryption_key = metadata_encryption_key  # 32-byte key to encrypt metadata in volume Y
        self.machine_info_hash = machine_info_hash  # Hash of machine info

    def pack(self) -> bytes:
        # Pack signature (8 bytes) + volume_size (16 bytes as two unsigned long longs)
        return self.signature + struct.pack('>QQ', self.volume_size, 0) + self.encryption_key + self.machine_info_hash

    @staticmethod
    def unpack(data: bytes):
        signature = data[:8]
        volume_size1, volume_size2 = struct.unpack('>QQ', data[8:24])
        volume_size = volume_size1 + (volume_size2 << 64)  # Combine two parts
        encryption_key = data[24:56]
        machine_info_hash = data[56:88]
        return VolumeInfo(signature, volume_size, encryption_key, machine_info_hash)

# Class representing an entry in the Entry Table
class Entry:
    def __init__(self,
                 status: int = 0x00,
                 first_block: bytes = ALL_ONES_ADDRESS,
                 filename: str = "",
                 creation_date: str = "",
                 modification_date: str = "",
                 password_hash: bytes = b'\x00' * 32,
                 md5_hash: bytes = b'\x00' * 16,
                 encrypted_size: int = 0,
                 original_size: int = 0,
                 root_dir: str | None = "" ):
        self.status = status
        self.first_block = first_block
        self.filename = filename
        self.creation_date = creation_date or current_iso8601()
        self.modification_date = modification_date or current_iso8601()
        self.password_hash = password_hash
        self.md5_hash = md5_hash
        self.encrypted_size = encrypted_size
        self.original_size = original_size
        self.root_dir = root_dir

    def pack(self) -> bytes:
        packed = struct.pack('>B', self.status)
        packed += self.first_block
        packed += pad_filename(self.filename)
        packed += self.creation_date.encode('ascii').ljust(20, b'\x00')
        packed += self.modification_date.encode('ascii').ljust(20, b'\x00')
        packed += self.password_hash
        packed += self.md5_hash
        packed += struct.pack('>Q', self.encrypted_size)
        packed += struct.pack('>Q', self.original_size)
        if self.root_dir:
            packed += self.root_dir.encode('ascii').ljust(256, b'\x00')
        else:
            packed += b'\x00' * 256
        return packed.ljust(401, b'\x00')  # Ensure fixed size

    @staticmethod
    def unpack(data: bytes):
        status = data[0]
        first_block = data[1:9]
        filename = data[9:41].rstrip(b'\x00').decode('ascii')
        creation_date = data[41:61].decode('ascii').rstrip('\x00')
        modification_date = data[61:81].decode('ascii').rstrip('\x00')
        password_hash = data[81:113]
        md5_hash = data[113:129]
        encrypted_size = struct.unpack('>Q', data[129:137])[0]
        original_size = struct.unpack('>Q', data[137:145])[0]
        if data[145:401].strip(b'\x00'):
            root_dir = data[145:401].decode('ascii').rstrip('\x00')  # 256 bytes
        else:
            root_dir = None
        return Entry(
            status=status,
            first_block=first_block,
            filename=filename,
            creation_date=creation_date,
            modification_date=modification_date,
            password_hash=password_hash,
            md5_hash=md5_hash,
            encrypted_size=encrypted_size,
            original_size=original_size,
            root_dir=root_dir
        )

class EntryTable:
    def __init__(self, entries: Optional[List[Entry]] = None):
        self.entries = entries or [Entry() for _ in range(ENTRY_TABLE_SIZE)]

    def pack(self) -> bytes:
        return b''.join(entry.pack() for entry in self.entries)

    @staticmethod
    def unpack(data: bytes):
        entries = []
        for i in range(ENTRY_TABLE_SIZE):
            entry_data = data[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE]
            entries.append(Entry.unpack(entry_data))
        return EntryTable(entries)

class DataBlock:
    def __init__(self, status: int = 0x00, next_block: bytes = ALL_ONES_ADDRESS, content: bytes = b'\x00' * 4087):
        self.status = status
        self.next_block = next_block
        self.content = content

    def pack(self) -> bytes:
        return struct.pack('>B', self.status) + self.next_block + self.content

    @staticmethod
    def unpack(data: bytes):
        status = data[0]
        next_block = data[1:9]
        content = data[9:4096]
        return DataBlock(status, next_block, content)

# Main File System Class
class FileSystem:
    def __init__(self, file_path: str, metadata_path: str = "metadata.ivf", access_password: str | None = None):
        self.file_path = file_path
        self.metadata_path = metadata_path
        self.access_password = access_password
        if not os.path.exists(file_path):
            self.initialize_filesystem()
        self.load_volume_info()
        self.load_entry_tables()
        self.load_metadata()


    def initialize_filesystem(self):
        with open(self.file_path, 'wb') as f:
            metadata_encryption_key = get_random_bytes(32)
            access_password_hash = hash_sha256(self.access_password) if self.access_password else b'\x00' * 32
            machine_info = PlatformMetadata(self.metadata_path, myFS_password_hash=access_password_hash)
            machine_info_hash = hash_sha256_bytes(machine_info.pack())
            
            # Initialize Volume Info
            volume_info = VolumeInfo(metadata_encryption_key=metadata_encryption_key, machine_info_hash=machine_info_hash)
            f.write(volume_info.pack())

            # Write metadata to a separate file
            with open(self.metadata_path, 'wb') as f_meta:
                machine_info.write_metadata_encrypted(volume_info.encryption_key)

            # Initialize Main and Backup Entry Tables
            entry_table = EntryTable()
            f.write(entry_table.pack())  # Main Entry Table
            f.write(entry_table.pack())  # Backup Entry Table
            # No data blocks initially

    def load_volume_info(self):
        with open(self.file_path, 'rb') as f:
            f.seek(0)
            data = f.read(VOLUME_INFO_SIZE)
            self.volume_info = VolumeInfo.unpack(data)

    def load_entry_tables(self):
        with open(self.file_path, 'rb') as f:
            # Load Main Entry Table
            f.seek(MAIN_ENTRY_TABLE_OFFSET)
            main_table_data = f.read(ENTRY_SIZE * ENTRY_TABLE_SIZE)
            self.main_entry_table = EntryTable.unpack(main_table_data)
            # Load Backup Entry Table
            f.seek(BACKUP_ENTRY_TABLE_OFFSET)
            backup_table_data = f.read(ENTRY_SIZE * ENTRY_TABLE_SIZE)
            self.backup_entry_table = EntryTable.unpack(backup_table_data)

    def save_entry_tables(self):
        with open(self.file_path, 'rb+') as f:
            # Save Main Entry Table
            f.seek(MAIN_ENTRY_TABLE_OFFSET)
            f.write(self.main_entry_table.pack())
            # Save Backup Entry Table
            f.seek(BACKUP_ENTRY_TABLE_OFFSET)
            f.write(self.backup_entry_table.pack())

    # Nạp thông tin metadata chứa thông tin máy tạo MyFS và mật khẩu truy cập
    def load_metadata(self):
        if not os.path.exists(self.metadata_path):
            raise Exception("Không tìm thấy file metadata, vui lòng đặt file metadata tương ứng (metadata.dat) và file volume cùng một thư mục.")
        
        with open(self.metadata_path, 'rb') as f:
            encrypted_metadata = f.read()
        metadata_key = self.volume_info.encryption_key
        decrypted_metadata_bytes = decrypt_data(metadata_key, encrypted_metadata)
        self.fs_metadata = PlatformMetadata.unpack(decrypted_metadata_bytes)
        self.fs_metadata.metadata_path = self.metadata_path

    def compare_metadata(self) -> bool:
        metadata_hash = hash_sha256_bytes(self.fs_metadata.pack())
        file_system_metadata_hash = self.volume_info.machine_info_hash
        return self.fs_metadata == PlatformMetadata(metadata_path=self.metadata_path) and metadata_hash == file_system_metadata_hash
    
    def is_password_match(self, password: str) -> bool:
        password_hash = hash_sha256(password)

        # If no password is set or matches the current password, return True
        if self.fs_metadata.myFS_password_hash == b'' or password_hash == self.fs_metadata.myFS_password_hash:
            return True
        else:
            return False

    def change_access_password(self, old_password: str | None, new_password: str | None):
        if old_password:
            old_password_hash = hash_sha256(old_password)
        else:
            old_password_hash = b''
        if new_password:
            new_password_hash = hash_sha256(new_password)
        else:
            new_password_hash = b''

        # If old password is not set or matches the current password, proceed with password change
        if self.fs_metadata.myFS_password_hash == b'' or old_password_hash == self.fs_metadata.myFS_password_hash:
            old_password_match = True
        else:
            old_password_match = False
        
        if not old_password_match:
            print("Mật khẩu cũ không đúng. Thay đổi mật khẩu truy cập MyFS thất bại.")
            return
        
        if new_password != None and new_password != "":
            self.fs_metadata.myFS_password_hash = new_password_hash
            key_from_new_password = derive_aes_key(new_password_hash)
            self.fs_metadata.write_metadata_encrypted(key_from_new_password)
        else:
            self.fs_metadata.write_metadata()
        
        print("Thay đổi mật khẩu truy cập thành công.")

    def find_entry(self, filename: str) -> Optional[Tuple[str, int, Entry]]:
        # Search in Main Entry Table
        for idx, entry in enumerate(self.main_entry_table.entries):
            if entry.status == 0x01 and entry.filename == filename:
                return ('main', idx, entry)
        # Search in Backup Entry Table
        for idx, entry in enumerate(self.backup_entry_table.entries):
            if entry.status == 0x01 and entry.filename == filename:
                return ('backup', idx, entry)
        return None

    def list_files(self) -> List[Entry]:
        files = []
        for entry in self.main_entry_table.entries:
            if entry.status == 0x01:
                files.append(entry)
        if not files:
            for entry in self.backup_entry_table.entries:
                if entry.status == 0x01:
                    files.append(entry)
        return files

    def find_free_entry(self) -> Optional[Tuple[str, int, Entry]]:
        # Search in Main Entry Table
        for idx, entry in enumerate(self.main_entry_table.entries):
            if entry.status == 0x00:
                return ('main', idx, entry)
        # Search in Backup Entry Table
        for idx, entry in enumerate(self.backup_entry_table.entries):
            if entry.status == 0x00:
                return ('backup', idx, entry)
        return None

    def find_free_data_block(self) -> Optional[int]:
        with open(self.file_path, 'rb') as f:
            f.seek(DATA_TABLE_OFFSET)
            block_index = 0
            while True:
                data = f.read(DATA_BLOCK_SIZE)
                if not data:
                    break
                block = DataBlock.unpack(data)
                if block.status in (0x00, 0x02):
                    return block_index
                block_index += 1
            return block_index  # Next available block index

    def read_data_block(self, block_index: int) -> DataBlock:
        with open(self.file_path, 'rb') as f:
            f.seek(DATA_TABLE_OFFSET + block_index * DATA_BLOCK_SIZE)
            data = f.read(DATA_BLOCK_SIZE)
            if len(data) < DATA_BLOCK_SIZE:
                # Initialize empty block if beyond current size
                return DataBlock()
            return DataBlock.unpack(data)

    def write_data_block(self, block_index: int, block: DataBlock):
        with open(self.file_path, 'rb+') as f:
            f.seek(DATA_TABLE_OFFSET + block_index * DATA_BLOCK_SIZE)
            f.write(block.pack())

    def add_file(self, source_path: str, filename: str, password: Optional[str] = None):
        # Step 1: Find a free entry
        free_entry = self.find_free_entry()
        if not free_entry:
            raise Exception("Không còn entry trống.")
        table_type, entry_idx, entry = free_entry

        # Step 2: Hash the password and file
        if password:
            password_hashed = hash_sha256(password)
        else:
            password_hashed = b'\x00' * 32

        with open(source_path, 'rb') as f:
            file_data = f.read()
            md5_hashed = hash_md5(file_data)
            original_size = len(file_data)

        if password and password != "":
            aes_key = derive_aes_key(password_hashed)
            encrypted_data = encrypt_data(aes_key, file_data)
        else:
            encrypted_data = file_data

        encrypted_size = len(encrypted_data)

        # Step 4: Divide encrypted data into blocks of up to 4087 bytes
        block_size = 4087
        data_chunks = [encrypted_data[i:i + block_size] for i in range(0, len(encrypted_data), block_size)]

        # Step 5: Find or create data blocks
        block_indices = []
        for chunk in data_chunks:
            free_block = self.find_free_data_block()
            block_indices.append(free_block)
            block_content = chunk.ljust(block_size, b'\x00')  # Pad to 4087 bytes
            data_block = DataBlock(status=0x01, next_block=ALL_ONES_ADDRESS, content=block_content)
            self.write_data_block(free_block, data_block)

        # Link the data blocks
        for i in range(len(block_indices) - 1):
            current_block = self.read_data_block(block_indices[i])
            next_block_address = struct.pack('>Q', block_indices[i + 1])
            current_block.next_block = next_block_address
            self.write_data_block(block_indices[i], current_block)

        # Last block points to all ones
        last_block = self.read_data_block(block_indices[-1])
        last_block.next_block = ALL_ONES_ADDRESS
        self.write_data_block(block_indices[-1], last_block)

        # Step 5 Continued: Update Entry
        entry.status = 0x01
        entry.first_block = struct.pack('>Q', block_indices[0])
        entry.filename = filename
        entry.creation_date = current_iso8601()
        entry.modification_date = current_iso8601()
        entry.password_hash = password_hashed
        entry.md5_hash = md5_hashed
        entry.encrypted_size = encrypted_size
        entry.original_size = original_size
        entry.root_dir = str(os.path.abspath(source_path))

        # Save the updated entry
        if table_type == 'main':
            self.main_entry_table.entries[entry_idx] = entry
        else:
            self.backup_entry_table.entries[entry_idx] = entry

        self.save_entry_tables()
        print(f"Tập tin '{filename}' thêm vào thành công.")

    def export_file(self, filename: str, export_path: str = None, password: Optional[str] = None):
        entry_info = self.find_entry(filename)
        if not entry_info:
            raise Exception("Tập tin không tồn tại.")
        table_type, entry_idx, entry = entry_info

        if entry.password_hash != b'':
            if not password:
                raise Exception("Cần mật khẩu để xuất file này.")
            password_hashed = hash_sha256(password)
            if password_hashed != entry.password_hash:
                raise Exception("Mật khẩu không đúng.")
            aes_key = derive_aes_key(password_hashed)
        else:
            aes_key = None

        # Traverse data blocks to collect data
        encrypted_data = b''
        current_block_index = struct.unpack('>Q', entry.first_block)[0]
        while current_block_index != ALL_ONES_ADDRESS_INT:
            block = self.read_data_block(current_block_index)
            encrypted_data += block.content.rstrip(b'\x00')
            next_block = struct.unpack('>Q', block.next_block)[0]
            if next_block == ALL_ONES_ADDRESS_INT:
                break
            current_block_index = next_block

        encrypted_data = encrypted_data[:entry.encrypted_size]

        if aes_key:
            decrypted_data = decrypt_data(aes_key, encrypted_data)
        else:
            decrypted_data = encrypted_data

        decrypt_data_hashed = hash_md5(decrypted_data)
        if decrypt_data_hashed != entry.md5_hash:
            raise Exception("Kiểm tra toàn vẹn gặp lỗi hoặc giá trị không đúng. Tập tin có thể bị hư hỏng.")

        if not export_path and not entry.root_dir:
            raise Exception("Không có đường dẫn xuất tập tin và đường dẫn tới tệp gốc không được đặt. Xuất tập tin bị hủy bỏ.")
        elif not export_path:
            export_path = entry.root_dir

        with open(export_path, 'wb') as f:
            f.write(decrypted_data)

        # Set the modification time and creation date of the exported file as the original file
        os.utime(export_path, (date_parse(entry.creation_date).timestamp(), date_parse(entry.modification_date).timestamp()))

        print(f"File '{filename}' exported successfully to '{export_path}'.")

    def delete_file(self, filename: str):
        entry_info = self.find_entry(filename)
        if not entry_info:
            raise Exception("File not found.")
        table_type, entry_idx, entry = entry_info

        # Traverse and mark data blocks as deleted
        current_block_index = struct.unpack('>Q', entry.first_block)[0]
        while current_block_index != ALL_ONES_ADDRESS_INT:
            block = self.read_data_block(current_block_index)
            block.status = 0x00  # Mark as deleted
            self.write_data_block(current_block_index, block)
            next_block = struct.unpack('>Q', block.next_block)[0]
            if next_block == ALL_ONES_ADDRESS_INT:
                break
            current_block_index = next_block

        # Update entry status to deleted
        entry.status = 0x00
        if table_type == 'main':
            self.main_entry_table.entries[entry_idx] = entry
        else:
            self.backup_entry_table.entries[entry_idx] = entry

        self.save_entry_tables()
        print(f"Tập tin '{filename}' đã xóa thành công khỏi MyFS.")

    def reset_password(self, filename: str, old_password: str, new_password: str):
        entry_info = self.find_entry(filename)
        if not entry_info:
            raise Exception("File not found.")
        table_type, entry_idx, entry = entry_info

        if entry.password_hash == b'\x00' * 32:
            raise Exception("This file does not have a password set.")

        # Verify old password
        old_password_hashed = hash_sha256(old_password)
        if old_password_hashed != entry.password_hash:
            raise Exception("Mật khẩu cũ không đúng.")

        # Derive old AES key
        old_aes_key = derive_aes_key(old_password_hashed)

        # Derive new AES key
        new_password_hashed = hash_sha256(new_password)
        new_aes_key = derive_aes_key(new_password_hashed)

        # Traverse data blocks to collect encrypted data
        encrypted_data = b''
        current_block_index = struct.unpack('>Q', entry.first_block)[0]
        while current_block_index != ALL_ONES_ADDRESS_INT:
            block = self.read_data_block(current_block_index)
            encrypted_data += block.content.rstrip(b'\x00')
            next_block = struct.unpack('>Q', block.next_block)[0]
            if next_block == ALL_ONES_ADDRESS_INT:
                break
            current_block_index = next_block

        encrypted_data = encrypted_data[:entry.encrypted_size]

        # Decrypt with old key
        decrypted_data = decrypt_data(old_aes_key, encrypted_data)

        # Encrypt with new key
        new_encrypted_data = encrypt_data(new_aes_key, decrypted_data)
        new_encrypted_size = len(new_encrypted_data)

        # Update entry with new password hash and encrypted size
        entry.password_hash = new_password_hashed
        entry.encrypted_size = new_encrypted_size
        entry.modification_date = current_iso8601()

        # Mark existing data blocks as deleted
        current_block_index = struct.unpack('>Q', entry.first_block)[0]
        while current_block_index != ALL_ONES_ADDRESS_INT:
            block = self.read_data_block(current_block_index)
            block.status = 0x00  # Mark as deleted
            self.write_data_block(current_block_index, block)
            next_block = struct.unpack('>Q', block.next_block)[0]
            if next_block == ALL_ONES_ADDRESS_INT:
                break
            current_block_index = next_block

        # Re-add the encrypted data with the new password
        # This process reuses the same entry but allocates new data blocks
        block_size = 4086
        data_chunks = [new_encrypted_data[i:i + block_size] for i in range(0, len(new_encrypted_data), block_size)]

        new_block_indices = []
        for chunk in data_chunks:
            free_block = self.find_free_data_block()
            new_block_indices.append(free_block)
            block_content = chunk.ljust(4087, b'\x00')
            data_block = DataBlock(status=0x01, next_block=ALL_ONES_ADDRESS, content=block_content)
            self.write_data_block(free_block, data_block)

        # Link the new data blocks
        for i in range(len(new_block_indices) - 1):
            current_block = self.read_data_block(new_block_indices[i])
            next_block_address = struct.pack('>Q', new_block_indices[i + 1])
            current_block.next_block = next_block_address
            self.write_data_block(new_block_indices[i], current_block)

        # Last block points to all ones
        last_block = self.read_data_block(new_block_indices[-1])
        last_block.next_block = ALL_ONES_ADDRESS
        self.write_data_block(new_block_indices[-1], last_block)

        # Update entry with new first block address
        entry.first_block = struct.pack('>Q', new_block_indices[0])

        # Save the updated entry
        if table_type == 'main':
            self.main_entry_table.entries[entry_idx] = entry
        else:
            self.backup_entry_table.entries[entry_idx] = entry

        self.save_entry_tables()
        print(f"Mật khẩu cho tập tin '{filename}' đã được đổi thành công.")

if __name__ == "__main__":
    fs = FileSystem("my_volume.ivf", metadata_path="meta.ivf")

    # Adding a file
    try:
        fs.add_file("source_file.txt", "my_file.txt", password="securepassword")
    except Exception as e:
        print(f"Error adding file: {e}")

    # Listing files
    try:
        files = fs.list_files()
        print("List of files:")
        for file in files:
            print(f"Filename: {file.filename}, Original Size: {file.original_size} bytes, Encrypted Size: {file.encrypted_size} bytes, Original Size: {file.original_size}, Creation Date: {file.creation_date}")
    except Exception as e:
        print(f"Error listing files: {e}")

    # Exporting a file
    try:
        fs.export_file("my_file.txt", "exported_file.txt", password="securepassword")
    except Exception as e:
        print(f"Error exporting file: {e}")

    # Resetting password
    try:
        fs.reset_password("my_file.txt", old_password="securepassword", new_password="newsecurepassword")
    except Exception as e:
        print(f"Error resetting password: {e}")


    is_metadata_match = fs.compare_metadata()
    print(f"Metadata match: {is_metadata_match}")

    fs.change_access_password("", "newnewsecurepassword")
    print(f"Password match: {fs.is_password_match('newnewsecurepassword')}")

    fs.change_access_password("newnewsecurepassword", "newsecurepassword")
    print(f"Password match: {fs.is_password_match('newnewsecurepassword')}")

    # Deleting a file
    try:
        fs.delete_file("my_file.txt")
    except Exception as e:
        print(f"Error deleting file: {e}")