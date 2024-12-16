import os
import platform
import subprocess
import struct
from encryption import *

class PlatformMetadata:
    def __init__(self, metadata_path=None, myFS_password_hash: bytes = b'\x00'*32):
        self.platform = platform.system()
        self.arch = platform.architecture()[0]
        self.release = platform.release()
        self.machine = platform.machine()
        self.processor = platform.processor()
        self.myFS_password_hash = myFS_password_hash
        self.metadata_path = metadata_path
        
    
    def __eq__(self, other):
        return (self.platform == other.platform 
                and self.arch == other.arch 
                and self.release == other.release 
                and self.machine == other.machine 
                and self.processor == other.processor)
    
    #Lưu thông tin metadata vào file
    def pack(self) -> bytes:
        packed = self.platform.encode('utf-8').ljust(16, b'\0')
        packed += self.arch.encode('utf-8').ljust(16, b'\0')
        packed += self.release.encode('utf-8').ljust(16, b'\0')
        packed += self.machine.encode('utf-8').ljust(16, b'\0')
        packed += self.processor.encode('utf-8').ljust(64, b'\0')
        packed += self.myFS_password_hash.ljust(32, b'\0')
        return packed
    
    def to_dict(self) -> dict:
        return {
            'platform': self.platform,
            'arch': self.arch,
            'release': self.release,
            'machine': self.machine,
            'processor': self.processor,
            'myFS_password_hash': self.myFS_password_hash.hex()
        }

    @staticmethod
    def unpack(data: bytes):
        platform = data[:16].rstrip(b'\x00').decode('utf-8')
        arch = data[16:32].rstrip(b'\x00').decode('utf-8')
        release = data[32:48].rstrip(b'\x00').decode('utf-8')
        machine = data[48:64].rstrip(b'\x00').decode('utf-8')
        processor = data[64:128].rstrip(b'\x00').decode('utf-8')
        myFS_password_hash = data[128:160].rstrip(b'\x00')
        metadata = PlatformMetadata()
        metadata.platform = platform
        metadata.arch = arch
        metadata.release = release
        metadata.machine = machine
        metadata.processor = processor
        metadata.myFS_password_hash = myFS_password_hash
        return metadata

    def write_metadata(self):
        with open(self.metadata_path, 'wb') as f:
            f.write(self.pack())

    def write_metadata_encrypted(self, key):
        metadata = self.pack()
        encrypted_metadata = encrypt_data(key, metadata)
        with open(self.metadata_path, 'wb') as f:
            f.write(encrypted_metadata)
    