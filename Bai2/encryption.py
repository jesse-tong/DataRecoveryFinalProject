from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

MAX_FILENAME_LENGTH = 32

def pad_filename(name: str) -> bytes:
    name_bytes = name.encode('ascii')[:MAX_FILENAME_LENGTH]
    return name_bytes.ljust(MAX_FILENAME_LENGTH, b'\x00')

def hash_sha256(password: str) -> bytes:
    hash_obj = SHA256.new(data=password.encode('utf-8'))
    return hash_obj.digest()

def hash_sha256_bytes(data: bytes) -> bytes:
    hash_obj = SHA256.new(data=data)
    return hash_obj.digest()

def hash_md5(data: bytes) -> bytes:
    hash_obj = MD5.new(data=data)
    return hash_obj.digest()

def derive_aes_key(password_hash: bytes) -> bytes:
    # Derive a 32-byte AES key from the SHA256 hash using PBKDF2
    salt = b'IVOLFILESYSTEM'  # In a real system, use a unique salt per password and store it securely
    key = PBKDF2(password_hash, salt, dkLen=32, count=10)
    return key

def encrypt_data(aes_key: bytes, data: bytes) -> bytes:
    # AES encryption in ECB mode
    cipher = AES.new(aes_key, AES.MODE_ECB)
    # PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext

def decrypt_data(aes_key: bytes, data: bytes) -> bytes:
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_data = cipher.decrypt(data)
    # Remove PKCS7 padding
    pad_len = padded_data[-1]
    return padded_data[:-pad_len]