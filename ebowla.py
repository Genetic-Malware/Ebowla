#!/usr/bin/env python2

import sys

try:
    from configobj import ConfigObj
except:
    print "[x] Error - You need to have configobj installed to use this tool"
    exit(-1)
from encryption import otp_full
from encryption import otp_key
from encryption import env


class make_payload():

    def __init__(self, payload, config):
        self.payload = payload
        self.lookup_table = ''
        self.inital_iteration = 0
        self.config = ConfigObj(config)
        #print self.payload.encode('hex')
        self.parse_config()
        self.main()

    def parse_config(self):
        for item in self.config:
            #print item, ":", self.config[item]
            pass

    def main(self):
        if self.config['Overall']['Encryption_Type'].lower() == 'otp' and self.config['otp_settings']['otp_type'] == 'full':
            print '[*] Using full file OTP'
            pad = self.config['otp_settings']['pad']
            otp_type = self.config['otp_settings']['otp_type']
            byte_width = self.config['otp_settings']['byte_width']
            payload_type = self.config['Overall']['payload_type'].lower()
            minus_bytes = int(self.config['Overall']['minus_bytes'])
            scan_dir = self.config['otp_settings']['scan_dir'].rstrip("\\")
            output_type = self.config['Overall']['output_type'].lower() 
            pad_max = self.config['otp_settings']['pad_max']
            clean_output = self.config['Overall'].as_bool('clean_output')
            otp_full.otp_full(pad, self.payload, byte_width, otp_type, payload_type, minus_bytes, scan_dir, output_type, pad_max,clean_output)
        
        elif self.config['Overall']['Encryption_Type'].lower() == 'otp' and self.config['otp_settings']['otp_type'].lower() == 'key':
            print '[*] Using key based OTP'
            pad = self.config['otp_settings']['pad']
            otp_type = self.config['otp_settings']['otp_type']
            payload_type = self.config['Overall']['payload_type'].lower()
            minus_bytes = int(self.config['Overall']['minus_bytes'])
            scan_dir = self.config['otp_settings']['scan_dir'].rstrip("\\")
            output_type = self.config['Overall']['output_type'].lower()
            key_iterations = self.config['Overall']['key_iterations']
            pad_max = self.config['otp_settings']['pad_max']
            clean_output = self.config['Overall'].as_bool('clean_output')
            otp_key.otp_key(pad, self.payload, otp_type, payload_type, minus_bytes, scan_dir, output_type, key_iterations, pad_max, clean_output)
        
        elif self.config['Overall']['Encryption_Type'].lower() == 'env':
            print '[*] Using Symmetric encryption'
            key_config = self.config['symmetric_settings_win']
            payload_type = self.config['Overall']['payload_type'].lower()
            minus_bytes = int(self.config['Overall']['minus_bytes'])
            output_type = self.config['Overall']['output_type'].lower()
            key_iterations = self.config['Overall']['key_iterations']
            clean_output = self.config['Overall'].as_bool('clean_output')
            env.env_encrypt(key_config, self.payload, payload_type, minus_bytes, output_type, key_iterations, clean_output)



if __name__ == "__main__":
    if len(sys.argv) < 3:
        print "Usage:", sys.argv[0], "input_file_to_encode", "config"
        exit(-1)
    
    test = make_payload(sys.argv[1], sys.argv[2])
    
