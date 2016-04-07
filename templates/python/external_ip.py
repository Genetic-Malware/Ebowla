'''
create a mask
if external ip is 12.12.12.1
mask = ['12.12.12.1', '12.12.12.0', '12.12.0.0', '12.0.0.0']

'''

buildcode="""
def get_external_ip():
    import subprocess
    extern_ip_mask = []
    temp_ip = ''
    try:
        output = subprocess.Popen(["nslookup","myip.opendns.com", "resolver1.opendns.com"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        resp = output.stdout.read().split("\\n")
    except:
        return extern_ip_mask
    if 'UnKnown' in resp or 'timed out' in resp or 'not found' in resp:
        return extern_ip_mask
    for item in resp:
        if 'Address' in item:
            print("[*] Address:", item)
            temp_ip = item.strip().split("  ") # two spaces for windows
            temp_ip_l = item.strip().split(":") # one colon for osx
    try: 
        extern_ip = temp_ip_l[5].strip()
    except:
        extern_ip = temp_ip[1].strip()

    print("[*] Extern_ip", extern_ip)
    octet0, octet1, octet2, octet3 = extern_ip.split(".")
    extern_ip_mask.append(extern_ip)
    extern_ip_mask.append(octet0 + "." + octet1 + "." + octet2 + ".0")
    extern_ip_mask.append(octet0 + "." + octet1 + ".0.0")
    extern_ip_mask.append(octet0 + ".0.0.0")
    return extern_ip_mask
"""

callcode="""
    key_combos.append(get_external_ip())
"""