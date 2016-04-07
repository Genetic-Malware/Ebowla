buildcode="""
# Add this and below if there is a path variable
def walk_native64(lookup_table, payload_hash, minus_bytes, key_combos, key_iterations):
    for root, dirs, files in os.walk(r"c:\Windows\sysnative\", topdown=True):
        temp_list = []
        for name in dirs:
            print name
            try:
                temp_list=key_combos[:]
                temp_list.append(os.path.join(root, name).lower())
                print 'temp_list', temp_list
                result = build_code(lookup_table, payload_hash, minus_bytes, temp_list, key_iterations)
                if result.run() is True:
                    return True
            except IOError:
                continue
        for name in files:
            #print(os.path.join(root, name))
            try:
                temp_list=key_combos[:]
                temp_list.append(os.path.join(root, name).lower())
                result = build_code(lookup_table, payload_hash, minus_bytes, temp_list, key_iterations)
                if result.run() is True:
                    return True
            except IOError:
                continue

def walk_os(lookup_table, payload_hash, minus_bytes, scan_dir, key_combos, key_iterations):
    # make method for 
    # need to add sysnative checks
    sys_paths = [r"c:\", r"c:\windows\", r"c:\windows\system32\"]
    print 'key_combos', key_combos
    import platform
    if '32' in platform.architecture()[0] and scan_dir.lower() in sys_paths:
        # 32 bit use sysnative to check x64 c:\Windows\sysnative
        #print "scanning sysnative"
        walk_native64(lookup_table, payload_hash, minus_bytes, key_combos, key_iterations)

    for root, dirs, files in os.walk(scan_dir, topdown=True):
        temp_list = []
        for name in dirs:
            print name
            try:
                temp_list=key_combos[:]
                temp_list.append(os.path.join(root, name).lower())
                print 'temp_list', temp_list
                result = build_code(lookup_table, payload_hash, minus_bytes, temp_list, key_iterations)
                if result.run() is True:
                    return True
            except IOError:
                continue
        for name in files:
            #print(os.path.join(root, name))
            try:
                temp_list=key_combos[:]
                temp_list.append(os.path.join(root, name).lower())
                print 'temp_list', temp_list
                result = build_code(lookup_table, payload_hash, minus_bytes, temp_list, key_iterations)
                if result.run() is True:
                    return True
            except IOError:
                continue
"""

callcode="""
    if scan_dir.endswith("%") and scan_dir.startswith("%"):
        print("[*] Env variable used for directory:", scan_dir)
        # over write scan_dir variable
        # strip staring and ending % from env var
        scan_dir = os.getenv(scan_dir[1:-1])
        print("[*] Scanning path:", scan_dir)
        if scan_dir == None:
            sys.exit(0)

    walk_os(lookup_table, payload_hash, minus_bytes, scan_dir, key_combos, key_iterations)
"""