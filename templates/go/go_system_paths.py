imports=["fmt",
         "os",
         "path/filepath",
         "runtime",
         "strings"]


buildcode="""
type fileDesc struct {
    isDir  bool
    fPath  string
    sName  string
}

var globalFile []fileDesc
var sysNativeDone = false

//used by the walk function to process directories / files
// This function gets called every file / directory in the path thats being searched
func walk_path(path string, info os.FileInfo, err error) error {
    //temp item holder
    var item fileDesc

    //check for errors
    if err != nil {
        fmt.Println(err)
        return nil
    }

    //determine if directory
    if info.IsDir(){
        item.isDir = true
    } else{
        item.isDir = false
    }

    //set addtional parameters into the struct
    item.fPath = strings.ToLower(path)
    item.sName = strings.ToLower(info.Name())
    globalFile = append(globalFile,item)

    //You would add check code here to call the combine function to test this path
    // plus env vars meet the check
    return nil
}


//called similar to python version
func walk_os(scan_dir string) {
    
    //Handle 32bit in 64bit machine sysnative
    sys_paths := []string{"c:\\\\windows", "c:\\\\windows\\\\system32"}
    //fmt.Println("Arch: "+runtime.GOARCH)
    if strings.Contains(runtime.GOARCH, "386") == true {
        for _, s_path_check := range sys_paths {
            // fmt.Println("Check: "+s_path_check+" vs Check: "+scan_dir)
            if strings.Compare(strings.ToLower(scan_dir), strings.ToLower(s_path_check)) == 0 && !sysNativeDone{
                fmt.Println("[*] Checking sysnative - searching for 64-Bit path")
                sysNativeDone = true
                filepath.Walk("c:\\\\Windows\\\\sysnative", walk_path)
            }
            //else 32bit do nothing special, but continue to walk the given path
        }
    }
    
    _ = filepath.Walk(scan_dir, walk_path)

    fmt.Printf("[*] Total FS Length %v \\n", len(globalFile))
    //fmt.Printf("%v",globalFile)
    
}
"""

callcode="""
    if true == strings.HasPrefix(start_loc, "%") {
        if true == strings.HasSuffix(start_loc, "%") {
            fmt.Println("We have a Env Var for path", start_loc)
            // Strip "%"
            start_loc = start_loc[1:len(start_loc) - 1] 
            // Get env path
            start_loc = os.Getenv(start_loc)
            fmt.Println("Resolv start_loc", start_loc)
            if start_loc == ""{
                os.Exit(0)
            }
        }
    }

    fmt.Println("Len key_combos", len(key_combos), key_combos)
    walk_os(start_loc)
    fmt.Println("", len(globalFile))
    //fmt.Println(globalFile)
    var full_payload []byte
    for _, itr := range globalFile{
        temp_keycombos := make([][]string, len(key_combos))
        copy(temp_keycombos, key_combos)
        fmt.Printf("[*] Testing File: %v",itr.fPath)
        temp_keycombos[i] = []string{itr.fPath}
        fmt.Println(temp_keycombos)
        full_payload = build_code(lookup_table, payload_hash, minus_bytes, temp_keycombos)
        if full_payload != nil{
            fmt.Println("not nil")
            break
        }
    
    }

    if full_payload == nil{
        fmt.Println(":( Exiting")
        os.Exit(0)
    }

    fmt.Println("Len full_payload:", len(full_payload))

"""
