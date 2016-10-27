buildcode="""
function Get-Walk-OS($lookup_table, $payload_hash, $minus_bytes, $temp_list, $key_iterations){
	$dir_parsing += get-childitem $scan_dir -recurse -force -ErrorAction SilentlyContinue | % {$_.FullName}
	$sys_paths = @("c:\", "c:\windows", "c:\windows\system32")
	
	if ([Environment]::Is64BitProcess -eq 0 -And $sys_paths -contains $scan_dir) { # Is a 32bit process
		$dir_parsing += get-childitem "\Windows\sysnative\" -recurse -force -ErrorAction SilentlyContinue | % {$_.FullName}
	} 

	foreach ($some_dir in $dir_parsing){
		$temp_list = $key_combos
		$temp_list += $some_dir.ToLower()
		Get-R-Done $lookup_table $payload_hash $minus_bytes $temp_list $key_iterations
	}
}
"""

callcode="""
	if ($scan_dir.Contains("%")){
		$scan_dir = [Environment]::GetEnvironmentVariable($scan_dir -replace "%")
	}

	Get-Walk-OS $lookup_table $payload_hash $minus_bytes $key_combos $key_iterations
"""