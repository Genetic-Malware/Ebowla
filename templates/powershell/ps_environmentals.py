buildcode="""
function Get-theEnvironmentals($env_vars){
	$env_string = ""
	foreach ($env_var in $env_vars){
		$env_string +=[Environment]::GetEnvironmentVariable($env_var)
	}
	return $env_string
}


"""

callcode="""
	$key_combos += ,(Get-theEnvironmentals $env_vars)
"""