buildcode="""
function Get-ExternalIP(){
	$extern_ip_mask = @()
	while ($response.IPAddress -eq $null){
		$response = Resolve-DnsName -Name myip.opendns.com -Server resolver1.opendns.com
		Start-Sleep -s 1

	}
	$octet1, $octet2, $octet3, $octet4 = $response.IPAddress.Split(".")
	$extern_ip_mask += $response.IPAddress
	$extern_ip_mask += [string]$octet1 + "." + [string]$octet2 + "." + [string]$octet3 + ".0"
	$extern_ip_mask += [string]$octet1 + "." + [string]$octet2 + ".0.0"
	$extern_ip_mask += [string]$octet1 + ".0.0.0"
	return $extern_ip_mask
}
	
"""

callcode="""
	$key_combos += ,(Get-ExternalIP)
"""