buildcode="""
function Get-SystemTime(){
	$time_mask = @()
	$the_time = Get-Date
	$time_mask += [string]$the_time.Year + "0000"
	$time_mask += [string]$the_time.Year + [string]$the_time.Month + "00"
	$time_mask += [string]$the_time.Year + [string]$the_time.Month + [string]$the_time.Day
	return $time_mask
}

"""

callcode="""
	$key_combos += ,(Get-SystemTime)
"""