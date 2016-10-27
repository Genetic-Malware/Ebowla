loader="""
$file_drop_output = "file_drop_output" + "{0}"

if ($payload.GetType().Name -eq "String"){{
	$payload | Out-File $file_drop_output
}} else {{
	[io.file]::WriteAllBytes($file_drop_output, $payload)	
}}

"""