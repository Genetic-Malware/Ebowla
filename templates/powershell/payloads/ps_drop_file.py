loader="""
$file_drop_output = "file_drop_output" + "{0}"
# check for string vs byte most likely will always be byte
if ($payload.GetType().Name -eq "String"){{
	"String"
	$payload | Out-File $file_drop_output
}} else {{
	[io.file]::WriteAllBytes($file_drop_output, $payload)	
}}

"""