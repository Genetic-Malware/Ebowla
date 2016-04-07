#!/bin/bash

#take argument 1 and build

if [ "$#" -ne 2 ]; then
	echo "Usage: $0 go_x86_script.go output.exe"
	exit
fi

# take the first argument and build an x86 binary from go
filename2=$(basename $2)
sans_extension="${filename2%.*}"

echo [*] Copy Files to tmp for building

cp $1 /tmp/$sans_extension.py

cd /tmp/

echo [*] Building...

wine /root/.wine/drive_c/Python27/python.exe /usr/share/pyinstaller/pyinstaller.py -F -c $sans_extension.py

cd - 1> /dev/null

echo [*] Copy $2 to output

cp /tmp/dist/$2 ./output/$2

echo [*] Cleaning up

rm /tmp/$sans_extension.py

rm /tmp/$sans_extension.spec

rm -rf /tmp/build/

rm -rf /tmp/dist/

echo [*] Done

