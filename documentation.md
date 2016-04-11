# About

This is a framework for building environmental keyed payloads.  

It's not necessarily user friendly, if you get your target parameters wrong,
it will NOT work as desired. *That's the point.*



## Setting up your environment

We decided on kali linux as our distro because everything worked together nicely.

You'll need to be able to cross compile the go and python output (which ends up in output).

### python

Install wine and python2.7, pyinstaller, pycrypto

If you want to be lazy you could just do this (all python/wine dependencies will be installed):
  
```  
  apt-get install veil-evasion   # avlol
  
```

### golang

```
# install golang from site

 Follow these steps to set up golang (Download, ENV Vars, etc):
 https://www.digitalocean.com/community/tutorials/how-to-install-go-1-5-3-on-ubuntu-14-04 
 
# build the cross compile env

sudo apt-get install cmake build-essential golang-go-linux-386 golang-go-windows-386 golang-go-windows-amd64 g++-mingw-w64-x86-64 g++-mingw-w64-i686 gcc-mingw-w64-i686 gcc-mingw-w64-x86-64

```

### Edit genetic.config

Read the config.

You have a couple options for encryption:

```
Encryption options:
  - OTP 
      We call this OTP in a general sense, it is more like a digitial book cipher with compression.  
      There is no modular addition and the the pads are NOT generated from a random stream of data.
      - cheers to psifertex making a better correlation for this mode.
  - ENV

Payload Types:
  - See config

OTP options:
  - Full (full pad with lookup table)
  - Key (key pulled from the middle of a file)

ENV options:
  - ENV_VARS: Empty == not used case insensitive
  - PATH: used in key
  - IP_RANGES: A mask (see config)
  - SYSTEM_TIME: A mask (see config)

```

### Run ebowla.py

```
  
  ./ebowla.py payload genetic.config
  Output will be in ./output/

```


### Build scripts

We wrote build scripts to help automate the process.  

We include compiled MemoryModule binaries in our code for x86 and x64 c libraries for golang use.

You are welcome to recompile them yourself. (After all @secretsquirrel wrote backdoor factory).

To do it, navigate to MemoryModule and change the CMakeLists.txt to "i686" or "x86_64" for x86/x64 respectively.

```
  mkdir build686 (or buildx64)
  cd build686 (or buildx64)
  cmake ..
  make

```

*WARNING:* 
*If your output binary is x86(32bit) go you need to compile to x86(32bit) or it will break on execution of payload.*
*Vice versa for x64.*
*Python can execute x86/x64 EXE binaries. If you are want x64 shellcode, you'll need to build your own x64 python* 
*compiling environment.*

```
  # For x86 go payloads
  ./build_x86_go.sh output/something.go payload.exe

  # For x64 go payloads
  ./build_x64_go.sh output/something.go payload.exe

  # For x86 python payloads (that can deploy x64 exes, but not x64 shellcode)
  ./build_python.sh output/something.py payload.exe

```
