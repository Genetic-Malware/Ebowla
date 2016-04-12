#EBOWLA

```
USAGE: ./ebowla.py exe_dll_shellcode genetic.config

Then: Compile your code
```

### Presentation Resources

Slides:

https://github.com/Genetic-Malware/Ebowla/raw/master/Infiltrate_2016_Morrow_Pitts_Genetic_Malware.pdf

Demos

Demo1:
https://www.youtube.com/watch?v=rRm3O7w5GHg

Demo2:
https://youtu.be/Bu_qDrbX9Zo

Demo3:
https://youtu.be/mlh70LtwmDo


### Contact:
```
  twitter:
    @wired33
    @midnite_runr
    
```

# Documentation

```
  https://github.com/Genetic-Malware/Ebowla/blob/master/documentation.md
  
  Also read genetic.config

```

# Payload Support

|Payload|Python|GO|
|:-----|:-----|:---|
|Reflective DLL| x32 / x64 - None| x32 / x64 - In Memory| 
|DLL| x32 / x64 - None| x32 / x64 - In Memory| 
|EXE| x32 / x64 - On Disk| x32 / x64 - In Memory| 
|Shell Code| x32 / x64 - In Memory| x32 / x64 - In Memory| 
|Python Code| x32 / x64 - In Memory| x32 / x64 - None| 

### Credits

https://github.com/vyrus001/go-mimikatz


### Contributing

If you have a bug report, submit an issue.  Include the OS that you tested everything on, including the server (victim).

Output of commands we like:
```
Windows:
  systeminfo
  
Linux:
  uname -a
  
```

If you want to contribute code please do so.  We ask that you actually submit something substantial, fixing spacing doesn't count, or making our code fully pep8.  

Look at our issues for ideas where you can help: https://github.com/Genetic-Malware/Ebowla/issues

secretsquirrel is on IRC #freenode as midnite_runr


### Contributors

https://github.com/wired33 (wrote most of the golang payload code)

https://github.com/secretsquirrel (wrote the python payload code and most of the encryption code)

