# rinject
Loads executable payload into target process memory and executes. I built this project to learn about process injection techniques. Only supports 32bit PE.

rinject.cpp - The process injector.  
target.cpp - Simple dummy process to inject into.  
payload.cpp - The payload to inject.  

1) rinject.exe loads payload.exe into target.exe:  
    1) payload PE is mapped into memory at faddr.  
	2) memory is allocated for payload in target process (imgVA). 
	3) PE headers are used to load PE into local buffer buff.  
	    a) DOS stub and optional headers mapped into buff.  
		b) sections mapped to appropriate VA's in buff.  
		c) imgVA var in data section of payload (now in buff) is replaced with actual imgVA.  
		d) fixes IAT of kernal32.  
		e) offsets from relocation table are adjusted to match new imagebase (imgVA).  
	4) buff is copied into target process address space (imgVA).  
2) rinject.exe executes injected payload.exe using remote thread.
3) Payload rebuilds import table to support non-standard and non-loaded libraries.

# Installation
Using vs command line compiler with vcvars32.bat:
```cd bin
cl ..\src\rinject.cpp
cl ..\src\payload.cpp
cl ..\src\target.cpp
```
# Usage
```
cd bin
rinject.exe [name of target process] [path to payload.exe]
```
# Test Rinject
```
cd bin
.\rinject.exe target.exe .\payload.exe 
```