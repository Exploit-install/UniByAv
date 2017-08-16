# UniByAv
UniByAv is a simple obfuscator that take raw shellcode and generate executable that are Anti-Virus friendly.

The obfuscation routine is purely writtend in assembly to remain pretty short and efficient. In a nutshell the application generate a 32 bits xor key and brute force the key at run time then perform the decryption of the actually shellcode.

I'm going to update the code over the time to also support some of the evasion technique that I was using.

# Usage
```
$ python UniByAv4.1.py shellcode test.exe /cygdrive/c/Program\ Files\ \(x86\)/CodeBlocks/MinGW/bin/ 4
UniByAv4.1 Shellcode encoder tool / Mr.Un1k0d3r RingZer0 Team 2014
Currently running under (cygwin) LINUX switch is set to 0
Self decoding payload written in assembly

[+]     Generating xoring key
[+]     Xoring key is set to 0x150014cc
[+]     Original shellcode size is (13) bytes adding (3) bytes to align it
[+]     Magic key is set to \x49\x62\x4d\x6b
[+]     Payload + decoder shellcode length is now (134) bytes
[+]     Generating the final c file
[+]     Generating random charset array for kernel32 and SetProcessDEPPolicy
[+]     Generating int array for "kernel32.dll". Array size is: 12
[+]     Generating int array for "SetProcessDEPPolicy". Array size is: 19
[+]     Compiling the final executable
[+]     /cygdrive/c/Users/Mr.Un1k0d3r/Desktop/output/test.exe has been created
[+]     Generation completed
```

![image](https://user-images.githubusercontent.com/4238766/29378637-d3e9c4e8-828d-11e7-9ce2-83e18a1ee931.png)

# Evasion technique 

Predefined configuation file can be found in configs folder.

###### process
Check if a specific process is running. If it does not run the binary exit without running the payload.

###### time
Check if SleepEx was hooked. If it return bogus information it exit without running the payload.

###### domain
Check if the current user is part of the defined domain. If it is not the case it exit without running the payload.

# Requirement
On Windows
```
python
MinGW (shipped with CodeBlocks)
```

On Linux
```
python
wine
MinGW
```

# Credit
Mr.Un1k0d3r RingZer0 Team
