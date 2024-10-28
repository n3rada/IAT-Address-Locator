# IAT-Address-Locator
A pykd module to locate specific function addresses within the Windows Import Address Table (IAT) in WinDbg.

Firstly, you will need to load `pykd` inside WinDbg:
```shell
.load pykd
```

Then, you can use-it directly on your targeted module:
```shell
!py C:\Tools\iatloc.py CSFTPAV6 VirtualAlloc
```

![image](https://github.com/user-attachments/assets/d3880894-fa75-426e-b499-e194dcd75601)


