# IAT-Address-Locator
A pykd module to locate specific function addresses within the Windows Import Address Table (IAT) in WinDbg. Useful when you want to bypass DEP and build ROP chain using Win32 API skeleton such as `VirtualAlloc`.

## Usage
To start, ensure `pykd.dll` is located in `C:\Program Files\Windows Kits\10\Debuggers\x86\winext` (path may vary depending on OS and WinDbg version).

Next, load `pykd` inside WinDbg:
```shell
.load pykd
```

Then, you can use the script directly on your target module:
```shell
!py C:\Tools\iatloc.py CSFTPAV6 VirtualAlloc
```

![image](https://github.com/user-attachments/assets/a7f307b8-ac72-4de6-9cf1-50d41428f005)


If the desired function is not loaded inside IAT, the script will give you some offset to play with. For example, searching for `WriteProcessMemory` address:
```shell
!py C:\Tools\iatloc.py CSFTPAV6 WriteProcessMemory
```

![image](https://github.com/user-attachments/assets/a36ba7f8-92cf-400c-a3e7-428eb3a6c25a)


## Disclaimer
This script was created to automate the task of locating specific function addresses in the IAT during my EXP-301 journey. While it worked well for my OSED certification studies, I do not guarantee portability accross up-to-date WinDbg.

