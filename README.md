# Detect-Hooks
Detect-Hooks is a proof of concept Beacon Object File (BOF) that attempts to detect userland API hooks in place by AV/EDR. The BOF will return a list of detected API hooks or let the operator know no hooks were detected. This can be useful knowledge to have before performing certain post-exploitation actions. This BOF is only a slight modificaiton of the work already done by @spotheplanet which can be found on their ired.team blog below.

# Subject References

This tool wouldn't exist without being able to piggyback off some really great research, tools, and code already published by members of the security community. So thank you. Lastly, if you feel anyone has been left out below, please let me know and I will be sure to get them added.

- Detecting Hooked Syscalls - (by [@spotheplanet](https://twitter.com/spotheplanet)) - [here](https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions) - Detecting Hooks Logic -> The Real MVP

## Getting Started

1. Copy the Detect-Hooks folder with all of its contents to a system you plan to connect with via the Cobalt Strike GUI application.
2. Load in the detect-hooks.cna Aggressor script
3. Run detect-hooks

### Build Your Own

Run the below command inside the src directory via x64 Native Tools Command Prompt for VS 2019
```
cl.exe /c detect-hooks.c /GS- /Fodetect-hooksx64.o
```

### Use Case

> *Detect hooks in AV/EDR*

### Syntax

```
beacon> detect-hooks
[*] Running detect-hooks by (@anthemtotheego)
[+] host called home, sent: 1964 bytes
[+] received output:

NtCreateFile
NtCreateKey
NtCreateUserProcess
NtDeleteFile
NtDeleteKey
NtDeleteValueKey
NtMapViewOfSection
NtOpenFile
NtOpenKey
NtOpenKeyEx
NtRenameKey
NtSetInformationFile
NtSetValueKey
NtTerminateProcess
NtTerminateThread
ZwCreateFile
ZwCreateKey
ZwCreateUserProcess
ZwDeleteFile
ZwDeleteKey
ZwDeleteValueKey
ZwMapViewOfSection
ZwOpenFile
ZwOpenKey
ZwOpenKeyEx
ZwRenameKey
ZwSetInformationFile
ZwSetValueKey
ZwTerminateProcess
ZwTerminateThread
```

## Caveats

1. x64 only currently
