# RansomLord (NG) Anti-Ransomware exploit tool.
Proof-of-concept tool that automates the creation of PE files, used to exploit ransomware pre-encryption. <br>

Updated version NG: https://github.com/malvuln/RansomLord/releases/tag/NG

Lang: C <br>
SHA256: fcb259471a4a7afa938e3aa119bdff25620ae83f128c8c7d39266f410a7ec9aa

Video PoC (old v2): <br >
https://www.youtube.com/watch?v=_Ho0bpeJWqI

RansomLordNG generated PE files are saved to disk in the x32 or x64 directorys where the program is run from. <br>
NG version exploit DLL MD5: <br>
x32: 36bf065dd7ada7b51c0a4a590f515d27 <br>
x64: b2cd933fe13e39ed2b3990c1ce675ea7 <br>

Goal is to exploit vulnerabilities inherent in certain strains of ransomware by deploying exploits to defend the network!<br> <br>
The DLLs may also provide additonal coverage against generic and info stealer malwares.<br>
RansomLord and its exported DLLs are NOT malicious see -s flag for security info.<br>

[Malvuln history] <br>
  May of 2022, I publicly disclosed a novel strategy to successfully defeat ransomware
  Using a well known attacker technique (DLL Hijack) to terminate Malware pre-encryption
  The first Malware to be successfully exploited was from Lockbit group MVID-2022-0572
  Followed by Conti, REvil, BlackBasta and CryptoLocker proving many are vulnerable

[NG Version] <br>
  Next gen version dumps process memory of the targeted Malware prior to termination <br>
  The process memory dump file MalDump.dmp varies in size and can be 50 MB plus <br>
  RansomLord now intercepts and terminates ransomware from 54 different threat groups <br>
  Adding GPCode, DarkRace, Snocry, Hydra and Sage to the ever growing victim list <br>

[DLL Exploit Generation] <br>
  The -g flag lists ransomware to exploit based on the selected ransomware group
  It will output a 32 or 64-bit DLL appropriately named based on the family selected

[Strategy] <br>
  The created DLL exploit file logic is simple, we check if the current directory
  is C:\Windows\System32. If not we grab our own process ID (PID) and terminate
  ourselves and the Malware pre-encryption as we now control code execution flow

[MalDump] <br>
  The -d flag creates a custom Windows registry key, that exploit DLLs will check
  to perform a process memory dump of Malware based on whether enabled=1 or disabled=0
  Leveraging code execution vulnerabilities to dump cleartext strings etc from process
  memory to disk, may be useful as we may avoid PE unpacking, anti-debugging techniques
  or relying on fully executing the Malware

[Event Log IOC] <br>
  The -e flag sets up a custom Windows Event source in the Windows registry
  Events are written to 'Windows Logs\Application' as 'RansomLord' event ID 1
  Malware name, SHA256 hash and process path are included in the general information
  Due to potential errors, at times only the Malware path and name may get recorded

[Sigma Rule Detection] <br>
  The -r flag saves the required Sigma rule RansomLord_Sigma.txt to disk
  The sigma rule is used along with the -e flag to enable endpoint detection capability
  Useful for IOC and alerting on potential Malware activity and may also help track down
  false positives E.g. programs run by end users that get terminated but are not malicious

[DLL Map] <br>
  The -m flag displays ransomware groups, DLL required and architecture x32 or 64-bit

[Trophy Room] <br>
  The -t flag lists old ransomware advisorys from 2022 with Malware vulnerability id

[Warning] <br>
  There is also the chance a vulnerable but legit program may be prevented from starting
  If ran from the same location exploit DLLs exists and the program is vulnerable to hijack
  Therefore, monitoring for RansomLord generated IOC alerts are helpful in such scenarios
  RansomLord proved a very high success rate within a virtual machine testing environment
  However, non vulnerable variants, OS version, environment or location etc. may ruin success

[Test Environment] <br>
  Primary testing was done in a Windows 10 Virtual Machine and Win-7 embedded OS Thin-client

[About] <br>
  The -a flag general information, contact and disclaimer
  By using this software and or its DLL files, you accept all risk and the full disclaimer
  By John Page (aka malvuln) Copyright (c) 2024 - malvuln13@gmail.com

<br>
References: <br>
https://web.archive.org/web/20220601204439/https://www.bleepingcomputer.com/news/security/conti-revil-lockbit-ransomware-bugs-exploited-to-block-encryption/ <br><br>
https://web.archive.org/web/20220504180432/https://www.securityweek.com/vulnerabilities-allow-hijacking-most-ransomware-prevent-file-encryption/ <br><br>

![RansomLordNG_1](https://github.com/user-attachments/assets/461d276f-cd42-4d2d-9643-bb3c8647e404)
![RansomLordNG_2](https://github.com/user-attachments/assets/4da0ec42-f98b-4481-ab86-e168e99e2954)
![RansomLordNG_victims](https://github.com/user-attachments/assets/e6921140-a834-4e28-9770-6ffb134345e6)




 
