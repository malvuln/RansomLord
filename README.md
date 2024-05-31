# RansomLord Anti-Ransomware exploit tool.
Proof-of-concept tool that automates the creation of PE files, used to exploit ransomware pre-encryption. <br>

Updated v3.1: https://github.com/malvuln/RansomLord/releases/tag/v3

Lang: C <br>
SHA256: 647494bda466e645768d6f7d1cd051097aee319f88018d1a80547d8d538c98db

Video PoC (old v2): <br >
https://www.youtube.com/watch?v=_Ho0bpeJWqI

RansomLord generated PE files are saved to disk in the x32 or x64 directorys where the program is run from. <br>

Goal is to exploit vulnerabilities inherent in certain strains of ransomware by deploying exploits to defend the network!<br> <br>
The DLLs may also provide additonal coverage against generic and info stealer malwares.<br>
RansomLord and its exported DLLs are NOT malicious see -s flag for security info.<br>

[Malvuln history] <br>
 In May 2022, I publicly disclosed a novel strategy to successfully defeat ransomware.
 Using a well known attacker technique (DLL hijack) to terminate malware pre-encryption.
 The first malware to be successfully exploited was from the group Lockbit MVID-2022-0572.
 Followed by Conti, REvil, BlackBasta and CryptoLocker proving many are vulnerable.
 RansomLord v1 intercepts and terminates malware tested from 33 different threat groups.
 Clop, Play, Royal, BlackCat (alphv), Yanluowang, DarkSide, Nokoyawa etc...

[v3.1 Update] <br>
RansomLord now intercepts and terminates ransomware tested from 49 different threat groups. <br>
Adding StopCrypt, RisePro, RuRansom, MoneyMessage, CryptoFortress and Onyx to the victim list. <br>
Windows event log feature -e flag will attempt to log the SHA256 hash of the ransomware. <br>
Added -r flag to output a Sigma rule for detecting RansomLord activity using Windows event log. <br>

[Generating exploits] <br>
 The -g flag lists ransomware to exploit based on the selected ransomware group.
 It will output a 32 or 64-bit DLL appropriately named based on the family selected.

[Strategy]  <br> 
 The created DLL exploit file logic is simple, we check if the current directory
 is C:\Windows\System32. If not we grab our own process ID (PID) and terminate
 ourselves and the Malware pre-encryption as we now control code execution flow.

[Event Log IOC] <br> 
 The -e flag sets up a custom Windows Event source in the Windows registry.
 Events are written to 'Windows Logs\Application' as 'RansomLord' event ID 1
 Malware name and full process path are also included in the general information.
 Windows event log feature -e flag will now log the SHA256 hash of the ransomware.

[DLL Map] <br>
 The -m flag displays ransomware groups, DLL required and architecture x32 or 64-bit.

[Trophy Room] <br>
 The -t flag lists old ransomware advisorys from 2022 with Malware vulnerability id.

[Warning] <br>
 The ransomware familys and or samples listed do NOT guarantee a successful outcome.
 Many factors can ruin success: different variants, OS versions, Malware location etc.
 Therefore, proceed with caution as mileage may vary, good luck.

[Test Environment] <br>
 Testing was done in a Windows 10 Virtual Machine and Win-7 embedded OS Thin-client.

[About] <br>
 The -a flag general information, contact and disclaimer.
 Using this program and or its DLL files, you accept all risk and the full disclaimer.
 By John Page (aka Malvuln) Copyright (c) 2023
 
<br>
References: <br>
https://web.archive.org/web/20220601204439/https://www.bleepingcomputer.com/news/security/conti-revil-lockbit-ransomware-bugs-exploited-to-block-encryption/ <br><br>
https://web.archive.org/web/20220504180432/https://www.securityweek.com/vulnerabilities-allow-hijacking-most-ransomware-prevent-file-encryption/ <br><br>
 
![RansomLord_v3_Victims](https://github.com/malvuln/RansomLord/assets/75002643/30006d20-8dc4-45aa-ae52-7bacf38e9dde)



