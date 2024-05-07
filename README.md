# RansomLord Anti-Ransomware exploit tool.
Proof-of-concept tool that automates the creation of PE files, used to exploit Ransomware pre-encryption. <br>

Updated v3: https://github.com/malvuln/RansomLord/releases/tag/v3

Lang: C
SHA256: 83f56d14671b912a9a68da2cd37607cac3e5b31560a6e30380e3c6bd093560f5

Video PoC (old v2): <br >
https://www.youtube.com/watch?v=_Ho0bpeJWqI

RansomLord generated PE files are saved to disk in the x32 or x64 directorys where the program is run from. <br>

Goal is to exploit vulnerabilities inherent in certain strains of Ransomware by deploying exploits that defend the network!<br> 
The DLLs may also provide additonal coverage against generic and info stealer malwares.<br>
RansomLord and its exported DLLs are NOT malicious see -s flag for security info.<br>

[Malvuln history] <br>
 In May 2022, I publicly disclosed a novel strategy to successfully defeat Ransomware.
 Using a well known attacker technique (DLL hijack) to terminate malware pre-encryption.
 The first malware to be successfully exploited was from the group Lockbit MVID-2022-0572.
 Followed by Conti, REvil, BlackBasta and CryptoLocker proving many are vulnerable.
 RansomLord v1 intercepts and terminates malware tested from 33 different threat groups.
 Clop, Play, Royal, BlackCat (alphv), Yanluowang, DarkSide, Nokoyawa etc...

[V3 update and features] <br>
RansomLord now intercepts and terminates ransomware tested from 49 different threat groups. <br>
Adding StopCrypt, RisePro, RuRansom, MoneyMessage, CryptoFortress and Onyx to the victim list.<br>
Windows event log feature -e flag will now log the SHA256 hash of the ransonmware.<br>

[Generating exploits] <br>
 The -g flag lists Ransomware to exploit based on the selected Ransomware group.
 It will output a 32 or 64-bit DLL appropriately named based on the family selected.

[Strategy]  <br> 
 The created DLL exploit file logic is simple, we check if the current directory
 is C:\Windows\System32. If not we grab our own process ID (PID) and terminate
 ourselves and the Malware pre-encryption as we now control code execution flow.

[Event Log IOC] <br> 
 The -e flag sets up a custom Windows Event source in the Windows registry.
 Events are written to 'Windows Logs\Application' as 'RansomLord' event ID 1
 Malware name and full process path are also included in the general information.

[DLL Map] <br>
 The -m flag displays Ransomware groups, DLL required and architecture x32 or 64-bit.

[Trophy Room] <br>
 The -t flag lists old Ransomware advisorys from 2022 with Malware vulnerability id.

[Warning] <br>
 The Ransomware familys and or samples listed do NOT guarantee a successful outcome.
 Many factors can ruin success: different variants, OS versions, Malware location etc.
 Therefore, proceed with caution as mileage may vary, good luck.

[Test Environment] <br>
 Testing was done in a Windows 10 Virtual Machine and Win-7 embedded OS Thin-client.

[About] <br>
 The -a flag general information, contact and disclaimer.
 Using this program and or its DLL files, you accept all risk and the full disclaimer.
 By John Page (aka Malvuln) Copyright (c) 2023
 
 <br><br><br>
 
![RansomLord_v3_Victims](https://github.com/malvuln/RansomLord/assets/75002643/30006d20-8dc4-45aa-ae52-7bacf38e9dde)



