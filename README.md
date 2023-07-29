# RansomLord v1
RansomLord is a proof-of-concept Anti-Ransomware exploitation tool that automates the creation of PE files, used to compromise Ransomware pre-encryption. <br>


Lang: C

SHA256: b0dfa2377d7100949de276660118bbf21fa4e56a4a196db15f5fb344a5da33ee

Video PoC: <br >
https://www.youtube.com/watch?v=_Ho0bpeJWqI

RansomLord generated PE files are saved to disk in the x32 or x64 directorys where the program is run from. <br>


Goal is to exploit code execution flaws inherent in certain strains of Ransomware

[Malvuln history] <br>
 In May 2022, I publicly disclosed a novel strategy to successfully defeat Ransomware.
 Using a well known attacker technique (DLL hijack) to terminate malware pre-encryption.
 The first malware to be successfully exploited was from the group Lockbit MVID-2022-0572.
 Followed by Conti, REvil, BlackBasta and CryptoLocker proving many are vulnerable.
 RansomLord v1 intercepts and terminates malware tested from 33 different threat groups.
 Clop, Play, Royal, BlackCat (alphv), Yanluowang, DarkSide, Nokoyawa etc...

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

![ransomlord2](https://github.com/malvuln/RansomLord/assets/75002643/762d63f9-9d22-4c05-984d-75b5a93df561)

![ransomlord](https://github.com/malvuln/RansomLord/assets/75002643/3a308eca-2a0a-48fd-8e2e-8c6e73ad0f28)

