# RansomLord Anti-Ransomware exploit tool.
RansomLord is a proof-of-concept tool that automates the creation of PE files, used to compromise Ransomware pre-encryption. <br>

Lang: C

SHA256: b0dfa2377d7100949de276660118bbf21fa4e56a4a196db15f5fb344a5da33ee

Video PoC: <br >
https://www.youtube.com/watch?v=_Ho0bpeJWqI

RansomLord generated PE files are saved to disk in the x32 or x64 directorys where the program is run from. <br>


Goal is to exploit code execution flaws inherent in certain strains of Ransomware. <br>  

[Victim List] <br>
[0] Lockbit <br>
[1] Yanluowang <br>
[2] Conti <br>
[3] REvil <br> 
[4] BlackMatter <br>
[5] WannaCry <br> 
[6] LokiLocker <br> 
[7] Ryuk.A <br> 
[8] Hive v5.1 <br> 
[9] BlueSky <br> 
[10] Haron <br> 
[11] Thanos <br> 
[12] AvosLocker <br> 
[13] AtomSilo <br> 
[14] Cryakl <br> 
[15] Meow <br> 
[16] BabukLocker <br> 
[17] Darkside <br> 
[18] CTBLocker <br> 
[19] Cerber <br> 
[20] Cryptowall <br> 
[21] Alphaware <br> 
[22] Clop <br> 
[23] Play <br> 
[24] Nokoyawa <br> 
[25] BlackCat(ALPHV) <br> 
[26] Royal <br> 
[27] Chaos <br> 
[28] Crytox <br> 
[29] LockerGoga <br> 
[30] Rook <br> 
[31] HelloKitty <br> 
[32] Curator <br> 

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
 
![ransomlord2](https://github.com/malvuln/RansomLord/assets/75002643/f82c790d-f540-455c-ac64-d91d3bb93919)

![ransomlord](https://github.com/malvuln/RansomLord/assets/75002643/4d9ebabd-3bd0-454d-b9bf-00d075fe0ad9)

