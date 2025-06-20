## RansomLord (NG) v1.0 Anti-Ransomware exploit tool.
Proof-of-concept tool that automates the creation of PE files, used to exploit ransomware pre-encryption. <br>

Updated version NG: https://github.com/malvuln/RansomLord/releases/tag/v1.0

Lang: C <br>
SHA256: ACB0C4EEAB421761B6C6E70B0FA1D20CE08247525641A7CD03B33A6EE3D35D8A

Deweaponize feature PoC video (NG v1.0) 2025: <br>
https://www.youtube.com/watch?v=w5TKNvnE0_g

Video PoC (old but gold v2): <br >
https://www.youtube.com/watch?v=_Ho0bpeJWqI

[NG version 1.0]
First official NG versioned release with significant updates, fixes and new features <br>

RansomLordNG generated PE files are saved to disk in the x32 or x64 directorys where the program is run from. <br>
Goal is to exploit vulnerabilities inherent in certain strains of ransomware by deploying exploits to defend the network!<br> <br>
The DLLs may also provide additonal coverage against generic and info stealer malwares.<br>
RansomLord and its exported DLLs are NOT malicious see -s flag for security info.<br>

Exploit x32/x64 DLL MD5: <br>
61126F5D55BA58398C317814389CF05C <br>
3CB517B752D6668FDC06BE8F1664378A <br>

[Malvuln history] <br>
  May of 2022, I publicly disclosed a novel strategy to successfully defeat ransomware
  Using a well known attacker technique (DLL Hijack) to terminate Malware pre-encryption
  The first Malware to be successfully exploited was from Lockbit group MVID-2022-0572
  Followed by Conti, REvil, BlackBasta and CryptoLocker proving many are vulnerable <br>

[The Pwned] <br>
RansomLordNG v1.0 DLLs intercept and terminate ransomware from sixty-one threat groups.
Adding VanHelsing, Pe32Ransom, Makop, Superblack, Mamona, Lynx and Fog to the victim list. <br><br>
Note: if you plan on testing Fog ransomware, you will have to bypass many malware anti-analysis 
and debugging techniques. Failure to do that will result in 'Sandbox detected! Exiting process...' <br>

[de-weaponize] <br>
deweaponize feature (experimental/optional) attempts to render a malware inoperable.
This experimental option potentially works for malware ran with high integrity (Admin). 
Goal is to reduce the risk of subsequent malware execution post exploitation by accident 
or from improper handling of malware during DFIR or other security response operations.

This feature is experimental and there is NO gurantee it will work. However, it has shown 
capability and high success rate when tested in a virtual machine environment. <br>

When deweaponize is enabled an exploit DLL will attempt the following actions: 
  1) copy the intercepted malware and rename it to a .bin file extension 
  2) delete the weaponized malware containing the .exe (weaponized) file extension 
Warn: some malware may drop additional malicious files to other directories, the feature 
does not account for that scenario and takes no attempted actions on such files.
There is always risk of false positives and non-malicious programs may be renamed and or deleted.
Therefore, use at own risk and enabling event logging with (-e) is suggested if using deweaponize.

deweaponize DISCLAIMER: <br>
By enabling deweaponize you agree and accept ALL legal liability, damages and associated risks 
Accept all responsibility, consequences and acknowlege it is experimental and without guarantees.
Moreover, you agree to allow RansomLordNG generated DLLs to COPY intercepted malware to disk, 
on the affected machine with the intention, to disable the malware by file extension renaming.
You also accept that an intercepted file containing a .exe file extension may be deleted.
You accept the risk and understand false positives can occur, potentially renaming or deleting 
a legitimate software file due to failure, possible error and or other unforeseen conditions.
Therefore, continue and use the de-weaponize feature only if you accept this risk. <br>

[SHA256 improved] <br>
NG v1.0 release also contains a more reliable, stable SHA256 hash generation for event logging.
In prior versions, hashing was done by creating a new process in memory that used native Windows 
certutil.exe to try an calculate a malwares SHA256 hash, this worked intermittently at best.
malware is now hashed more reliably in C code, using the public informational standard RFC4634. 

[NG Version] <br>
  Next gen version dumps process memory of the targeted Malware prior to termination.
  The process memory dump file MalDump.dmp varies in size and can be 50 MB plus.
  RansomLord now intercepts and terminates ransomware from sixty-one different threat groups.
  VanHelsing, Pe32Ransom, Makop, Superblack, Mamona, Lynx and Fog to the ever growing pwned list.

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
  This may work when malware is executed with high integrity (Admin).
  Process memory dumps are saved to C:\Users\Public\MalDump.dmp when successful.
  Leveraging code execution vulnerabilities to dump cleartext strings etc from process
  memory to disk, may be useful as we may avoid PE unpacking, anti-debugging techniques
  or relying on fully executing the Malware

[Event Log IOC] <br>
  The -e flag sets up a custom Windows Event source in the Windows registry
  Events are written to 'Windows Logs\Application' as 'RansomLord' event ID 1
  malware name, SHA256 hash and process path are included in the general information
  Additional logging now includes the DLL name that intercepted the malware. In addition
  if deweaponize and or MalDump is enabled they are also logged to the general information

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

![RansomLordNG-v1 0](https://github.com/user-attachments/assets/af76c0ba-8a46-4929-aa90-19bf11ad5671)

##### [ Currently defeats the following ransomware ] <br>
[0] Lockbit
[1] Yanluowang
[2] Conti
[3] REvil
[4] BlackMatter
[5] WannaCry
[6] LokiLocker
[7] Ryuk.A
[8] Hive v5.1
[9] BlueSky
[10] Haron
[11] Thanos
[12] AvosLocker
[13] AtomSilo
[14] Cryakl
[15] Meow
[16] BabukLocker
[17] Darkside
[18] CTBLocker
[19] Cerber
[20] Cryptowall
[21] Alphaware
[22] Clop
[23] Play
[24] Nokoyawa
[25] BlackCat(ALPHV)
[26] Royal
[27] Chaos
[28] Crytox
[29] LockerGoga
[30] Rook
[31] HelloKitty
[32] Curator
[33] Wagner
[34] BlackSnake
[35] DarkBit
[36] DoubleZero
[37] HakBit
[38] Jaff
[39] Paradise
[40] Vohuk
[41] Medusa
[42] Phobus
[43] StopCrypt
[44] RuRansom
[45] RisePro
[46] MoneyMessage
[47] CryptoFortress
[48] Onyx
[49] GPCode
[50] DarkRace
[51] Snocry
[52] Sage
[53] HydraCrypt
[54] VanHelsing
[55] Pe32Ransom
[56] Superblack
[57] Mamona
[58] Lynx
[59] Makop
[60] Fog



 
