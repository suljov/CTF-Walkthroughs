


# Foothold



with no creds we can just try to login to rdp and we see this

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240216233910.png)

we get in but for the looks of it is a "kiosk computer". 

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240216233956.png)
we can barley see or do anything. 

with some basic "kiosk escape tricks" we can a shell. 

press windows key to get the start menu 


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240216234101.png)


we will see if edge is locked down or we can use it to get cmd shell

we can use the browser to find cmd.exe. we will save it to the downloads folder and save it as msedge or else it will be blocked


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240216234259.png)


in the windows start menu open up the downloads folder and start the cmd.exe


we have a shell

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240216234351.png)



# Privesc 1 


after some looking we found that the RDP+ is installed 

we found a secret folder that have credentials that is stored but is encoded. 

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240216234547.png)

this can be used for RDP+ but after some testing we cant use it either on the target nor our own windows dev machine. but in our own machine we can get the password to show in the RDP+ using a tool called `BulletsPassView`

https://www.nirsoft.net/utils/bullets_password_view.html


after it will look like this 

#### before:
![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240216234939.png)

#### After:
![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240216234921.png)

now we can use `runas` to get a shell as admin

```
PS C:\_admin> runas /user:admin powershell.exe
Enter the password for admin:
Attempting to start powershell.exe as user "ESCAPE\admin" ...
```


now we are admin (kinda)

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240216235059.png)



# Privesc 2


now as admin we might got a little bit more priv but not much at all. 

now we can try to download cmd as before. but after that we will try to run it as `admin`

start edge 

```
cd "C:\Program Files (x86)\Microsoft\Edge\Application\"

.\msedge.exe
```

```
cd "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"

".\Microsoft Edge.lnk"
```

save it as msedge again (since we are the admin user now)

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240217000031.png)

do the same process but now right click and press to run as admin


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240217000130.png)

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240217000143.png)

and now we are full admin

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Escape/Screenshots/Pasted%20image%2020240217000230.png)

