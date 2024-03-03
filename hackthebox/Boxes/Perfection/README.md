

# Foothold 

we see their is only ssh and the web. 

in the web we see the calculator for the Grade Calculator

[!image](https://github.com/suljov/CTF-Walkthroughs/blob/main/hackthebox/Boxes/Perfection/Screenshots/Pasted%20image%2020240303175253.png)
after testing we see we might get some kind of os command injection

![[Pasted image 20240303175336.png]]


looking into `WEBrick` a little bit it might be ruby or some kind but not sure. we try some filter bypass and found `%0a` will kinda break it and we are able to use more characters to get a working payload 

![[Pasted image 20240303180142.png]]

to make a payload we find its a `SSTI` and use a payload for that.

after looking we found this payload 

```
<%= 7*7 %>
```

this one is just to test `SSTI`

but i dont work

![[Pasted image 20240303180520.png]]

we might need to encode some stuff.

we encode the start and the end of the payload

after encoding

```
<%25= 7*7 %25>
```


![[Pasted image 20240303180629.png]]

and we got 49 meaning it works. now we can use `system` to execute commands

we make a payoad to download and execute a bash script to get shell

![[Pasted image 20240303180800.png]]


and we have shell


![[Pasted image 20240303180830.png]]


# Privesc


after enumerating the box we a message from the mail

```
cat /var/mail/susan

Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```

ah so our password will be `susan_nasus<random number>`

inside our users home folder we see the folder `Migration` that as a file called `pupilpath_credentials.db`

after downloading it we see its the hashes for the users

![[Pasted image 20240303181123.png]]

so now we have a hash of the user susan. we now get a script that will crack this hash since we know what the password will look like

script: 

```
import hashlib

def generate_password(firstname):
    firstname_lower = firstname.lower()
    firstname_backwards = firstname_lower[::-1]
    for i in range(1, 1000000001):
        password = f"{firstname_lower}_{firstname_backwards}_{i}"
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        yield password, hashed_password

def crack_hash(hash_to_crack, firstname):
    for password, hashed_password in generate_password(firstname):
        if hashed_password == hash_to_crack:
            return password
    return None

# Hash provided by the user
hash_to_crack = "abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f"

# Firstname of the user
firstname = "Susan"

# Attempt to crack the hash
cracked_password = crack_hash(hash_to_crack, firstname)

if cracked_password:
    print(f"Hash cracked! Password is: {cracked_password}")
else:
    print("Unable to crack the hash.")

```

after a while we see the hash was cracked

![[Pasted image 20240303181749.png]]


we now use that password and login as root

![[Pasted image 20240303181448.png]]
