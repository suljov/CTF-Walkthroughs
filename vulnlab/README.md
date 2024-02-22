![image](https://images.squarespace-cdn.com/content/v1/645cd03992f04603f1cee0e6/3426e498-a8f5-49b0-b970-21727c7df786/dark_transparent_full_blue_small.png?format=1500w)


###### https://www.vulnlab.com/
###### https://wiki.vulnlab.com/
###### https://vulndev.io/

Vulnlab offers a pentesting & red teaming lab environment with 80+ vulnerable machines, ranging from standalone machines to big Active Directory environments with multiple forests that require bypassing modern defenses. The labs have various difficulties from easy to advanced and come with guidance in the form of notes, hints & walkthroughs. New content gets added on a regular basis.

You will get access to a private lab area on the Discord server, from which you can generate VPN packs, control machines and submit flags.



#### My thoughts

I started on Vulnlab 2024-02-07 and so far i love it. The boxes are well made and they are realistic. For me the labs are worth every penny. Vulnlab is the GOAT and the best place!! atleast for me. I learn so much on every box, even if its small stuff it nice to learn something cool and new. 


### Box walkthroughs
* [Baby](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/baby) - 🪟 - Easy
* [Data](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Data) - 🐧 - Easy
* [Escape](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Escape) - 🪟 - Easy
* [Feedback](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Feedback)  - 🐧 - Easy
* [Forgotten](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Forgotten) - 🐧
* [Lock](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Lock) - 🪟 - Easy
* [Retro](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Retro) - 🪟 - Easy
* [Sync](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Sync) - 🐧 - Easy
* [Baby2](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Baby2) - 🪟 - Medium
* [Bamboo](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Bamboo) - 🪟 - Medium
* [Breach](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Breach) - 🪟 - Medium
* [Delegate](https://github.com/suljov/CTF-Walkthroughs/tree/main/vulnlab/Delegate) - 🪟 - Medium





| **Command**              | **Description**                      |
| ------------------------ | ------------------------------------ |
| **General**              |                                      |
| `sudo openvpn user.ovpn` | Connect to VPN                       |
| `ifconfig`/`ip a`        | Show our IP address                  |
| `netstat -rn`            | Show networks accessible via the VPN |
| `ssh user@10.10.10.10`   | SSH to a remote server               |
| `ftp 10.129.42.253`      | FTP to a remote server               |
| **tmux**                 |                                      |
| `tmux`                   | Start tmux                           |
| `ctrl+b`                 | tmux: default prefix                 |
| `prefix c`               | tmux: new window                     |
| `prefix 1`               | tmux: switch to window (`1`)         |
| `prefix shift+%`         | tmux: split pane vertically          |
| `prefix shift+"`         | tmux: split pane horizontally        |
| `prefix ->`              | tmux: switch to the right pane       |
| **Vim**                  |                                      |
| `vim file`               | vim: open `file` with vim            |
| `esc+i`                  | vim: enter `insert` mode             |
| `esc`                    | vim: back to `normal` mode           |
| `x`                      | vim: Cut character                   |
| `dw`                     | vim: Cut word                        |
| `dd`                     | vim: Cut full line                   |
| `yw`                     | vim: Copy word                       |
| `yy`                     | vim: Copy full line                  |
| `p`                      | vim: Paste                           |
| `:1`                     | vim: Go to line number 1.            |
| `:w`                     | vim: Write the file 'i.e. save'      |
| `:q`                     | vim: Quit                            |
| `:q!`                    | vim: Quit without saving             |
| `:wq`                    | vim: Write and quit                  |
