---
layout      : post
title       : "Vessel - HackTheBox"
author      : L4nder
published   : false
image       : assets/images/HTB/Vessel/Vessel.jpg
category    : [ HackTheBox ]
tags        : [ Linux ]
---

Hola a todos! Hoy estaremos completando la máquina [Vessel](https://app.hackthebox.com/machines/Vessel) de la plataforma [HackTheBox](https://app.hackthebox.com), donde tocaremos los siguientes puntos:

- **Web Enumeration**
- **Extracting the contents of .git directory - GitDumper**
- **Source Code Analysis**
- **Exploiting CVE-2022-24637**
- **Binary Code Analysis**
- **Python Scripting in order to crack a password protected PDF**
- **Exploiting SUID Binary [Privilege Escalation]**

# Reconocimiento

Bueno, como cualquier otra máquina, comenzaremos escaneando todo el rango de puertos por el protocolo TCP utilizando la herramienta `nmap`

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.178 -oG allPorts
Nmap scan report for 10.10.11.178
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Ahora, vamos a utilizar la herramienta `extractPorts` para extraer toda la información importante de la captura grepeable que acabamos de crear con `nmap`

```shell
❯ which extractPorts
extractPorts () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')" 
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)" 
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
	/bin/batcat --paging=never extractPorts.tmp
	rm extractPorts.tmp
}
❯ extractPorts allPorts
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.11.178
   5   │     [*] Open ports: 22,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Ahora, vamos a profundizar nuestro escaneo únicamente sobre estos dos puertos

```shell
❯ nmap -p22,80 -sCV 10.10.11.178 -oN targeted
Nmap scan report for 10.10.11.178
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 38c297327b9ec565b44b4ea330a59aa5 (RSA)
|   256 33b355f4a17ff84e48dac5296313833d (ECDSA)
|_  256 a1f1881c3a397274e6301f28b680254e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Vessel
|_http-trane-info: Problem with XML parsing of /evox/about
```

