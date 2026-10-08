# WIRESHARK-commands

## 1. Базовые фильтры (основа основ)

По IP-адресу

    ip.addr == 10.9.11.135 Все пакеты от/к этому IP

    ip.src == 10.9.11.135 Только исходящие

    ip.dst == 10.9.11.135 Только входящие

    ip.addr == 10.9.11.0/24 Вся подсеть

    ip.addr != 10.9.11.2 Всё, кроме DC
    
По MAC-адресу
    
    eth.addr == 00:22:fb:ec:7e:e7 По MAC (от/к)
    
    eth.src == 00:22:fb:ec:7e:e7 Только источник
    
    eth.dst == ff:ff:ff:ff:ff:ff Broadcast-пакеты

По порту

    tcp.port == 443 TCP-трафик на порт 443
    
    udp.port == 53 UDP на порт 53 (DNS)
    
    tcp.srcport == 63723 Исходящий порт
    
    tcp.dstport == 9000 Входящий порт (нестандартный!)
    
    tcp.portrange 1024-65535 Диапазон портов

Логические операторы

    И and или &&
    
    ИЛИ or или ||
    
    НЕ not или !

    Содержит contains

    Матч matches (regex)

##  2. Протокольные фильтры

TCP / UDP

    tcp                                        # весь TCP-трафик
    tcp.flags.syn == 1                         # только SYN-пакеты (начало соединения)
    tcp.flags.ack == 1
    tcp.flags.syn == 1 && tcp.flags.ack == 1   # SYN-ACK
    tcp.flags.reset == 1                       # RST (сброс соединения — подозрительно!)
    tcp.flags.fin == 1                         # FIN (завершение)
    tcp.analysis.retransmission                # ретрансмиссии (проблемы в сети)
    tcp.stream eq 5                            # весь 5-й TCP-поток (Follow TCP Stream)
    udp                                        # весь UDP

HTTP / HTTPS

    http                                 # весь HTTP
    http.request                         # только запросы
    http.response                        # только ответы
    http.request.method == "GET"
    http.request.method == "POST"
    http.request.uri contains "exe"      # ищет exe в url
    http.host contains "org"             # ищет org в домене
    http.user_agent contains "PowerShell"        # 🔥 для ClickFix!
    http.content_type contains "application"
    tls                                          # весь TLS/SSL
    tls.handshake.extensions_server_name contains "org"

DNS

    dns                          # весь DNS
    dns.qry.name contains "org"
    dns.qry.name contains "overhands"
    dns.qry.type == A            # только A-записи
    dns.qry.type == AAAA         # IPv6
    dns.qry.type == TXT          # TXT-записи (часто DNS-туннелирование!)
    dns.qry.type == MX
    dns.qry.type == SRV          # SRV-записи (поиск DC, как в твоём задании)
    dns.resp.name                # ответы DNS
    dns.flags.rcode == 3         # NXDOMAIN (домен не существует)

## 4. Blue Team фильтры (самые важные для SOC)

    Kerberos
    kerberos                     # весь Kerberos
    kerberos.msg.type == 10      # AS-REQ (первичная аутентификация) 
    kerberos.msg.type == 12      # TGS-REQ (сервисный билет)
    kerberos.msg.type == 14      # AP-REQ (доступ к сервису)
    kerberos.msg.type == 15      # TGS-REP
    kerberos.msg.type == 11      # AS-REP
    kerberos.CNameString contains "admin"  # поиск по имени

SMB / NTLM

SMB (Server Message Block) — протокол Windows для доступа к файлам и папкам по сети.

    smb                          # SMBv1
    smb2                         # SMBv2/v3
    smb2.cmd == 0                # Negotiate Protocol
    smb2.cmd == 1                # Session Setup ⭐ (тут имя пользователя!)
    ntlmssp                      # NTLM-аутентификация
    ntlmssp.auth.ntlm_response   # NTLM-ответы (можно брутфорсить!)

LDAP (Active Directory)
    
    ldap                         # весь LDAP
    ldap.msgid                   # по ID сообщения
    ldap.searchRequest           # запросы поиска
    ldap.searchResEntry          # ответы с данными ⭐ (тут ФИО!)
    ldap.bindRequest             # аутентификация

DHCP

    bootp                        # DHCP (да, в Wireshark это bootp!)
    bootp.option.dhcp == 1       # DHCP Discover
    bootp.option.dhcp == 3       # DHCP Request
    bootp.option.hostname        # имя хоста

ARP

    arp                          # весь ARP
    arp.opcode == 1              # ARP Request
    arp.opcode == 2              # ARP Reply
    arp.src.proto_ipv4 == 10.9.11.135

##  5. Поиск по содержимому (когда не знаешь, что искать)

    frame contains "password"           # ищет во всём пакете
    frame contains "admin"
    frame contains "base64"
    data contains "MZ"                  # сигнатура EXE-файла
    data contains "PK"                  # сигнатура ZIP/DOCX
    tcp contains "GET /"
    icmp                               # пинги (часто C2-beaconing) что еще добавить
