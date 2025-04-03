rule hijack_network {
    meta:
        id = "3o6LzpYOE7iauzWNt82MzG"
        fingerprint = "v1_sha256_82a53308659b227be705ad1830b0cec9933ca189004cab373fe3de14de645d75"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Hijack network configuration"
        category = "INFO"

    strings:
        $p1 = "SOFTWARE\\Classes\\PROTOCOLS\\Handler" nocase
        $p2 = "SOFTWARE\\Classes\\PROTOCOLS\\Filter" nocase
        $p3 = "Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer" nocase
        $p4 = "software\\microsoft\\windows\\currentversion\\internet settings\\proxyenable" nocase
        $f1 = "drivers\\etc\\hosts" nocase
    condition:
        any of them
}
rule network_udp_sock {
    meta:
        id = "LLPeQMpfNwWegFjnc9bPj"
        fingerprint = "v1_sha256_6a8310711d72a824dcae45369069cdaf1fcd6475ac73428f2cd5b37b34c51ce5"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications over UDP network"
        category = "INFO"

    strings:
        $f1 = "Ws2_32.dll" nocase
    $f2 = "System.Net" nocase
        $f3 = "wsock32.dll" nocase
        $c0 = "WSAStartup"
        $c1 = "sendto"
        $c2 = "recvfrom"
        $c3 = "WSASendTo"
        $c4 = "WSARecvFrom"
        $c5 = "UdpClient"
    condition:
        (($f1 or $f3) and 2 of ($c*)) or ($f2 and $c5)
}
rule network_tcp_listen {
    meta:
        id = "3KtYgcHfK0iUtSQnOMfoIa"
        fingerprint = "v1_sha256_1b2001706c4afe9c44a9e5c1736461197ed3ac6c9dc14cffebc388d737f35e3a"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Listen for incoming communication"
        category = "INFO"

    strings:
        $f1 = "Ws2_32.dll" nocase
        $f2 = "Mswsock.dll" nocase
        $f3 = "System.Net" nocase
        $f4 = "wsock32.dll" nocase
        $c1 = "bind"
        $c2 = "accept"
        $c3 = "GetAcceptExSockaddrs"
        $c4 = "AcceptEx"
        $c5 = "WSAStartup"
        $c6 = "WSAAccept"
        $c7 = "WSASocket"
        $c8 = "TcpListener"
        $c9 = "AcceptTcpClient"
        $c10 = "listen"
    condition:
        1 of ($f*) and 2 of ($c*)
}
rule network_dyndns {
    meta:
        id = "tf0iyDAOkAqiK2I9WH67C"
        fingerprint = "v1_sha256_00ae5f2786fce6350baa3a3c2381545e0d7f8d71bb8c5bb4829af443f8379a71"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications dyndns network"
        category = "INFO"

    strings:
    $s1 =".no-ip.org"
        $s2 =".publicvm.com"
        $s3 =".linkpc.net"
        $s4 =".dynu.com"
        $s5 =".dynu.net"
        $s6 =".afraid.org"
        $s7 =".chickenkiller.com"
        $s8 =".crabdance.com"
        $s9 =".ignorelist.com"
        $s10 =".jumpingcrab.com"
        $s11 =".moo.com"
        $s12 =".strangled.com"
        $s13 =".twillightparadox.com"
        $s14 =".us.to"
        $s15 =".strangled.net"
        $s16 =".info.tm"
        $s17 =".homenet.org"
        $s18 =".biz.tm"
        $s19 =".continent.kz"
        $s20 =".ax.lt"
        $s21 =".system-ns.com"
        $s22 =".adultdns.com"
        $s23 =".craftx.biz"
        $s24 =".ddns01.com"
        $s25 =".dns53.biz"
        $s26 =".dnsapi.info"
        $s27 =".dnsd.info"
        $s28 =".dnsdynamic.com"
        $s29 =".dnsdynamic.net"
        $s30 =".dnsget.org"
        $s31 =".fe100.net"
        $s32 =".flashserv.net"
        $s33 =".ftp21.net"
    condition:
        any of them
}

rule network_toredo {
    meta:
        id = "4wAg4gJZvzUKvGCtMW9IHe"
        fingerprint = "v1_sha256_375d31db79d93409fa958ecaf7e48094e84e7dd726bb325d409e17d7ee387962"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications over Toredo network"
        category = "INFO"

    strings:
          $f1 = "FirewallAPI.dll" nocase
        $p1 = "\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\" nocase
    condition:
        all of them
}

rule network_smtp_dotNet {
    meta:
        id = "7Mx56dQWzX0rxZibITX8lm"
        fingerprint = "v1_sha256_561f43ff22e9d01430fcd2f5a278a7c1b50fce3520e335266b87a85aefd86356"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications smtp"
        category = "INFO"

    strings:
          $f1 = "System.Net.Mail" nocase
        $p1 = "SmtpClient" nocase
    condition:
        all of them
}

rule network_smtp_raw {
    meta:
        id = "5KwQLWCb2ZiRwdUx0FvzYa"
        fingerprint = "v1_sha256_139302eecb856675a52de006a03b57d8f28f2709389aee9057bf157fc223446d"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications smtp"
        category = "INFO"

  strings:
          $s1 = "MAIL FROM:" nocase
        $s2 = "RCPT TO:" nocase
  condition:
        all of them
}

rule network_smtp_vb {
    meta:
        id = "1m6PpZFVg0BLSn1TRYD4gG"
        fingerprint = "v1_sha256_315a06691e6b6971c1cf3cdd55ebc167defe5ea8b9f7e541c73267879ffaaa17"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications smtp"
        category = "INFO"

    strings:
          $c1 = "CDO.Message" nocase
        $c2 = "cdoSMTPServer" nocase
        $c3 = "cdoSendUsingMethod" nocase
        $c4 = "cdoex.dll" nocase
        $c5 = "/cdo/configuration/smtpserver" nocase
    condition:
        any of them
}

rule network_p2p_win {
    meta:
        id = "1u5e75bGNdfNxqbK25bsxZ"
        fingerprint = "v1_sha256_e3d51775734d9548919a05881498b1005698752b5866c9d474864708a3cd5abe"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications over P2P network"
        category = "INFO"

    strings:
         $c1 = "PeerCollabExportContact"
         $c2 = "PeerCollabGetApplicationRegistrationInfo"
         $c3 = "PeerCollabGetEndpointName"
         $c4 = "PeerCollabGetEventData"
         $c5 = "PeerCollabGetInvitationResponse"
         $c6 = "PeerCollabGetPresenceInfo"
         $c7 = "PeerCollabGetSigninOptions"
         $c8 = "PeerCollabInviteContact"
         $c9 = "PeerCollabInviteEndpoint"
         $c10 = "PeerCollabParseContact"
         $c11 = "PeerCollabQueryContactData"
         $c12 = "PeerCollabRefreshEndpointData"
         $c13 = "PeerCollabRegisterApplication"
         $c14 = "PeerCollabRegisterEvent"
         $c15 = "PeerCollabSetEndpointName"
         $c16 = "PeerCollabSetObject"
         $c17 = "PeerCollabSetPresenceInfo"
         $c18 = "PeerCollabSignout"
         $c19 = "PeerCollabUnregisterApplication"
         $c20 = "PeerCollabUpdateContact"
    condition:
        5 of them
}
rule network_tor {
    meta:
        id = "7BItXroaHga11EhUeIlgse"
        fingerprint = "v1_sha256_7bfcd62e8ed1ecfc148deb2803956a6598798523bd4a9191b370c85c9dee3dcf"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications over TOR network"
        category = "INFO"

    strings:
        $p1 = "tor\\hidden_service\\private_key" nocase
        $p2 = "tor\\hidden_service\\hostname" nocase
        $p3 = "tor\\lock" nocase
        $p4 = "tor\\state" nocase
    condition:
        any of them
}
rule network_irc {
    meta:
        id = "7AMniIDWkm1rfi9RwxROrX"
        fingerprint = "v1_sha256_f81f7b5d53b98cdcdc1fb706f93cd6415b37c45a0a9366ca7150f664d71307bc"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications over IRC network"
        category = "INFO"

    strings:
        $s1 = "NICK"
        $s2 = "PING"
        $s3 = "JOIN"
        $s4 = "USER"
        $s5 = "PRIVMSG"
    condition:
        all of them
}

rule network_http {
    meta:
        id = "6mnhB4Om1Af4DoMr6AsYLL"
        fingerprint = "v1_sha256_48042e195d0333b78171b8bae6a4ae03e60b662ccaa042c92e981d08423cfd8e"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications over HTTP"
        category = "INFO"

    strings:
        $f1 = "wininet.dll" nocase
        $c1 = "InternetConnect"
        $c2 = "InternetOpen"
        $c3 = "InternetOpenUrl"
        $c4 = "InternetReadFile"
        $c5 = "InternetWriteFile"
        $c6 = "HttpOpenRequest"
        $c7 = "HttpSendRequest"
        $c8 = "IdHTTPHeaderInfo"
    condition:
        $f1 and $c1 and ($c2 or $c3) and ($c4 or $c5 or $c6 or $c7 or $c8)
}


rule network_ftp {
    meta:
        id = "3NsqZovaBSfyzhWHuvBqrt"
        fingerprint = "v1_sha256_88e8a4f581cdb9c1ce628460ed20da4a4877d3dd29dfcc199161722f6760b028"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications over FTP"
        category = "INFO"

    strings:
          $f1 = "Wininet.dll" nocase
        $c1 = "FtpGetCurrentDirectory"
        $c2 = "FtpGetFile"
        $c3 = "FtpPutFile"
        $c4 = "FtpSetCurrentDirectory"
        $c5 = "FtpOpenFile"
        $c6 = "FtpGetFileSize"
        $c7 = "FtpDeleteFile"
        $c8 = "FtpCreateDirectory"
        $c9 = "FtpRemoveDirectory"
        $c10 = "FtpRenameFile"
        $c11 = "FtpDownload"
        $c12 = "FtpUpload"
        $c13 = "FtpGetDirectory"
    condition:
        $f1 and (4 of ($c*))
}

rule network_tcp_socket {
    meta:
        id = "RJERxAGsOWpeEt9yiycjA"
        fingerprint = "v1_sha256_13fa5ac080880bbad579d0fc3360236f621ffa0d800d0ea27fbfcc9207d210b7"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications over RAW socket"
        category = "INFO"

    strings:
          $f1 = "Ws2_32.dll" nocase
        $f2 = "wsock32.dll" nocase
        $c1 = "WSASocket"
        $c2 = "socket"
        $c3 = "send"
        $c4 = "WSASend"
        $c5 = "WSAConnect"
        $c6 = "connect"
        $c7 = "WSAStartup"
        $c8 = "closesocket"
        $c9 = "WSACleanup"
    condition:
        1 of ($f*) and 2 of ($c*)
}

rule network_dns {
    meta:
        id = "1ZhXKlEmgipBcJcJchRCVE"
        fingerprint = "v1_sha256_de51ed908cf39d725ba532dc445454858dd77db0768fee2bf8ccce1b8d2a3025"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications use DNS"
        category = "INFO"

    strings:
        $f1 = "System.Net"
        $f2 = "Ws2_32.dll" nocase
        $f3 = "Dnsapi.dll" nocase
        $f4 = "wsock32.dll" nocase
        $c2 = "GetHostEntry"
          $c3 = "getaddrinfo"
          $c4 = "gethostbyname"
          $c5 = "WSAAsyncGetHostByName"
          $c6 = "DnsQuery"
    condition:
        1 of ($f*) and  1 of ($c*)
}

rule network_ssl {
    meta:
        id = "3UfpEMAmgySZQ7mjogZvyU"
        fingerprint = "v1_sha256_e767086c8fccaaca13e6ef6cecb57768a4ba941aacd4cbb99571574a333fae8c"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communications over SSL"
        category = "INFO"

    strings:
        $f1 = "ssleay32.dll" nocase
        $f2 = "libeay32.dll" nocase
        $f3 = "libssl32.dll" nocase
        $c1 = "IdSSLOpenSSL" nocase
    condition:
        any of them
}

rule network_dga {
    meta:
        id = "4N5P04BDVjJ5ZZrLH59LAV"
        fingerprint = "v1_sha256_f8faa45870012d068a86deb31f1639f1fad1e9aab16ffc351c1c8e04b0dd3c76"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Communication using dga"
        category = "INFO"

    strings:
        $dll1 = "Advapi32.dll" nocase
        $dll2 = "wininet.dll" nocase
          $dll3 = "Crypt32.dll" nocase
        $time1 = "SystemTimeToFileTime"
        $time2 = "GetSystemTime"
        $time3 = "GetSystemTimeAsFileTime"
        $hash1 = "CryptCreateHash"
        $hash2 = "CryptAcquireContext"
        $hash3 = "CryptHashData"
        $net1 = "InternetOpen"
        $net2 = "InternetOpenUrl"
        $net3 = "gethostbyname"
        $net4 = "getaddrinfo"
    condition:
        all of ($dll*) and 1 of ($time*) and 1 of ($hash*) and 1 of ($net*)
}
rule lookupip {
    meta:
        id = "YaAstyG8BLgFlTo4kgWN6"
        fingerprint = "v1_sha256_e4cf83d8320d08d3bdd5ef8c9808c6713b83be22b5bf94344432568002a333eb"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Lookup external IP"
        category = "INFO"

    strings:
        $n1 = "checkip.dyndns.org" nocase
        $n2 = "whatismyip.org" nocase
        $n3 = "whatsmyipaddress.com" nocase
        $n4 = "getmyip.org" nocase
        $n5 = "getmyip.co.uk" nocase
    condition:
        any of them
}

rule dyndns {
    meta:
        id = "3LLK3dC3jbB7xRfG2HXGl5"
        fingerprint = "v1_sha256_affe67dbb8ed6cf7bc6d2fee11e11a1084ce30632a7a2d0353b96dca0f6c4cd0"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Dynamic DNS"
        category = "INFO"

    strings:
        $s1 = "SOFTWARE\\Vitalwerks\\DUC" nocase
    condition:
        any of them
}

rule lookupgeo {
    meta:
        id = "1JqZHVsixcOYDIY0QhNUUd"
        fingerprint = "v1_sha256_585382bc43dbf5316d135719b5ffa794199cce37b3fdb9dd4aa7a7f817149398"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Lookup Geolocation"
        category = "INFO"

    strings:
        $n1 = "j.maxmind.com" nocase
    condition:
        any of them
}
rule sniff_lan {
    meta:
        id = "aiifvBLWMoave041tvLRJ"
        fingerprint = "v1_sha256_98ee8a041f469b944817461a5f4f53a7bab66b4b72f04d4fe7baba3e46c11aa1"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Sniff Lan network traffic"
        category = "INFO"

    strings:
        $f1 = "packet.dll" nocase
        $f2 = "npf.sys" nocase
        $f3 = "wpcap.dll" nocase
        $f4 = "winpcap.dll" nocase
    condition:
        any of them
}
rule spreading_file {
    meta:
        id = "zW2OnfU3m2YPGSuFBWuDP"
        fingerprint = "v1_sha256_5e7473c94ba5966bb195ce27690d9a7c76d499ab3fc9ac765c691b38f9989787"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Malware can spread east-west file"
        category = "INFO"

    strings:
        $f1 = "autorun.inf" nocase
        $f2 = "desktop.ini" nocase
        $f3 = "desktop.lnk" nocase
    condition:
        any of them
}
rule spreading_share {
    meta:
        id = "34fSicwu2Ne1dMKInKMXkm"
        fingerprint = "v1_sha256_30756413139a7bd2a1b77d0f78986a8784c0d6691c307ab9943036b30167bffa"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Malware can spread east-west using share drive"
        category = "INFO"

    strings:
        $f1 = "netapi32.dll" nocase
        $c1 = "NetShareGetInfo"
        $c2 = "NetShareEnum"
    condition:
        $f1 and 1 of ($c*)
}

rule rat_vnc {
    meta:
        id = "4TIGYivEKz9NsUJa1nmbjj"
        fingerprint = "v1_sha256_1a150e4f4f0b7053bfa45e9cf830dbfe373e8fcfd198ded3ca6340764cd4d909"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Remote Administration toolkit VNC"
        category = "INFO"

    strings:
        $f1 = "ultravnc.ini" nocase
        $c2 = "StartVNC"
        $c3 = "StopVNC"
    condition:
        any of them
}

rule rat_rdp {
    meta:
        id = "6M45OJtn0Dnr247lRtoqvm"
        fingerprint = "v1_sha256_ebf4cd33b72e963afb14d53311bd84a45094f6df54288e7578b7d373d4cde3b2"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Remote Administration toolkit enable RDP"
        category = "INFO"

    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" nocase
        $p2 = "software\\microsoft\\windows nt\\currentversion\\terminal server" nocase
        $p3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" nocase
        $r1 = "EnableAdminTSRemote"
        $c1 = "net start termservice"
        $c2 = "sc config termservice start"
    condition:
        any of them
}

rule rat_telnet {
    meta:
        id = "mvB1e744v4A3D47vICO7u"
        fingerprint = "v1_sha256_946fabd142d61ecd6cc6cd14d2b28a5c08733793813ed9c871c235052fd6920d"
        version = "0.1"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Remote Administration toolkit enable Telnet"
        category = "INFO"

    strings:
        $r1 = "software\\microsoft\\telnetserver" nocase
    condition:
        any of them
}
