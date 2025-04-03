rule Confucius_B
{
    meta:
        id = "2shdSyJbUZpT5KrsPSW5XH"
        fingerprint = "v1_sha256_66a0cf05a791aff71833cbf02097b7e4db4eb219bfedc6ae78efed7cc7ee63d7"
        version = "1.0"
        date = "2020-04-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Confucius malware."
        category = "MALWARE"
        malware = "CONFUCIUS"
        malware_type = "BACKDOOR"
        reference = "https://unit42.paloaltonetworks.com/unit42-confucius-says-malware-families-get-further-by-abusing-legitimate-websites/"
        first_imported = "2021-12-30"

    strings:
        $ = "----BONE-79A8DE0E314C50503FF2378aEB126363-" ascii wide
        $ = "----MUETA-%.08x%.04x%.04x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x-" ascii wide
        $ = "C:\\Users\\DMITRY-PC\\Documents\\JKE-Agent-Win32\\JKE_Agent_DataCollectorPlugin\\output\\Debug\\JKE_Agent_DumbTestPlugin.dll" ascii wide

    condition:
        any of them
}import "pe"

rule Cotx_RAT
{
    meta:
        id = "6GBzQXrRKLvayZwQyXgMZi"
        fingerprint = "v1_sha256_7ee24d050521c02b7e90b93432234ce8b12fe5388871fcf9cee1832c4a303380"
        version = "1.0"
        date = "2019-07-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Cotx RAT."
        category = "MALWARE"
        malware = "COTX"
        malware_type = "RAT"
        reference = "https://www.proofpoint.com/us/threat-insight/post/chinese-apt-operation-lagtime-it-targets-government-information-technology"
        first_imported = "2021-12-30"

    strings:
        $ = "%4d-%02d-%02d %02d:%02d:%02d" ascii wide
        $ = "%hs|%hs|%hs|%hs|%hs|%hs|%hs" ascii wide
        $ = "%hs|%s|%hs|%s|%s|%s|%s|%s|%s|%s|%hs" ascii wide
        $ = "%s;%s;%s;%.2f GB;%.2f GB|" ascii wide
        $ = "Cmd shell is not running,or your cmd is error!" ascii wide
        $ = "Domain:    [%s]" ascii wide
        $ = "Error:Cmd file not exists!" ascii wide
        $ = "Error:Create read pipe error!" ascii wide
        $ = "Error:No user is logoned!" ascii wide
        $ = "Error:You have in a shell,please exit first!" ascii wide
        $ = "Error:You have in a shell,please exit it first!" ascii wide
        $ = "Error:cmd.exe not exist!" ascii wide
        $ = "LogonUser: [%s]" ascii wide
        $ = "WriteFile session error!" ascii wide
        $ = "You have no permission to write on" ascii wide
        $ = "cannot delete directory:" ascii wide
        $ = "cannot delete file:" ascii wide
        $ = "cannot upload file to %s" ascii wide
        $ = "copy failed:" ascii wide
        $ = "exec failed:" ascii wide
        $ = "exec ok:" ascii wide
        $ = "explorer.exe" ascii wide
        $ = "file list error:open path [%s] error." ascii wide
        $ = "is already exist!" ascii wide
        $ = "is not exist!" ascii wide
        $ = "not exe:" ascii wide
        $ = "open file error:" ascii wide
        $ = "read file error:" ascii wide
        $ = "set config items error." ascii wide
        $ = "set config ok." ascii wide

    condition:
        15 of them or ( for any i in (0..pe.number_of_sections-1) : (pe.sections[i].name==".cotx"))
}import "pe"
rule NikiCert
{
    meta:
        id = "2XUGCKIiNCwsOo1BYZYlqT"
        fingerprint = "v1_sha256_d346c46bb51beaefcfdc247e20af3ceda6d239366c7126e1a568036ef4c8f60f"
        version = "1.0"
        date = "2024-06"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@bartblaze, @nsquar3"
        description = "Identifies Nexaweb digital certificate used in (likely) Kimsuky campaign."
        category = "INFO"
        reference = "https://cyberarmor.tech/new-north-korean-based-backdoor-packs-a-punch/"
        tlp = "White"
        hash_a = "cca1705d7a85fe45dce9faec5790d498427b3fa8e546d7d7b57f18a925fdfa5d"
        hash_b = "000e2926f6e094d01c64ff972e958cd38590299e9128a766868088aa273599c7"

condition:
    uint16(0) == 0x5A4D and
    for any i in (0 .. pe.number_of_signatures) : (
        pe.signatures[i].serial == "03:15:e1:37:a6:e2:d6:58:f0:7a:f4:54:c6:3a:0a:f2"
    )
}rule NikiGo
{
    meta:
        id = "1BZcRwqEMuksKi4WHnGAMd"
        fingerprint = "v1_sha256_8ba5e84e750a707eacabbf1df13900ef96ef773745f0f623f41da5e7ca905420"
        version = "1.0"
        date = "2024-06"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@bartblaze, @nsquar3"
        description = "Identifies NikiGo, a Go dropper by (likely) Kimsuky."
        category = "INFO"
        reference = "https://cyberarmor.tech/new-north-korean-based-backdoor-packs-a-punch/"
        hash = "000e2926f6e094d01c64ff972e958cd38590299e9128a766868088aa273599c7"
        tlp = "White"

strings:
    $go = "Go build ID:"

    $func1 = "main.ParseCommandLine" ascii wide fullword
    $func2 = "main.RunCmd" ascii wide fullword
    $func3 = "main.HttpGet" ascii wide fullword
    $func4 = "main.SelfDel" ascii wide fullword
    $func5 = "main.RandomBytes" ascii wide fullword

    $pdb_src = "C:/Users/niki/go/src/niki/auxiliary/engine-binder/main.go" ascii wide
    $pdb_path = "/Users/niki/go/src/niki/auxiliary/engine-binder/" ascii wide
    
condition:
    uint16(0) == 0x5A4D and $go and (
    all of ($func*) or
    any of ($pdb*)
    )
}rule NikiHTTP
{
    meta:
        id = "6AEqhgFoW83vh76GzxMtjF"
        fingerprint = "v1_sha256_0315e58657b36871b5937d06b338363de94e6bb81c19d03b92a53e2b525f56b4"
        version = "1.0"
        date = "2024-06"
        modified = "2025-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@bartblaze, @nsquar3"
        description = "Identifies NikiHTTP aka HTTPSpy, a versatile backdoor by (likely) Kimsuky."
        category = "INFO"
        reference = "https://cyberarmor.tech/new-north-korean-based-backdoor-packs-a-punch/"
        tlp = "White"
        hash_a = "3314b6ea393e180c20db52448ab6980343bc3ed623f7af91df60189fec637744"
        hash_b = "c94a5817fcd6a4ea93d47d70b9f2b175923a8b325234a77f127c945ae8649874"

strings:
    $cmd = {4? 8d 0d be 2f 03 00 4? 85 c0 4? 8d 15 8c 2f 03 00}
    $str_1 = "%s%sc %s >%s 2>&1" ascii wide
    $str_2 = "%s%sc %s 2>%s" ascii wide
    $str_3 = "%s:info" ascii wide
    
    //D:\02.data\03.atk-tools\engine\niki\httpSpy\..\bin\httpSpy.pdb
    $pdb_full = "\\02.data\\03.atk-tools\\"
    $pdb_httpspy = "\\bin\\httpSpy.pdb"
        
    $code = {0f 57 c0 4? 89 7? ?? 33 c0 c7 4? ?? 68 00 00 00 0f 11 4? ?? c7 4? ?? 01 00 00 00 66 4? 89 7? 00 0f 11 4? ?? 4? 89 4? ?? 0f 11 4? ?? c7 44 ?? ?? 53 71 80 60 0f 11 4? ?? c7 44 ?? ?? 71 79 7c 5c 0f 11 4? ?? c7 44 ?? ?? 6d 80 74 63 0f 11 4? ?? 88 44 ?? ?? 0f 11 4? ?? 0f 1f 44 00 00}

condition:
    uint16(0) == 0x5A4D and (
    $cmd or (2 of ($str_*)) or
    any of ($pdb_*) or $code
    )
}
rule RokRAT
{
    meta:
        id = "6PTZ4h1MQZlpQcitAdTFRh"
        fingerprint = "v1_sha256_9a421d0257276c98d57abdaeb1e31e98956ec8ecf97d48827b35b527d174f35e"
        version = "1.0"
        modified = "2024-03-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RokRAT."
        category = "MALWARE"
        malware_type = "RAT"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rokrat"

strings:
    $new_pe = {0f b6 03 8d 4b 05 03 c8 89 4? ?? 8b 44 18 01 89 4? ?? 8d ?? 98 f4 ff ff 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d ?? 98 f4 ff ff 4f 8a 
    4? ?? 47 84 c0 75 ?? 8b 5? ?? be ?? ?? ?? ?? 33 c0 8b c8 a5 a5 a5 a5 a4 8b 7? ?? 85 d2 74 ?? 8a 26 8a 04 31 32 c4 34 ?? 88 04 31 41 3b ca}

    $str_1 = "%s%04X%04X.tmp" ascii wide
    $str_2 = "360Tray.exe" ascii wide
    $str_3 = "dir /A /S %s >> \"%%temp%%/%c_.TMP\"" ascii wide
    $str_4 = "KB400928_doc.exe" ascii wide
    $str_5 = "\\%d.dat" ascii wide
    $str_6 = "%spid:%d,name:%s,path:%s%s" ascii wide
    $str_7 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" ascii wide

    $comms_1 = "127.0.0.1" ascii wide
    $comms_2 = "api.pcloud.com" ascii wide
    $comms_3 = "my.pcloud.com" ascii wide
    $comms_4 = "cloud-api.yandex.net" ascii wide
    $comms_5 = "api.dropboxapi.com" ascii wide
    $comms_6 = "content.dropboxapi.com" ascii wide
    $comms_7 = "Content-Type: voice/mp3" ascii wide

condition:
    $new_pe or 
    4 of ($str_*) or 
    (6 of ($comms_*) and 2 of ($str_*))
}
rule RoyalRoad_RTF
{
    meta:
        id = "4PK9Mv5Sh0CuKYy79p2xJw"
        fingerprint = "v1_sha256_635f144894089c0e6e122955535052f61f8a2e708a67442f41f5f60078fe210b"
        version = "1.0"
        date = "2020-01-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RoyalRoad RTF, used by multiple China-based APT groups."
        category = "MALWARE"
        malware = "ROYALROAD"
        malware_type = "EXPLOITKIT"
        reference = "https://nao-sec.org/2020/01/an-overhead-view-of-the-royal-road.html"
        first_imported = "2021-12-30"

    strings:
        $rtf = "{\\rt"
        $RR1 = "5C746D705C382E74" nocase
        $RR2 = "5C417070446174615C4C6F63616C5C54656D705C382E74" nocase

    condition:
        $rtf at 0 and any of ($RR*)
}
rule Andromeda
{
    meta:
        id = "68kfxFxiGY1pDE7QNLIco6"
        fingerprint = "v1_sha256_070e3649444fbb25864cad08265961485bb086654dff66fc739211567a78667a"
        version = "1.0"
        date = "2021-03-01"
        modified = "2022-01-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Andromeda aka Gamarue botnet."
        category = "MALWARE"
        malware = "ANDROMEDA"
        malware_type = "WORM"
        mitre_att = "S1074"
        first_imported = "2022-01-24"

    strings:
        //IndexerVolumeGuid
        $ = { 8d ?? dc fd ff ff 50 8d ?? d8 fd ff ff 50 e8 ?? ?? ?? ?? 8a 00 53 68 ?? ?? ?? ?? 56
    ff b? ?? ?? ?? ?? a2 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 18 53 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53
    53 ff 15 ?? ?? ?? ?? ff b? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 f8
    ff 74 ?? 6a 01 50 ff 15 ?? ?? ?? ?? }
        $ = { 83 c4 10 ff b? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff b? ?? ?? ?? ?? ff b?
    ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? }


        /*
        MOV        DL ,byte ptr SS :[EAX  + EBP *0x1  + 0xffffff00 ]
        MOV        DH ,byte ptr SS :[EBX  + EBP *0x1  + 0xffffff00 ]
        MOV        byte ptr SS :[EAX  + EBP *0x1  + 0xffffff00 ],DH
        MOV        byte ptr SS :[EBX  + EBP *0x1  + 0xffffff00 ],DL
        */
        $ = { 36 8a 94 28 00 ff ff ff 02 da 36 8a b4 2b 00 ff ff ff 36 88 b4 28 00 ff ff ff 36 88 94 2b 00 ff ff ff }

    condition:
        any of them
}
rule ArechClient
{
    meta:
        id = "2DxUPwuC8wLKolxJABa5xS"
        fingerprint = "v1_sha256_c27d6917e4a528efcbcd378e7c53103cac2747e3239b81e15d68afbdd251b764"
        version = "1.0"
        date = "2021-07-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ArechClient, infostealer."
        category = "MALWARE"
        malware = "ARECHCLIENT"
        malware_type = "INFOSTEALER"
        mitre_att = "S1074"
        first_imported = "2021-12-30"

    strings:
        $ = "is_secure" ascii wide
        $ = "encrypted_value" ascii wide
        $ = "host_keyexpires_utc" ascii wide

    condition:
        all of them
}import "dotnet"

rule ArechClient_Campaign_July2021
{
    meta:
        id = "5uq90Gf5NQGy9E26EVyUrN"
        fingerprint = "v1_sha256_b1683ce6fc9cba94730f734cab3c1028ec4f035f17f5bf42628a8873a3cbe67e"
        version = "1.0"
        date = "2021-07-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ArechClient stealer's July 2021 campaign."
        category = "MALWARE"
        malware = "ARECHCLIENT"
        malware_type = "INFOSTEALER"
        mitre_att = "S1074"
        reference = "https://twitter.com/bcrypt/status/1420471176137113601"
        first_imported = "2021-12-30"

    condition:
        dotnet.guids[0]=="10867a7d-8f80-4d52-8c58-47f5626e7d52" or dotnet.guids[0]=="7596afea-18b9-41f9-91dd-bee131501b08"
}rule AuroraStealer
{
    meta:
        id = "T1xBscsuEOC59yEI3JpxC"
        fingerprint = "v1_sha256_9ecee6f64e3c6b1e1027c50686c7a6ec8dd323f3925cc13ab51090ccaea39cf3"
        version = "1.0"
        modified = "2024-08-14"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Aurora Stealer."
        category = "MALWARE"
        malware = "AURORA STEALER"
        mitre_att = "S1074"
        reference = " https://malpedia.caad.fkie.fraunhofer.de/details/win.aurora_stealer"
        first_imported = "2023-05-26"

strings:
    $ = "main.base64Decode" ascii wide
    $ = "main.base64Encode" ascii wide
    $ = "main.Capture" ascii wide
    $ = "main.CaptureRect" ascii wide
    $ = "main.compresss" ascii wide
    $ = "main.ConnectToServer" ascii wide
    $ = "main.countupMonitorCallback" ascii wide
    $ = "main.CreateImage" ascii wide
    $ = "main.enumDisplayMonitors" ascii wide
    $ = "main.FileExsist" ascii wide
    $ = "main.getCPU" ascii wide
    $ = "main.getDesktopWindow" ascii wide
    $ = "main.GetDisplayBounds" ascii wide
    $ = "main.getGPU" ascii wide
    $ = "main.GetInfoUser" ascii wide
    $ = "main.getMasterKey" ascii wide
    $ = "main.getMonitorBoundsCallback" ascii wide
    $ = "main.getMonitorRealSize" ascii wide
    $ = "main.GetOS" ascii wide
    $ = "main.Grab" ascii wide
    $ = "main.MachineID" ascii wide
    $ = "main.NumActiveDisplays" ascii wide
    $ = "main.SendToServer_NEW" ascii wide
    $ = "main.SetUsermame" ascii wide
    $ = "main.sysTotalMemory" ascii wide
    $ = "main.xDecrypt" ascii wide
    $ = "type..eq.main.Browser_G" ascii wide
    $ = "type..eq.main.Crypto_G" ascii wide
    $ = "type..eq.main.DATA_BLOB" ascii wide
    $ = "type..eq.main.FileGrabber_G" ascii wide
    $ = "type..eq.main.FTP_G" ascii wide
    $ = "type..eq.main.Grabber" ascii wide
    $ = "type..eq.main.ScreenShot_G" ascii wide
    $ = "type..eq.main.Steam_G" ascii wide
    $ = "type..eq.main.STRUSER" ascii wide
    $ = "type..eq.main.Telegram_G" ascii wide
    
condition:
    25 of them
}
rule AveMaria
{
    meta:
        id = "7PsKBye7qnMOy7Ago07Msa"
        fingerprint = "v1_sha256_79a162e7233998aa93bbc8a1f6252798c11de6dbdc7fb66e3e86c60dc7b289ff"
        version = "1.0"
        date = "2020-11-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies AveMaria aka WarZone RAT."
        category = "MALWARE"
        malware = "WARZONERAT"
        malware_type = "RAT"
        mitre_att = "S0534"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "AVE_MARIA" ascii wide
        $ = "Ave_Maria Stealer OpenSource" ascii wide
        $ = "Hey I'm Admin" ascii wide
        $ = "WM_DISP" ascii wide fullword
        $ = "WM_DSP" ascii wide fullword
        $ = "warzone160" ascii wide

    condition:
        3 of them
}rule BazarBackdoor
{
    meta:
        id = "2IIdsjC5brejnaAj2BSm1z"
        fingerprint = "v1_sha256_63793893da9826c47b47803b153c31c29d02df92f660c0f83c8156f29d58afc8"
        version = "1.0"
        date = "2020-04-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Bazar backdoor."
        category = "MALWARE"
        malware = "BAZAR BACKDOOR"
        malware_type = "BACKDOOR"
        mitre_att = "S0534"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://www.bleepingcomputer.com/news/security/bazarbackdoor-trickbot-gang-s-new-stealthy-network-hacking-malware/"
        first_imported = "2021-12-30"

    strings:
        $ = {c7 44 ?? ?? 6d 73 67 3d c7 44 ?? ?? 6e 6f 20 66 c7 44 ?? ?? 69 6c 65 00}
        $ = {c7 44 ?? ?? 43 4e 20 3d 4? 8b f1 4? 89 b? ?? ?? ?? ?? 33 d2 4? 89 b? ?? ?? ?? ?? 4? 8d ?? ?4 60 4? 89 b? ?? ?? ?? ?? 4? 8d 7f 10 c7 44 ?? ?? 20 6c 6f 63 4? 8b c7 c7 44 ?? ?? 61 6c 68 6f 4? 8b df 66 c7 44 ?? ?? 73 74}

    condition:
        any of them
}
rule BazarLoader
{
    meta:
        id = "5prUAia2or9moey53nQjoZ"
        fingerprint = "v1_sha256_cb33564a9bcb1e11a7e33b08ad87220fde6e17b253d7a1db60e53e84ab296601"
        version = "1.0"
        date = "2020-04-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies BazarLoader."
        category = "MALWARE"
        malware = "BAZARLOADER"
        malware_type = "LOADER"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://www.bleepingcomputer.com/news/security/bazarbackdoor-trickbot-gang-s-new-stealthy-network-hacking-malware/"
        first_imported = "2021-12-30"

    strings:
        $code = {4? 89 05 69 8f 03 00 4? 85 c0 0f 84 e3 fe ff ff 4? 8b 05 01 e3 02 00 4? 89 85 e0 00 00 00 4? 8b 05 fb 
    e2 02 00 4? 89 85 e8 00 00 00 4? c7 85 d0 00 00 00 0f 00 00 00 4? 89 a5 c8 00 00 00 4? 88 a5 b8 00 00 00 4? 8d 
    44 ?4 40 4? 8d 15 77 e2 02 00 4? 8d 8d b8 00 00 00 e8 ca df ff ff 90 4? c7 45 58 0f 00 00 00 4? 89 65 50 4? 88 
    65 40 4? 8d 44 ?4 07 4? 8d 15 36 e2 02 00 4? 8d 4d 40 e8 a4 df ff ff 90 4? c7 45 08 0f 00 00 00 4? 89 65 00 4? 
    88 65 f0 4? 8d 44 ?4 0b 4? 8d 15 00 e2 02 00}
        $pdb1 = "C:\\Users\\User\\Desktop\\2010\\14.4.20\\Test_64\\SEED\\Release\\SEED.pdb" ascii
        $pdb2 = "D:\\projects\\source\\repos\\7\\bd7 v2\\Bin\\x64\\Release_nologs\\bd7_x64_release_nologs.pdb" ascii

    condition:
        $code or any of ($pdb*)
}
rule BroEx
{
    meta:
        id = "5Fg4240bgYFjN0bIREWHHi"
        fingerprint = "v1_sha256_fa2d509de97bc1f64cbd8bf0563a80af331f681298d1a0a95689b528b329cf1a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Detects BroEx, a type of agressive adware."
        category = "MALWARE"
        malware = "BROEX"
        malware_type = "ADWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        hash = "7f103012a143b9e358087cf94dbdd160362a57e5ebc65c560e352ac7541bd80e"
        first_imported = "2023-09-18"

strings:
    //PDB
    $pdb = "I:\\Repository2\\test\\Project21\\event\\Release\\event.pdb"
    
    //Mutants
    $mut1 = "Global\\A6A161D8-150E-46A1-B7EC-18E4CB58C6D2" ascii wide
    $mut2 = "Global\\D80D9D78-BCDA-482C-98F2-C38991A8CA3" ascii wide
    $mut3 = "Global\\8D13D07B-A758-456A-A215-0518F1268C2A" ascii wide
    
    //Launch
    $browser1 = "main -c rbrowser chrome" ascii wide
    $browser2 = "main -c rbrowser msedge" ascii wide
    
    //Service names
    $svc1 = "WimsysUpdaterService" ascii wide
    $svc2 = "WimsysService" ascii wide
    $svc3 = "WimsysServiceX64" ascii wide
    
    /*
    pvVar1 = (void *)0x0;
    param_1[3] = (void *)0x7;
    param_1[2] = (void *)0x0;
    *(undefined2 *)param_1 = 0;
    if (*(short *)param_2 != 0) {
    pvVar1 = (void *)0xffffffffffffffff;
    */
    $str_decode = {4? 53 4? 83 ec 20 4? 33 c0 4? c7 41 18 07 00 00 00 4? 8b d9 4? 89 41 10 66 4? 89 01 66 4? 39 02 74 11 4? 83 c8 ff}

condition:
    uint16(0) == 0x5a4d and ($pdb or 2 of ($mut*) or all of ($browser*) 
    or 2 of ($svc*) or $str_decode)
}
rule CrunchyRoll
{
    meta:
        id = "2o1i1HmCEzkOS9sYy0NCIs"
        fingerprint = "v1_sha256_f2726a4e9e74fa7c91630dd85fb92102ba789d36170c7d42f234e77bd7f9dbdd"
        version = "1.0"
        date = "2019-11-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies malware used in CrunchyRoll website hack."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://bartblaze.blogspot.com/2017/11/crunchyroll-hack-delivers-malware.html"
        first_imported = "2021-12-30"

    strings:
        $ = "C:\\Users\\Ben\\Desktop\\taiga-develop\\bin\\Debug\\Taiga.pdb"
        $ = "c:\\users\\ben\\source\\repos\\svchost\\Release\\svchost.pdb"

    condition:
        any of them
}
rule Ganelp
{
    meta:
        id = "6AotPIhdiXpDfG4MjBkMrI"
        fingerprint = "v1_sha256_65da5334f693b344e8e40dc550f54e240491d505555399b49b5d257748fb5246"
        version = "1.0"
        date = "2021-06-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Ganelp, a worm that also spreads via USB."
        category = "MALWARE"
        malware = "GANELP"
        malware_type = "WORM"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "regardez cette photo :D %s" ascii wide
        $ = "to fotografiu :D %s" ascii wide
        $ = "vejte se na mou fotku :D %s" ascii wide
        $ = "bekijk deze foto :D %s" ascii wide
        $ = "spojrzec na to zdjecie :D %s" ascii wide
        $ = "bu resmi bakmak :D %s" ascii wide
        $ = "dette bildet :D %s" ascii wide
        $ = "seen this?? :D %s" ascii wide
        $ = "guardare quest'immagine :D %s" ascii wide
        $ = "denna bild :D %s" ascii wide
        $ = "olhar para esta foto :D %s" ascii wide
        $ = "uita-te la aceasta fotografie :D %s" ascii wide
        $ = "pogledaj to slike :D %s" ascii wide
        $ = "poglej to fotografijo :D %s" ascii wide
        $ = "dette billede :D %s" ascii wide

    condition:
        3 of them
}rule IcedID_init_loader
{
    meta:
        id = "1REpyN86rLP20fpDVcYIul"
        fingerprint = "v1_sha256_c74f5b33b5ded5e298c2bab913d1f8d794365445a6efc2b9b39401867a41256f"
        version = "1.0"
        date = "2021-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IcedID (stage 1 and 2, initial loaders)."
        category = "MALWARE"
        malware = "ICEDID"
        malware_type = "LOADER"
        mitre_att = "S0483"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $s1 = "{%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X}" ascii wide
        $s2 = "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X" ascii wide
        $s3 = "/image/?id=%0.2X%0.8X%0.8X%s" ascii wide
        $x1 = "; _gat=" ascii wide
        $x2 = "; _ga=" ascii wide
        $x3 = "; _u=" ascii wide
        $x4 = "; __io=" ascii wide
        $x5 = "; _gid=" ascii wide
        $x6 = "Cookie: __gads=" ascii wide

    condition:
        int16(0) == 0x5a4d
        and 2 of ($s*) or 3 of ($x*)
}

rule IcedID_core_loader
{
    meta:
        id = "44C0TB2rXgyB69MSCvFwbl"
        fingerprint = "v1_sha256_0bda0730e1185bc294e3d5c14861041f8ff491add75265a49b48cbb5cad4bfcf"
        version = "1.0"
        date = "2021-07-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IcedID core loader."
        category = "MALWARE"
        malware = "ICEDID"
        malware_type = "LOADER"
        mitre_att = "S0483"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $code = {4? 33 d2 4? 85 f6 0f 84 ?? ?? ?? ?? 4? 83 fe 04 0f 
    82 ?? ?? ?? ?? 4? 83 c6 fc 4? 89 74 ?? ?? 4? 85 db 75 ?? 4? 
    85 f6 0f 84 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4? 8b c8 4? 8d 46 
    01 8d 53 08 ff 15 ?? ?? ?? ?? 4? 89 44 ?? ?? 4? 8b d8 4? 85 
    c0 0f 84 ?? ?? ?? ?? 4? 8b b? ?? ?? ?? ?? 4? ba 01 00 00 00}

    condition:
        $code
}
rule JSSLoader
{
    meta:
        id = "37sBGTnEOxlG96iAHQtMMA"
        fingerprint = "v1_sha256_a9a0e1512eadf41b0d6e5f3edcda74ef4f9c96e96fa4760b3e5ca27f9c25e025"
        version = "1.0"
        date = "2021-06-01"
        modified = "2025-02-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies FIN7's JSSLoader."
        category = "MALWARE"
        malware = "JSSLOADER"
        malware_type = "LOADER"
        mitre_att = "S0648"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $s1 = "desktop_file_list" ascii wide fullword
        $s2 = "adinfo" ascii wide fullword
        $s3 = "no_ad" ascii wide fullword
        $s4 = "adinformation" ascii wide fullword
        $s5 = "part_of_domain" ascii wide fullword
        $s6 = "pc_domain" ascii wide fullword
        $s7 = "pc_dns_host_name" ascii wide fullword
        $s8 = "pc_model" ascii wide fullword
        $x1 = "/?id=" ascii wide
        $x2 = "failed start exe" ascii wide
        $x3 = "Sending timer request failed, error code" ascii wide
        $x4 = "Internet connection failed, error code" ascii wide
        $x5 = "Sending initial request failed, error code" ascii wide

    condition:
        filesize <200KB and (all of ($s*) or 3 of ($x*))
}
rule Jupyter
{
    meta:
        id = "4WHjCRKha13Ck1krBl8GcH"
        fingerprint = "v1_sha256_dbbafd2d6dee6dae67be2a1d20e7dc373122e44f154549af9e937e6f6bb23650"
        version = "1.0"
        date = "2021-06-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Jupyter aka SolarMarker, backdoor."
        category = "MALWARE"
        malware = "SOLARMARKER"
        malware_type = "BACKDOOR"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "var __addr__=" ascii wide
        $ = "var __hwid__=" ascii wide
        $ = "var __xkey__=" ascii wide
        $ = "solarmarker.dat" ascii wide

    condition:
        3 of them
}rule KeyBase
{
    meta:
        id = "5IStCVPnrWTlxmqvvTkQ1b"
        fingerprint = "v1_sha256_adf1e8f28263a202e77006133da8f406139a85bdf43ad9360199ebdcf656e0e2"
        version = "1.0"
        date = "2019-02-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies KeyBase aka Kibex."
        category = "MALWARE"
        malware = "KEYBASE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        hash = "cafe2d12fb9252925fbd1acb9b7648d6"
        first_imported = "2021-12-30"

    strings:
        $s1 = " End:]" ascii wide
        $s2 = "Keystrokes typed:" ascii wide
        $s3 = "Machine Time:" ascii wide
        $s4 = "Text:" ascii wide
        $s5 = "Time:" ascii wide
        $s6 = "Window title:" ascii wide
        $x1 = "&application=" ascii wide
        $x2 = "&clipboardtext=" ascii wide
        $x3 = "&keystrokestyped=" ascii wide
        $x4 = "&link=" ascii wide
        $x5 = "&username=" ascii wide
        $x6 = "&windowtitle=" ascii wide
        $x7 = "=drowssap&" ascii wide
        $x8 = "=emitenihcam&" ascii wide

    condition:
        uint16(0)==0x5a4d and (5 of ($s*) or 6 of ($x*) or (3 of ($s*) and 3 of ($x*)))
}rule LNKR_JS_a
{
    meta:
        id = "39e03y18RtacpUoodtSmYv"
        fingerprint = "v1_sha256_bc3dee27e7a3579524ede10f5e1ccfe673a1e6b23a728992760dabe48ef03674"
        version = "1.0"
        date = "2021-04-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "AMZN_SEARCH" ascii wide
        $ = "BANNER_LOAD" ascii wide
        $ = "CB_FSI_ANSWER" ascii wide
        $ = "CB_FSI_BLIND_NO_URL" ascii wide
        $ = "CB_FSI_BREAK" ascii wide
        $ = "CB_FSI_DISPLAY" ascii wide
        $ = "CB_FSI_DO_BLIND" ascii wide
        $ = "CB_FSI_ERROR_EXCEPTION" ascii wide
        $ = "CB_FSI_ERROR_PARSERESULT" ascii wide
        $ = "CB_FSI_ERROR_TIMEOUT" ascii wide
        $ = "CB_FSI_ERR_INVRELINDEX" ascii wide
        $ = "CB_FSI_ERR_INV_BLIND_POS" ascii wide
        $ = "CB_FSI_FUSEARCH" ascii wide
        $ = "CB_FSI_FUSEARCH_ORGANIC" ascii wide
        $ = "CB_FSI_INJECT_EMPTY" ascii wide
        $ = "CB_FSI_OPEN" ascii wide
        $ = "CB_FSI_OPTOUTED" ascii wide
        $ = "CB_FSI_OPTOUT_DO" ascii wide
        $ = "CB_FSI_ORGANIC_RESULT" ascii wide
        $ = "CB_FSI_ORGANIC_SHOW" ascii wide
        $ = "CB_FSI_ORGREDIR" ascii wide
        $ = "CB_FSI_SKIP" ascii wide
        $ = "MNTZ_INJECT" ascii wide
        $ = "MNTZ_LOADED" ascii wide
        $ = "OPTOUT_SHOW" ascii wide
        $ = "PROMO_ANLZ" ascii wide
        $ = "URL_IGNOREDOMAIN" ascii wide
        $ = "URL_STATICFILE" ascii wide

    condition:
        5 of them
}

rule LNKR_JS_b
{
    meta:
        id = "y4hJYcvvTv51YlCVBOAfj"
        fingerprint = "v1_sha256_33b31f8f10a36de4f67fad29ce835310c34e28931af509b5afc021a9b3e1e076"
        version = "1.0"
        date = "2021-04-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "StartAll ok" ascii wide
        $ = "dexscriptid" ascii wide
        $ = "dexscriptpopup" ascii wide
        $ = "rid=LAUNCHED" ascii wide

    condition:
        3 of them
}

rule LNKR_JS_c
{
    meta:
        id = "ZFNYiUJohPi8LbqoFkQWh"
        fingerprint = "v1_sha256_cbee9929be2a14995e8c1b9e9210b59c95e369bf6cb1c0890f368dfc15036068"
        version = "1.0"
        date = "2021-04-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "var affid" ascii wide
        $ = "var alsotry_enabled" ascii wide
        $ = "var boot_time" ascii wide
        $ = "var checkinc" ascii wide
        $ = "var dom" ascii wide
        $ = "var fsgroup" ascii wide
        $ = "var gcheckrunning" ascii wide
        $ = "var kodom" ascii wide
        $ = "var last_keywords" ascii wide
        $ = "var trkid" ascii wide
        $ = "var uid" ascii wide
        $ = "var wcleared" ascii wide

    condition:
        3 of them
}

rule LNKR_JS_d
{
    meta:
        id = "6tMKKI41sc1XzqtSZH6q9G"
        fingerprint = "v1_sha256_b0e337c56ea7bf25f898f751f59e02842eb920818127fbfd78b16574802776c0"
        version = "1.0"
        date = "2021-04-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "adTrack" ascii wide
        $ = "addFSBeacon" ascii wide
        $ = "addYBeacon" ascii wide
        $ = "algopopunder" ascii wide
        $ = "applyAdDesign" ascii wide
        $ = "applyGoogleDesign" ascii wide
        $ = "deleteElement" ascii wide
        $ = "fixmargin" ascii wide
        $ = "galgpop" ascii wide
        $ = "getCurrentKw" ascii wide
        $ = "getGoogleListing" ascii wide
        $ = "getParameterByName" ascii wide
        $ = "getXDomainRequest" ascii wide
        $ = "googlecheck" ascii wide
        $ = "hasGoogleListing" ascii wide
        $ = "insertAfter" ascii wide
        $ = "insertNext" ascii wide
        $ = "insertinto" ascii wide
        $ = "isGoogleNewDesign" ascii wide
        $ = "moreReq" ascii wide
        $ = "openInNewTab" ascii wide
        $ = "pagesurf" ascii wide
        $ = "replaceRel" ascii wide
        $ = "sendData" ascii wide
        $ = "sizeinc" ascii wide
        $ = "streamAds" ascii wide
        $ = "urlcleanup" ascii wide

    condition:
        10 of them
}rule Monero_Compromise
{
    meta:
        id = "fb9wBtXlDWNnlyAM3obJ4"
        fingerprint = "v1_sha256_4d61c3f53734cb6184265168011457314536a630aa7fe0f664abc11a082d795d"
        version = "1.0"
        date = "2019-11-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies compromised Monero binaries."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://bartblaze.blogspot.com/2019/11/monero-project-compromised.html"
        first_imported = "2021-12-30"

    strings:
        $ = "ZN10cryptonote13simple_wallet9send_seedERKN4epee15wipeable_stringE" ascii wide
        $ = "ZN10cryptonote13simple_wallet10send_to_ccENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES6_i" ascii wide
        $ = "node.xmrsupport.co" ascii wide
        $ = "node.hashmonero.com" ascii wide

    condition:
        any of them
}rule OfflRouter
{
    meta:
        id = "7AgDTHXrtxLEyClfH1YUrb"
        fingerprint = "v1_sha256_f5b689daf5def4df3289a6d468c3b5570cd88babe22edfafee016cb06339e2a7"
        version = "1.0"
        date = "2022-01-01"
        modified = "2022-01-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies OfflRouter, malware which spreads to Office documents and removable drives."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://www.csirt.gov.sk/wp-content/uploads/2021/08/analysis_offlrouter.pdf"
        first_imported = "2022-01-24"

    strings:
        /*
        Dim num As Long = 0L
        Dim num2 As Long = CLng((Bytes.Length - 1))
        For num3 As Long = num To num2
        Bytes(CInt(num3)) = (Bytes(CInt(num3)) Xor CByte(((num3 + CLng(Bytes.Length) + 1L) Mod &H100L)))
        */
        $ = { 16 6A 02 50 8E B7 17 59 6A 0B 0A 2B 22 02 50 06 69 02 50 06 69 91 06 02 50 8E B7 6A 58 17 6A 58 20 00 01 00 00 6A 5D D2 61 9C 06 17 6A 58 0A 06 07 }

    condition:
        all of them
}
rule Parallax
{
    meta:
        id = "51wzFlWF5KwC6EGP4TznBr"
        fingerprint = "v1_sha256_fdc387f27fbc62457ec1ac3007dd37a2e9c320e229bd5003d0a36954e5ccd4e2"
        version = "1.0"
        date = "2020-09-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Parallax RAT."
        category = "MALWARE"
        malware = "PARALLAX"
        malware_type = "RAT"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = ".DeleteFile(Wscript.ScriptFullName)" ascii wide
        $ = ".DeleteFolder" ascii wide fullword
        $ = ".FileExists" ascii wide fullword
        $ = "= CreateObject" ascii wide fullword
        $ = "Clipboard Start" ascii wide fullword
        $ = "UN.vbs" ascii wide fullword
        $ = "[Alt +" ascii wide fullword
        $ = "[Clipboard End]" ascii wide fullword
        $ = "[Ctrl +" ascii wide fullword

    condition:
        3 of them
}rule Prometei_Main
{
    meta:
        id = "5Hsx9gaJnME4yPHKDd1VHu"
        fingerprint = "v1_sha256_132de5fa201511ebea231400b98ee5b33e73402a419bb1d48d703590942649bf"
        version = "1.0"
        modified = "2023-03-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Prometei botnet main modules."
        category = "MALWARE"
        malware = "PROMETEI"
        malware_type = "BOT"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"
        first_imported = "2023-03-24"

  strings:
    $ = "prometeicmd" ascii wide fullword
    $ = "/cgi-bin/prometei.cgi" ascii wide

condition:
    any of them
}

rule Prometei_PDB
{
    meta:
        id = "6lzJU85hJOwrLZ9lYs5h2Q"
        fingerprint = "v1_sha256_4bffd0bc1b54704437d44b77c31b49c879b2b3ec218d6f2a062bcfa588b69ab6"
        version = "1.0"
        modified = "2023-03-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies debug paths for Prometei botnet."
        category = "MALWARE"
        malware = "PROMETEI"
        malware_type = "BOT"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"
        first_imported = "2023-03-24"

strings:
    $ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\walker\\/ ascii wide
    $ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\prometei\\/ ascii wide
    $ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\misc\\/ ascii wide

condition:
    any of them
}

import "dotnet"
rule Prometei_Dotnet
{
    meta:
        id = "3h770CfI4oN39gnGtMPI1I"
        fingerprint = "v1_sha256_cb002da648e0941efc93922a81a000a0dbc1d35a3954040ca3f1ecb9335b9cfe"
        version = "1.0"
        modified = "2023-03-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies dotnet modules used by Prometei botnet, specifically BlueKeep and NetHelper."
        category = "MALWARE"
        malware = "PROMETEI"
        malware_type = "BOT"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"
        first_imported = "2023-03-24"

strings:
    $crypt = {13 30 05 00 DB 00 00 00 0? 00 00 11 20 00 01 00 00 8D ?? 00 00 01 13 05 20 00 01 00 00 8D ?? 00 00 01 13 06 03 8E 69 8D ?? 00 00 01 13 07 16 0B 2B 14 11 05 07 02 07 02 8E 69 5D 91 9E 11 06 07 07 9E 07 17 58 0B 07 20 00 01 00 00 32 E4 16 16 0B 0C 2B 2A 08 11 06 07 94 58 11 05 07 94 58 20 00 01 00 00 5D 0C 11 06 07 94 13 04 11 06 07 11 06 08 94 9E 11 06 08 11 04 9E 07 17 58 0B 07 20 00 01 00 00 32 CE 16 16 0B 16 0C 0A 2B 50 06 17 58 0A 06 20 00 01 00 00 5D 0A 08 11 06 06 94 58 0C 08 20 00 01 00 00 5D 0C 11 06 06 94 13 04 11 06 06 11 06 08 94 9E 11 06 08 11 04 9E 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5D 94 0D 11 07 07 03 07 91 09 61 D2 9C 07 17 58 0B 07 03 8E 69 32 AA 11 07 2A}

condition:
    $crypt or dotnet.typelib == "daee89b2-0055-46ce-bbab-abb621d6bef1" or dotnet.typelib == "6e74992f-648e-471f-9879-70f57b73ec8d"
}

rule Prometei_Spreader
{
    meta:
        id = "6sdryfY7b2Bf6h1RKK6CqK"
        fingerprint = "v1_sha256_d15865ef61bd71931d19ddbc2f0a39e4e83289601ff93ffec7f9992749edc729"
        version = "1.0"
        modified = "2023-03-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SSH spreader used by Prometei botnet, specifically windrlver."
        category = "MALWARE"
        malware = "PROMETEI"
        malware_type = "BOT"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"
        first_imported = "2023-03-24"

strings:
    $code = {8a 01 41 84 c0 75 ?? 2b ce 8d 04 13 2b cb 03 c7 2b cf 51 50 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 83 c4 0c 33 db 8d 9b 00 00 00 00}

condition:
    $code
}
rule PureZip
{
    meta:
        id = "6kmcQ3uA3Irp1H97EqxJrD"
        fingerprint = "v1_sha256_c713faeaeb58701fd04353ef6fd17e4677da735318c43658d62242cd2ca3718d"
        version = "1.0"
        date = "2024-03-20"
        modified = "2024-03-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ZIP files with a hidden file named '__.exe', as seen in a massive PureCrypt campaign in Q1 2024."
        category = "MALWARE"
        malware = "PURE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        hash = "ff668ef41336749df82e897c36b1438da1a21b1816716b30183024a8b62342a2"
        malware_family = "INFOSTEALER"

strings:
    //This pattern is always the same. ZIP is sometimes password-protected. But typically 2 files, where __.exe is a hidden file.
    //These are all PureCrypt samples, but may drop anything from PureLogs to Agent Tesla to RedLine to...
    $exe = {5F 5F 2E 65 78 65} //__.exe

condition:
    uint16(0) == 0x4b50 and $exe in (filesize-300..filesize)
}
rule PurpleFox_a
{
    meta:
        id = "3kW4QxvMG2gi20oH7mbpag"
        fingerprint = "v1_sha256_4cd2169074abf0f4c4dd4a9eb8e3c7445c33f758fd848d82da9f55e0c039cac6"
        version = "1.0"
        date = "2021-11-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PurpleFox aka DirtyMoe botnet."
        category = "MALWARE"
        malware = "PURPLEFOX"
        malware_type = "BOT"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $movetmp = {4? 8d 4d 38 4? 8b 95 88 01 00 00 4? 8d 05 1f 01 00 00 e8 9a c8 fd ff 4? 8b 4d 38 e8 51 cc fd ff 4? 89 c1 4? 8d 55 48 e8 55 07 fe ff 4? 89 c3 4? 83 fb ff 74 74 8b 45 48 83 e0 10 83 f8 10 74 50 4? 8d 4d 30 4? 8d 55 74 4? c7 c0 04 01 00 00 4? 33 c9 e8 9a c6 fd ff 4? 8d 4d 40 4? 8b 95 88 01 00 00 4? 8b 45 30 e8 46 c8 fd ff 4? 8b 4d 40 e8 fd cb fd ff 4? 89 c1 4? 33 d2 e8 c2 09 fe ff 4? 8b 4d 40 e8 e9 cb fd ff 4? 89 c1 e8 a1 06 fe ff 4? 89 d9 4? 8d 55 48 e8 f5 06 fe ff 85 c0 75 95 4? 89 d9 e8 19 3d fe ff}

    condition:
        all of them
}

rule PurpleFox_b
{
    meta:
        id = "6z91mAmBcUiT3nVXPMkybr"
        fingerprint = "v1_sha256_8967f5e81c1a74a7365faac98ff505a28e997ebc57825d806b686bdd7c80dc37"
        version = "1.0"
        date = "2021-11-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PurpleFox aka DirtyMoe botnet."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = /dump_[A-Z0-9]{8}/ ascii wide
        $ = "cscdll.dll" ascii wide
        $ = "sens.dll" ascii wide

    condition:
        all of them
}

rule PurpleFox_c
{
    meta:
        id = "5m2ywh758Q6qSTQMKc6jIL"
        fingerprint = "v1_sha256_600d4a6424b88127741ab6cbfa17185773dd88c77b3807ff7079ed95567aeb5a"
        version = "1.0"
        date = "2021-11-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PurpleFox aka DirtyMoe botnet."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "UpProxyRandom" ascii wide
        $ = "SetServiceName" ascii wide
        $ = "DrvServiceName" ascii wide
        $ = "DriverOpenName" ascii wide
        $ = "DirLogFilePath" ascii wide
        $ = "RunPeShellPath" ascii wide
        $ = "DriverFileName" ascii wide

    condition:
        all of them
}

rule PurpleFox_Dropper
{
    meta:
        id = "7fuHhl5YeBovcWV2A6zY6P"
        fingerprint = "v1_sha256_a2a68eb61298941bf16ee42e92ff17949ae8b44d1f4a535a8185697be7666d59"
        version = "1.0"
        date = "2021-11-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PurpleFox aka DirtyMoe botnet, dropper CAB or MSI package."
        category = "MALWARE"
        malware_type = "DROPPER"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $doc = {D0 CF 11 E0}
        $cab = {4D 53 43 46}
        $s1 = "sysupdate.log" ascii wide
        $s2 = "winupdate32.log" ascii wide
        $s3 = "winupdate64.log" ascii wide

    condition:
        ($doc at 0 and all of ($s*)) or ($cab at 0 and all of ($s*))
}
rule RedLine_a
{
    meta:
        id = "1bfVICBV1LBGxyLnzyMPGx"
        fingerprint = "v1_sha256_942d59220bda93d8a231c6cc30550eb0a8582726c7ba70d7fe15815118701876"
        version = "1.0"
        date = "2021-06-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer."
        category = "MALWARE"
        malware = "REDLINE"
        malware_type = "INFOSTEALER"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "Account" ascii wide
        $ = "AllWalletsRule" ascii wide
        $ = "ArmoryRule" ascii wide
        $ = "AtomicRule" ascii wide
        $ = "Autofill" ascii wide
        $ = "BrowserExtensionsRule" ascii wide
        $ = "BrowserVersion" ascii wide
        $ = "Chrome" ascii wide
        $ = "CoinomiRule" ascii wide
        $ = "CommandLineUpdate" ascii wide
        $ = "CryptoHelper" ascii wide
        $ = "CryptoProvider" ascii wide
        $ = "DataBaseConnection" ascii wide
        $ = "DesktopMessangerRule" ascii wide
        $ = "DiscordRule" ascii wide
        $ = "DisplayHelper" ascii wide
        $ = "DownloadAndExecuteUpdate" ascii wide
        $ = "DownloadUpdate" ascii wide
        $ = "ElectrumRule" ascii wide
        $ = "EndpointConnection" ascii wide
        $ = "EthRule" ascii wide
        $ = "ExodusRule" ascii wide
        $ = "Extensions" ascii wide
        $ = "FileCopier" ascii wide
        $ = "FileScanner" ascii wide
        $ = "FileScannerArg" ascii wide
        $ = "FileScannerRule" ascii wide
        $ = "FileZilla" ascii wide
        $ = "GameLauncherRule" ascii wide
        $ = "Gecko" ascii wide
        $ = "GeoHelper" ascii wide
        $ = "GeoInfo" ascii wide
        $ = "GeoPlugin" ascii wide
        $ = "GuardaRule" ascii wide
        $ = "HardwareType" ascii wide
        $ = "IpSb" ascii wide
        $ = "IRemoteEndpoint" ascii wide
        $ = "ITaskProcessor" ascii wide
        $ = "JaxxRule" ascii wide
        $ = "NordApp" ascii wide
        $ = "OpenUpdate" ascii wide
        $ = "OpenVPNRule" ascii wide
        $ = "OsCrypt" ascii wide
        $ = "Program" ascii wide
        $ = "ProgramMain" ascii wide
        $ = "ProtonVPNRule" ascii wide
        $ = "RecordHeaderField" ascii wide
        $ = "RecoursiveFileGrabber" ascii wide
        $ = "ResultFactory" ascii wide
        $ = "ScanDetails" ascii wide
        $ = "ScannedBrowser" ascii wide
        $ = "ScannedCookie" ascii wide
        $ = "ScannedFile" ascii wide
        $ = "ScanningArgs" ascii wide
        $ = "ScanResult" ascii wide
        $ = "SqliteMasterEntry" ascii wide
        $ = "StringDecrypt" ascii wide
        $ = "SystemHardware" ascii wide
        $ = "SystemInfoHelper" ascii wide
        $ = "TableEntry" ascii wide
        $ = "TaskResolver" ascii wide
        $ = "UpdateAction" ascii wide
        $ = "UpdateTask" ascii wide
        $ = "XMRRule" ascii wide

    condition:
        45 of them
}

rule RedLine_b
{
    meta:
        id = "4ffdf5u5hBfvdQREMC8vdu"
        fingerprint = "v1_sha256_565e6cc31f06d942f84e8f4c4783b1e63e477e8b77fb5d14001ef9a24ef5d488"
        version = "1.0"
        date = "2021-10-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer."
        category = "MALWARE"
        malware = "REDLINE"
        malware_type = "INFOSTEALER"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "Account" ascii wide
        $ = "AllWallets" ascii wide
        $ = "Autofill" ascii wide
        $ = "Browser" ascii wide
        $ = "BrowserVersion" ascii wide
        $ = "Chr_0_M_e" ascii wide
        $ = "CommandLineUpdate" ascii wide
        $ = "ConfigReader" ascii wide
        $ = "DesktopMessanger" ascii wide
        $ = "Discord" ascii wide
        $ = "DownloadAndExecuteUpdate" ascii wide
        $ = "DownloadUpdate" ascii wide
        $ = "EndpointConnection" ascii wide
        $ = "Extensions" ascii wide
        $ = "FileCopier" ascii wide
        $ = "FileScanner" ascii wide
        $ = "FileScannerArg" ascii wide
        $ = "FileScanning" ascii wide
        $ = "FileSearcher" ascii wide
        $ = "FileZilla" ascii wide
        $ = "FullInfoSender" ascii wide
        $ = "GameLauncher" ascii wide
        $ = "GdiHelper" ascii wide
        $ = "GeoInfo" ascii wide
        $ = "GeoPlugin" ascii wide
        $ = "HardwareType" ascii wide
        $ = "IContract" ascii wide
        $ = "ITaskProcessor" ascii wide
        $ = "IdentitySenderBase" ascii wide
        $ = "LocalState" ascii wide
        $ = "LocatorAPI" ascii wide
        $ = "NativeHelper" ascii wide
        $ = "NordApp" ascii wide
        $ = "OpenUpdate" ascii wide
        $ = "OpenVPN" ascii wide
        $ = "OsCrypt" ascii wide
        $ = "ParsSt" ascii wide
        $ = "PartsSender" ascii wide
        $ = "RecordHeaderField" ascii wide
        $ = "ScanDetails" ascii wide
        $ = "ScanResult" ascii wide
        $ = "ScannedCookie" ascii wide
        $ = "ScannedFile" ascii wide
        $ = "ScanningArgs" ascii wide
        $ = "SenderFactory" ascii wide
        $ = "SqliteMasterEntry" ascii wide
        $ = "StringDecrypt" ascii wide
        $ = "SystemHardware" ascii wide
        $ = "SystemInfoHelper" ascii wide
        $ = "TableEntry" ascii wide
        $ = "TaskResolver" ascii wide
        $ = "UpdateAction" ascii wide
        $ = "UpdateTask" ascii wide
        $ = "WalletConfig" ascii wide

    condition:
        45 of them
}
import "dotnet"

rule RedLine_Campaign_June2021
{
    meta:
        id = "6rkknPBxc81GKug4Ynuauq"
        fingerprint = "v1_sha256_248e5ac67117dd88414aa8afc6e8868e2ba3eed543a5c0d15f42f9183f4401a0"
        version = "1.0"
        date = "2021-06-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer's June 2021 campaign."
        category = "MALWARE"
        malware = "REDLINE"
        malware_type = "INFOSTEALER"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://bartblaze.blogspot.com/2021/06/digital-artists-targeted-in-redline.html"
        first_imported = "2021-12-30"

    condition:
        dotnet.guids[0]=="a862cb90-79c7-41a9-847b-4ce4276feaeb" or dotnet.guids[0]=="a955bdf8-f5ac-4383-8f5d-a4111125a40e" or dotnet.guids[0]=="018ca516-2128-434a-b7c6-8f9a75dfc06e" or dotnet.guids[0]=="829c9056-6c93-42c2-a9c8-19822ccac0a4" or dotnet.guids[0]=="e1a702b0-dee1-463a-86d3-e6a9aa86348e" or dotnet.guids[0]=="6152d28b-1775-47e6-902f-8bdc9e2cb7ca" or dotnet.guids[0]=="111ab36c-09ad-4a3e-92b3-a01076ce68e0" or dotnet.guids[0]=="ea7dfb6d-f951-48e6-9e25-41c31080fd42" or dotnet.guids[0]=="34bca13d-abb5-49ce-8333-052ec690e01e" or dotnet.guids[0]=="1422b4dd-c4c1-4885-b204-200e83267597" or dotnet.guids[0]=="d0570d65-3998-4954-ab42-13b122f7dde5"
}rule SaintBot
{
    meta:
        id = "11hESLHbVFgVTJeUkXsMl9"
        fingerprint = "v1_sha256_641cfd3274862598f3aa107836e3546a1f26b7446bda2c1a181592aa604cfdfb"
        version = "1.0"
        date = "2022-07-29"
        modified = "2022-07-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Saint Bot malware downloader."
        category = "MALWARE"
        malware = "SAINTBOT"
        malware_type = "DOWNLOADER"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2022-07-29"

    strings:
        $ = "de:regsvr32" ascii wide
        $ = "de:LoadMemory" ascii wide
        $ = "de:LL" ascii wide
        $ = "/gate.php" ascii wide

    condition:
        all of them
}
rule ShinnyShield
{
    meta:
        id = "3Uzp4Mpgv5EPVtWv7oMO4R"
        fingerprint = "v1_sha256_4e079a9265aebe4d147e6004ab908fbc48d4e60fdb3852d4b26a141df5d01cd7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Worm that spreads via Call of Duty Modern Warfare 2, 2009 version."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://techcrunch.com/2023/07/27/hackers-are-infecting-call-of-duty-players-with-a-self-spreading-malware"
        first_imported = "2023-08-01"

strings:
    $msg_dbg1 = "Adding legitimate lobby to party list." ascii wide
    $msg_dbg2 = "Discarded QoS response from modded lobby." ascii wide
    $msg_dbg3 = "Handled join accept from " ascii wide
    $msg_dbg4 = "Handled join request from " ascii wide
    $msg_dbg5 = "Incorrect exe or mw2 version!" ascii wide
    $msg_dbg6 = "Locking the RCE to " ascii wide
    $msg_dbg7 = "Received packet from " ascii wide
    $msg_dbg8 = "Refusing to join blacklisted lobby." ascii wide
    $msg_dbg9 = "Unauthorized RCE attempt detected." ascii wide
    $msg_dbg10 = "Unknown or missing worm instruction." ascii wide
    $msg_dbg11 = "User was randomly selected to be a spreader in modded lobbies." ascii wide
    $msg_dbg12 = "User was selected to be a host/ignore modded lobbies/join unmodded lobbies only" ascii wide
    $msg_worm1 = "Worm deactivated by control server." ascii wide
    $msg_worm2 = "Worm failed to retrieve data from the control server." ascii wide
    $msg_worm3 = "Worm killed by control server." ascii wide
    $msg_worm4 = "Worm up to date." ascii wide
    $msg_worm5 = "wormStatus infected %s" ascii wide
    $msg_worm6 = "get cucked by shiny" ascii wide

    $pdb = "F:\\1337 Call Of Duty\\dxproxies\\DirectX-Wrappers\\Release\\dsound.pdb"

    $exp = "joinParty 149 1 1 0 0 0 32 0 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17"
    
condition:
    3 of ($msg_*) or $pdb or $exp
}
rule SystemBC_Socks
{
    meta:
        id = "59NpoC4gUBtxsIlxdK058n"
        fingerprint = "v1_sha256_bf329d08b43bfbb3a47f83bcf9cd066bab3bc544d7dfbd7891b0a302fcc4ff6d"
        version = "1.0"
        date = "2021-07-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SystemBC RAT, Socks proxy version."
        category = "MALWARE"
        malware = "SYSTEMBC"
        malware_type = "RAT"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $code1 = { 68 10 27 00 00 e8 ?? ?? ?? ?? 8d ?? 72 fe ff ff 50 68 02 02 00 00 e8 ?? ?? 
    ?? ?? 85 c0 75 ?? c7 8? ?? ?? ?? ?? ?? ?? ?? ?? 8d ?? 60 fe ff ff 50 6a ff 68 ?? ?? 
    ?? ?? e8 ?? ?? ?? ?? 8d ?? 60 fe ff ff 50 e8 ?? ?? ?? ?? 89 8? ?? ?? ?? ?? ff b? ?? 
    ?? ?? ?? ff b? ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 81 b? ?? ?? ?? ?? ?? ?? ?? ?? 
    75 ?? c7 8? ?? ?? ?? ?? ?? ?? ?? ?? eb ?? }
        $code2 = { 55 8b ec 81 c4 d0 fe ff ff 53 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 
    ?? ?? ?? ?? 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 4? ?? 6a 04 ff 7? ?? 8d ?? fc 50 e8 
    ?? ?? ?? ?? c7 8? ?? ?? ?? ?? 01 00 00 00 6a 04 8d ?? d4 fe ff ff 50 6a 01 6a 06 ff 
    7? ?? e8 ?? ?? ?? ?? 8d ?? d8 fe ff ff 50 6a ff ff 7? ?? e8 ?? ?? ?? ?? 6a 02 8d ?? 
    d8 fe ff ff 50 e8 ?? ?? ?? ?? 89 4? ?? 8b 4? ?? 3d 00 00 01 00 76 ?? 50 e8 ?? ?? ?? ?? }

    condition:
        any of them
}

rule SystemBC_Config
{
    meta:
        id = "5hkVsLjaTDm2U9uyQwcIo3"
        fingerprint = "v1_sha256_860147afa79053870d95a9c8b24df44846ef5d77b9c3d9b6e95b2a3e4fed9703"
        version = "1.0"
        date = "2021-07-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SystemBC RAT, decrypted config."
        category = "MALWARE"
        malware_type = "RAT"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "BEGINDATA" ascii wide fullword
        $ = "HOST1:" ascii wide fullword
        $ = "HOST2:" ascii wide fullword
        $ = "PORT1:" ascii wide fullword
        $ = "TOR:" ascii wide fullword
        $ = "-WindowStyle Hidden -ep bypass -file" ascii wide

    condition:
        3 of them
}rule Unk_BR_Banker
{
    meta:
        id = "4tw0dAoafMeYT9JoKi007r"
        fingerprint = "v1_sha256_12b79f0e66ca9d9c9508b0db0b10e506eac0def2ef6c69e7334df141b210b11e"
        version = "1.0"
        date = "2021-06-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies an unknown Brazilian banking trojan."
        category = "MALWARE"
        malware_type = "BANKER"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "<ALARME>" ascii wide
        $ = "<ALARME_G>" ascii wide
        $ = "<ALARME_R>" ascii wide
        $ = "<|LULUZDC|>" ascii wide
        $ = "<|LULUZLD|>" ascii wide
        $ = "<|LULUZLU|>" ascii wide
        $ = "<|LULUZPos|>" ascii wide
        $ = "<|LULUZRD|>" ascii wide
        $ = "<|LULUZRU|>" ascii wide
        $ = ">CRIAR_ALARME_AZUL<" ascii wide
        $ = ">ESCREVER_BOTAO_DIREITO<" ascii wide
        $ = ">REMOVER_ALARME_GRAY<" ascii wide
        $ = ">WIN_SETA_ACIMA<" ascii wide
        $ = ">WIN_SETA_BAIXO<" ascii wide
        $ = ">WIN_SETA_ESQUERDA<" ascii wide
        $ = "BOTAO_DIREITO" ascii wide

    condition:
        5 of them
}import "pe"

rule Unk_Crime_Downloader_1
{
    meta:
        id = "7QiwbleKa8Yu1VH4HdJ8rq"
        fingerprint = "v1_sha256_ec696ac2a97a03d7db427501208bbf326b79531b935f9d6e2676d5ab23148028"
        version = "1.0"
        date = "2020-10-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Unknown downloader DLL, likely used by Emotet and/or TrickBot."
        category = "MALWARE"
        malware = "EMOTET"
        malware_type = "DOWNLOADER"
        mitre_att = "S0367"
        mitre_att = "S1074"
        mitre_att = "S0670"
        hash = "3d2ca7dc3d7c0aa120ed70632f9f0a15"
        first_imported = "2021-12-30"

    strings:
        $ = "LDR.dll" ascii wide fullword
        $ = "URLDownloadToFileA" ascii wide

    condition:
        all of them or pe.imphash()=="4f8a708f1b809b780e4243486a40a465"
}rule Unk_Crime_Downloader_2
{
    meta:
        id = "6KfrG3eUBiBzjWuiaDxyTG"
        fingerprint = "v1_sha256_9e6a26d06965366eaa5c3ad98fb2b120187cfb04a935e6a82effc58b23a235f0"
        version = "1.0"
        date = "2024-03-20"
        modified = "2024-03-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies what appears to be related to PureLogs stealer, but it's likely a 2nd stage with the final stage to be downloaded."
        category = "MALWARE"
        malware = "PURELOGS"
        malware_type = "DOWNLOADER"
        mitre_att = "S1074"
        mitre_att = "S0670"
        hash = "443b3b9929156d71ed73e99850a671a89d4d0d38cc8acc7f286696dd4f24895e"

strings:
    $unc = "UNCNOWN" ascii wide fullword
    $anti_vm1 = "WINEHDISK" ascii wide fullword
    $anti_vm2 = "(VMware|Virtual|WINE)" ascii wide
    $click_1 = "TOffersPanel" ascii wide
    $click_2 = "TOfferLabel" ascii wide
    $click_3 = "TOfferCkb" ascii wide
    $campaign = "InstallComaignsThread" ascii wide
    $net_call = "/new/net_api" ascii wide

condition:
    4 of them
}
rule Unk_DesktopLoader
{
    meta:
        id = "6u9FGIKOAjfoKem1miGEiB"
        fingerprint = "v1_sha256_7fb39c978d0f957c2b6500816bac79efef3ea14458ac38d1b6d83cbaa81ad868"
        version = "1.0"
        date = "2021-08-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies implant that will decrypt and load shellcode from a blob file. Calling it DesktopLoader for now, based on the filename it seeks."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lockfile-ransomware-new-petitpotam-windows"
        first_imported = "2021-12-30"

    strings:
        $ = { 68 00 08 00 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 33 
    c9 85 c0 7e ?? ba 5c 00 00 00 8d 49 00 66 39 14 ?? ?? ?? ?? ?? 
    75 ?? 85 c9 74 ?? 49 48 85 c0 7f ?? eb ?? 33 c9 66 89 0c ?? ?? 
    ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 00 
    68 80 00 00 00 6a 03 6a 00 6a 02 68 00 00 00 80 68 ?? ?? ?? ?? 
    ff 15 ?? ?? ?? ?? 83 f8 ff 75 ?? 6a 00 ff 15 ?? ?? ?? ?? }

    condition:
        any of them
}rule ZLoader
{
    meta:
        id = "5Oiq3bAzKTmwjYS8ihDDva"
        fingerprint = "v1_sha256_207bc8222d042628427fad80c55cbbb0ab0aa439e6147753a30311c78f1c147e"
        version = "1.0"
        date = "2020-04-01"
        modified = "2022-02-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ZLoader in memory or unpacked."
        category = "MALWARE"
        malware = "ZLOADER"
        malware_type = "LOADER"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        /*
            00104bc0 89 f8           MOV        EAX,EDI
            00104bc2 8b 0d 00        MOV        ECX,dword ptr [PTR_s_#Irb4utunQPhJZjSn_0010b000] = 0010a4d0
                     b0 10 00
            00104bc8 99              CDQ
            00104bc9 f7 7d f0        IDIV       dword ptr [EBP + local_14]
            00104bcc 8b 45 08        MOV        EAX,dword ptr [EBP + param_1]
            00104bcf 0f b6 1c 11     MOVZX      EBX,byte ptr [ECX + EDX*0x1]=>s_#Irb4utunQPhJZ   = "#Irb4utunQPhJZjSn"
            00104bd3 32 1c 38        XOR        BL,byte ptr [EAX + EDI*0x1]
            00104bd6 88 1c 3e        MOV        byte ptr [ESI + EDI*0x1],BL
            00104bd9 8d 7f 01        LEA        EDI,[EDI + 0x1]
        */
        $code = { 89 f8 8b 0d ?? ?? ?? ?? 99 f7 7? ?? 8b 4? ?? 0f b6 1c ?? 32
    1c 38 88 1c 3e 8d 7f 01 74 ?? e8 ?? ?? ?? ?? 80 fb 7f 74 ?? 38 c3 7d
    ?? 80 fb 0d 77 ?? 0f b6 c3 b9 00 26 00 00 0f a3 c1 72 ?? }
        $dll = "antiemule-loader-bot32.dll" ascii wide fullword
        $s1 = "/post.php" ascii wide
        $s2 = "BOT-INFO" ascii wide
        $s3 = "Connection: close" ascii wide
        $s4 = "It's a debug version." ascii wide
        $s5 = "Proxifier is a conflict program, form-grabber and web-injects will not works. Terminate proxifier for solve this problem." ascii wide
        $s6 = "rhnbeqcuwzbsjwfsynex" ascii wide fullword

    condition:
        $code or $dll or (4 of ($s*))
}
rule AutoIT_Compiled
{
    meta:
        id = "5ariwa9e7Tk1sowwh8gQZG"
        fingerprint = "v1_sha256_cd01df1045c9ebe36bac11c89cf54c2b2e7db97b906b983bb0fd67057e76848a"
        version = "1.0"
        date = "2020-09-01"
        modified = "2023-12-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies compiled AutoIT script (as EXE). This rule by itself does NOT necessarily mean the detected file is malicious."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "#OnAutoItStartRegister" ascii wide
        $ = "#pragma compile" ascii wide
        $ = "/AutoIt3ExecuteLine" ascii wide
        $ = "/AutoIt3ExecuteScript" ascii wide
        $ = "/AutoIt3OutputDebug" ascii wide
        $ = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
        $ = ">>>AUTOIT SCRIPT<<<" ascii wide
        $ = "This is a third-party compiled AutoIt script." ascii wide

    condition:
        uint16(0)==0x5A4D and any of them
}

rule AutoIT_Script
{
    meta:
        id = "2f5rVaIF3BjlhX2tTBarRg"
        fingerprint = "v1_sha256_df27ec10d71894c424942f17735c9bcf5cc5c7651714eabc2c9d166b9c659440"
        version = "1.0"
        date = "2020-09-01"
        modified = "2023-12-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies AutoIT script.  This rule by itself does NOT necessarily mean the detected file is malicious."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "#OnAutoItStartRegister" ascii wide
        $ = "#pragma compile" ascii wide
        $ = "/AutoIt3ExecuteLine" ascii wide
        $ = "/AutoIt3ExecuteScript" ascii wide
        $ = "/AutoIt3OutputDebug" ascii wide
        $ = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
        $ = ">>>AUTOIT SCRIPT<<<" ascii wide
        $ = "This is a third-party compiled AutoIt script." ascii wide
        $ = "AU3!EA06" ascii wide

    condition:
        uint16(0)!=0x5A4D and any of them
}
import "dotnet"
rule Costura_Protobuf
{
    meta:
        id = "6jGFSWMjFuva1linNiW7iC"
        fingerprint = "v1_sha256_da84b0a5628231b790fa802d404dcebd30c39805360e619ea78c6d56cf5d3c52"
        version = "1.0"
        date = "2024-03-20"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Costura and Protobuf in .NET assemblies, respectively for storing resources and (de)serialization. Seen together might indicate a suspect binary."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference_a = "https://github.com/Fody/Costura"
        reference_b = "https://github.com/protobuf-net/protobuf-net"
        reference_c = "https://any.run/cybersecurity-blog/pure-malware-family-analysis/"

strings:
    $comp = "costura.protobuf-net.dll.compressed" ascii wide fullword
    
condition:
    dotnet.is_dotnet and $comp
}
rule DotNet_Reactor
{
    meta:
        id = "6u7Yph7jnVCngo4hDuUWch"
        fingerprint = "v1_sha256_48fafcf1cbbc618fae72666ca11cb4d4bc37fdd45e98c24053eec4d757942c46"
        version = "1.1"
        date = "2024-03-20"
        modified = "2024-04-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies .NET Reactor, which offers .NET code protection such as obfuscation, encryption and so on."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference_a = "https://www.eziriz.com/dotnet_reactor.htm"
        reference_b = "https://unprotect.it/technique/net-reactor/"

strings:
    $s1 = "{11111-22222-20001-00001}" ascii wide fullword
    $s2 = "{11111-22222-20001-00002}" ascii wide fullword
    $s3 = "{11111-22222-40001-00001}" ascii wide fullword
    $s4 = "{11111-22222-40001-00002}" ascii wide fullword
    
    //{.1.1.1.1.1.-.2.2.2.2.2.-.2.0.0.0.1.-.0.0.0.0.1.}
    $x1 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 32 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 31 00 7D}
    
    //{.1.1.1.1.1.-.2.2.2.2.2.-.2.0.0.0.1.-.0.0.0.0.2.}
    $x2 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 32 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 32 00 7D}
    
    //{.1.1.1.1.1.-.2.2.2.2.2.-.4.0.0.0.1.-.0.0.0.0.1.}
    $x3 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 34 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 31 00 7D}
    
    //{.1.1.1.1.1.-.2.2.2.2.2.-.4.0.0.0.1.-.0.0.0.0.2.}
    $x4 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 34 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 32 00 7D}

condition:
    2 of ($s*) or 2 of ($x*)
}
rule EnigmaStub
{
    meta:
        id = "6JRALW6kyZBudPAOUz5ADI"
        fingerprint = "v1_sha256_e3be34d76ffffe657b956a150d88ab07424e91e7587164c6b08904d5c9ca0bf7"
        version = "1.0"
        date = "2020-03-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Enigma packer stub."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "Enigma anti-emulators plugin - GetProcAddress" ascii wide
        $ = "Enigma anti-debugger plugin - CheckRemoteDebuggerPresent" ascii wide
        $ = "Enigma anti-debugger plugin - IsDebuggerPresent" ascii wide
        $ = "Enigma Sandboxie Detect plugin" ascii wide
        $ = "Enigma_Plugin_Description" ascii wide
        $ = "Enigma_Plugin_About" ascii wide
        $ = "Enigma_Plugin_OnFinal" ascii wide
        $ = "EnigmaProtector" ascii wide
        $ = "Enigma_Plugin_OnInit" ascii wide

    condition:
        any of them
}rule Generic_Phishing_PDF
{
    meta:
        id = "2cWVCIBoFZaOW0QSZ4jbuX"
        fingerprint = "v1_sha256_0cf774f080d3cacdc96cbbc91361ee1e939f3db5d7c771637c56e578ac3e4aba"
        version = "1.0"
        date = "2019-03-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies generic phishing PDFs."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://bartblaze.blogspot.com/2019/03/analysing-massive-office-365-phishing.html"
        first_imported = "2021-12-30"

    strings:
        $pdf = {25504446}
        $s1 = "<xmp:CreatorTool>RAD PDF</xmp:CreatorTool>"
        $s2 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"DynaPDF"

    condition:
        $pdf at 0 and all of ($s*)
}rule Hidden
{
    meta:
        id = "2nHwcr9JEgs3hedAjagml6"
        fingerprint = "v1_sha256_57531743b5a09b0d48c1371ebf635526b3a79fa4126eb4d88e734ccf70ee8d29"
        version = "1.0"
        date = "2021-11-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Hidden Windows driver, used by malware such as PurpleFox."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://github.com/JKornev/hidden"
        first_imported = "2021-12-30"

    strings:
        $ = "Hid_State" ascii wide
        $ = "Hid_StealthMode" ascii wide
        $ = "Hid_HideFsDirs" ascii wide
        $ = "Hid_HideFsFiles" ascii wide
        $ = "Hid_HideRegKeys" ascii wide
        $ = "Hid_HideRegValues" ascii wide
        $ = "Hid_IgnoredImages" ascii wide
        $ = "Hid_ProtectedImages" ascii wide
        $ = "Hid_HideImages" ascii wide

    condition:
        5 of them
}rule IEuser_author_doc
{
    meta:
        id = "12tBBWrKCuMd46f2ASugpm"
        fingerprint = "v1_sha256_b69a8546ae2764b7bf6d47af1abc54d4f5b3a273eb2c37d8a9fabfa967b4abb9"
        version = "1.0"
        date = "2020-12-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Microsoft Word documents created with the default user on IE11 test VMs, more likely to be suspicious."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/"
        first_imported = "2021-12-30"

    strings:
        $doc = {D0 CF 11 E0}
        $ieuser = {49 00 45 00 55 00 73 00 65 00 72}

    condition:
        $doc at 0 and $ieuser
}
rule ISO_exec
{
    meta:
        id = "60e0631AKCaefOc9Fkus10"
        fingerprint = "v1_sha256_ce5e70fa871b22d50875640060a50770a4483966e48d138752fdec68e6f5b977"
        version = "1.0"
        modified = "2022-07-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies execution artefacts in ISO files, seen in malware such as Bumblebee."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2022-07-29"

strings:
       $ = "\\System32\\cmd.exe" ascii wide nocase
       $ = "\\System32\\rundll32.exe" ascii wide nocase
       $ = "OSTA Compressed Unicode" ascii wide
       $ = "UDF Image Creator" ascii wide

condition:
       uint16(0) != 0x5a4d and 3 of them
}
import "math"

private rule isLNK
{
    meta:
        id = "7J3hg8ZbLMwpscLuNDRT2O"
        fingerprint = "v1_sha256_8b6155514a54081beb1568afca6de52c479aaf7d7074ff7aa55341bd305a6aa9"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Private rule identifying shortcut (LNK) files. To be used in conjunction with the other LNK rules below."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }

    condition:
        $lnk at 0
}

rule PS_in_LNK
{
    meta:
        id = "6RkaRGUzz6nKauDsvCCXq6"
        fingerprint = "v1_sha256_6b27ef757466fdb9cfa83a99ae7f18fc56ab1ef240eb6265209fabf0f5ac555c"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PowerShell artefacts in shortcut (LNK) files."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = ".ps1" ascii wide nocase
        $ = "powershell" ascii wide nocase
        $ = "invoke" ascii wide nocase
        $ = "[Convert]" ascii wide nocase
        $ = "FromBase" ascii wide nocase
        $ = "-exec" ascii wide nocase
        $ = "-nop" ascii wide nocase
        $ = "-noni" ascii wide nocase
        $ = "-w hidden" ascii wide nocase
        $ = "-enc" ascii wide nocase
        $ = "-decode" ascii wide nocase
        $ = "bypass" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Script_in_LNK
{
    meta:
        id = "6V0aP7ePM1oXhsx26IYRMX"
        fingerprint = "v1_sha256_2014a6c532fe43b3172692ac7eace82add41b1c7c060ced92290c4c84b5427b6"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies scripting artefacts in shortcut (LNK) files."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "javascript" ascii wide nocase
        $ = "jscript" ascii wide nocase
        $ = "vbscript" ascii wide nocase
        $ = "wscript" ascii wide nocase
        $ = "cscript" ascii wide nocase
        $ = ".js" ascii wide nocase
        $ = ".vb" ascii wide nocase
        $ = ".wsc" ascii wide nocase
        $ = ".wsh" ascii wide nocase
        $ = ".wsf" ascii wide nocase
        $ = ".sct" ascii wide nocase
        $ = ".cmd" ascii wide nocase
        $ = ".hta" ascii wide nocase
        $ = ".bat" ascii wide nocase
        $ = "ActiveXObject" ascii wide nocase
        $ = "eval" ascii wide nocase

    condition:
        isLNK and any of them
}

rule EXE_in_LNK
{
    meta:
        id = "3gPO7xHney18J5DOvEa85f"
        fingerprint = "v1_sha256_cfd093e44aee1224440cf8fa8e5f0d4dca66979b26060042ad2077bf69a123fc"
        version = "1.0"
        date = "2020-01-01"
        modified = "2025-02-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable artefacts in shortcut (LNK) files."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "This program" ascii wide nocase
        $ = "TVqQAA" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Archive_in_LNK
{
    meta:
        id = "3HOwT3umQISEO9KXviSV4E"
        fingerprint = "v1_sha256_1ab624a15e0f0951f264dff06da207050ef3f972dd08f15c8fb9d3195cd8ecb2"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies archive (compressed) files in shortcut (LNK) files."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = ".7z" ascii wide nocase
        $ = ".zip" ascii wide nocase
        $ = ".cab" ascii wide nocase
        $ = ".iso" ascii wide nocase
        $ = ".rar" ascii wide nocase
        $ = ".bz2" ascii wide nocase
        $ = ".tar" ascii wide nocase
        $ = ".lzh" ascii wide nocase
        $ = ".dat" ascii wide nocase
        $ = "WinRAR\\Rar.exe" ascii wide nocase
        $ = "expand" ascii wide nocase
        $ = "makecab" ascii wide nocase
        $ = "UEsDBA" ascii wide nocase
        $ = "TVNDRg" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Execution_in_LNK
{
    meta:
        id = "2MnPF8gbh8epzNcnoeL4KL"
        fingerprint = "v1_sha256_e5289b72368f8c93980fdb890b03d01f47bbab22ac909287f3313e53761499ae"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies execution artefacts in shortcut (LNK) files."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "cmd.exe" ascii wide nocase
        $ = "/c echo" ascii wide nocase
        $ = "/c start" ascii wide nocase
        $ = "/c set" ascii wide nocase
        $ = "%COMSPEC%" ascii wide nocase
        $ = "rundll32.exe" ascii wide nocase
        $ = "regsvr32.exe" ascii wide nocase
        $ = "Assembly.Load" ascii wide nocase
        $ = "[Reflection.Assembly]::Load" ascii wide nocase
        $ = "process call" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Compilation_in_LNK
{
    meta:
        id = "7XNtJ1vGRWWqmMAOYjfhKY"
        fingerprint = "v1_sha256_bf9aa7bbbef277e37c0f442d4301688e11b43b6aa8bea7f007afe7c9c59b9916"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies compilation artefacts in shortcut (LNK) files."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "vbc.exe" ascii wide nocase
        $ = "csc.exe" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Download_in_LNK
{
    meta:
        id = "WsPzmpilT8Mcr3uZGgUJQ"
        fingerprint = "v1_sha256_d005d31031b742452cc1d334538ec45201fc6faa0258c7add733b7ccd2cbe482"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies download artefacts in shortcut (LNK) files."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "bitsadmin" ascii wide nocase
        $ = "certutil" ascii wide nocase
        $ = "ServerXMLHTTP" ascii wide nocase
        $ = "http" ascii wide nocase
        $ = "ftp" ascii wide nocase
        $ = ".url" ascii wide nocase

    condition:
        isLNK and any of them
}

rule MSOffice_in_LNK
{
    meta:
        id = "528qdGxKIsNrIS7lTFn25Y"
        fingerprint = "v1_sha256_60c96389a8c0be685052a2cd5fa2237cc80e641ffe86ea552dde766ca45fa1eb"
        version = "1.0"
        date = "2020-01-01"
        modified = "2025-02-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Microsoft Office artefacts in shortcut (LNK) files."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = ".docm" ascii wide nocase
        $ = ".dotm" ascii wide nocase
        $ = ".potm" ascii wide nocase
        $ = ".ppsm" ascii wide nocase
        $ = ".pptm" ascii wide nocase
        $ = ".rtf" ascii wide nocase
        $ = ".sldm" ascii wide nocase
        $ = ".slk" ascii wide nocase
        $ = ".wll" ascii wide nocase
        $ = ".xla" ascii wide nocase
        $ = ".xlam" ascii wide nocase
        $ = ".xls" ascii wide nocase
        $ = ".xlsm" ascii wide nocase
        $ = ".xll" ascii wide nocase
        $ = ".xltm" ascii wide nocase

    condition:
        isLNK and any of them
}

rule PDF_in_LNK
{
    meta:
        id = "6CV8x5S18fd7Yx9itmQk4r"
        fingerprint = "v1_sha256_2b3c81801fbfdbb4efb0766b2d67a15219b6a511dd9ad7471894f0d389822921"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adobe Acrobat artefacts in shortcut (LNK) files."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = ".pdf" ascii wide nocase
        $ = "%PDF" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Flash_in_LNK
{
    meta:
        id = "1pzoRPb5BYV0br65qdheNi"
        fingerprint = "v1_sha256_43aa37aaba1225620ce14a4f41ecd60c8c2cf684bcde5dfe6f85def26dd0cf2f"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adobe Flash artefacts in shortcut (LNK) files."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = ".swf" ascii wide nocase
        $ = ".fws" ascii wide nocase

    condition:
        isLNK and any of them
}

rule SMB_in_LNK
{
    meta:
        id = "B6eP8nLWTbKLwu7pSrrj4"
        fingerprint = "v1_sha256_a0125a09f12581ac13a73cc42313a57cdf5ddd97cab635181316cc5b364e555c"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "NA"
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "\\c$\\" ascii wide nocase

    condition:
        isLNK and any of them
}


rule Long_RelativePath_LNK
{
    meta:
        id = "51y8o47rhOst1DImZpr3VU"
        fingerprint = "v1_sha256_5f0147d90afda3fb944fd0bb05afbe02ed89f1d3950502ff143a046d031f53ea"
        version = "1.0"
        date = "2020-01-01"
        modified = "2025-02-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file with a long relative path. Might be used in an attempt to hide the path."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "..\\..\\..\\..\\..\\..\\" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Large_filesize_LNK
{
    meta:
        id = "6Yci0Q6wQinWw9jpVOfQ8J"
        fingerprint = "v1_sha256_f771274ace07116305f09ff9e829c89385f338fbda9a9e6ce20919c1180e5f77"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file larger than 100KB. Most goodware LNK files are smaller than 100KB."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    condition:
        isLNK and filesize >100KB
}

rule High_Entropy_LNK
{
    meta:
        id = "5mgZePTcMDokg3bnl4Qfdc"
        fingerprint = "v1_sha256_dedab342b3d5d1c1c895c9b7e4eab63e28650fb8449e0e73147afcfd0d175b4e"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file with equal or higher entropy than 6.5. Most goodware LNK files have a low entropy, lower than 6."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    condition:
        isLNK and math.entropy(0, filesize )>=6.5
}

rule CDN_in_LNK
{
    meta:
        id = "5Px7DgZFehejNJopl6N2eU"
        fingerprint = "v1_sha256_acee4befbb1051b710bcee74b11f7f2210ca2eb271a5ac8211b717260c0bd786"
        version = "1.0"
        date = "2020-03-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies CDN (Content Delivery Network) domain in shortcut (LNK) file."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "cdn." ascii wide nocase
        $ = "githubusercontent" ascii wide nocase
        $ = "googleusercontent" ascii wide nocase
        $ = "cloudfront" ascii wide nocase
        $ = "amazonaws" ascii wide nocase
        $ = "akamai" ascii wide nocase
        $ = "cdn77" ascii wide nocase
        $ = "discordapp" ascii wide nocase

    condition:
        isLNK and any of them
}
rule MalScript_Tricks
{
    meta:
        id = "DmHxWnAdMC8UkbehAdSZf"
        fingerprint = "v1_sha256_9e4804eb10d3045c0b925096d2578f1b871af4fecd4d2d4c39e667b6f0624db9"
        version = "1.0"
        date = "2020-12-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies tricks often seen in malicious scripts such as moving the window off-screen or resizing it to zero."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $s1 = "window.moveTo -" nocase
        $s2 = "window.resizeTo 0" nocase
        $x1 = "window.moveTo(-" nocase
        $x2 = "window.resizeTo(" nocase

    condition:
        filesize <50KB and ( all of ($s*) or all of ($x*) )
}
rule MiniTor
{
    meta:
        id = "7dT3QbJgslsLvdag5Oz5IZ"
        fingerprint = "v1_sha256_aaf172f73bd6833b05506ec99d436492a17630ce5f582cc29d42fd421cb9d218"
        version = "1.0"
        date = "2021-03-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies MiniTor implementation as seen in SystemBC and Parallax RAT."
        category = "MALWARE"
        malware_type = "RAT"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://news.sophos.com/en-us/2020/12/16/systembc/"
        first_imported = "2021-12-30"

    strings:
        $code1 = {55 8b ec 81 c4 f0 fd ff ff 51 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 ?? ?? ?? 
        ?? 6a 0f 8d ?? 00 fe ff ff 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d ?? 0f fe ff ff 50 6a 14 ff 
        7? ?? e8 ?? ?? ?? ?? 8d ?? fc fd ff ff 50 8d ?? 00 fe ff ff 50 ff 7? ?? ff 7? ?? e8 ?? ?? 
        ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b b? ?? ?? ?? ?? 89 8? ?? ?? ?? ?? 68 ?? ?? ?? ?? ff b? ?? 
        ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 2b c7 03 f8 29 8? ?? ?? ?? ?? 68 ?? ?? 
        ?? ?? ff b? ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 74 ?? 2b c7 03 f8 29 8? ?? ?? ?? ?? 68 ?? 
        ?? ?? ?? ff b? ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 74 ?? 8b f7 83 c6 1e 8d ?? 00 fe ff ff c6}
        $code2 = {55 8b ec 81 c4 78 f8 ff ff 53 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 ?? ?? ?? 
        ?? 68 00 00 00 f0 6a 0d 68 ?? ?? ?? ?? 6a 00 8d ?? fc 50 e8 ?? ?? ?? ?? 6a 00 6a 00 8d 05 
        ?? ?? ?? ?? 5? 8d ?? f8 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 
        ff d0 6a 00 6a 00 8d 05 ?? ?? ?? ?? 5? 8d ?? f4 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? 
        ?? ?? 50 e8 ?? ?? ?? ?? ff d0 6a 00 6a 00 8d 05 ?? ?? ?? ?? 5? 8d ?? f0 50 68 ?? ?? ?? ?? 
        e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ff d0 6a 00 6a 20 8d 05 ?? ?? ?? ?? 5? 8d 
        05 ?? ?? ?? ?? 5? ff 7? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50}

    condition:
        any of them
}rule OLEfile_in_CAD_FAS_LSP
{
    meta:
        id = "7CeRkmrU1QUYTd0pvhAmYX"
        fingerprint = "v1_sha256_ccd5bf66072d0e6b31e40d79f6278c609ce5896c433f46a9914d368a8f3e2b89"
        version = "1.0"
        date = "2019-12-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies OLE files embedded in AutoCAD and related Autodesk files, quite uncommon and potentially malicious."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://blog.didierstevens.com/2019/12/16/analyzing-dwg-files-with-vba-macros/"
        first_imported = "2021-12-30"

    strings:
        $acad = {41 43 31}
        $fas = {0D 0A 20 46 41 53 34 2D 46 49 4C 45 20 3B 20 44 6F 20 6E 6F 74 20 63 68 61 6E 67 65 20 69 74 21}
        $lsp1 = "lspfilelist"
        $lsp2 = "setq"
        $lsp3 = ".lsp"
        $lsp4 = "acad.mnl"
        $ole = {D0 CF 11 E0}

    condition:
        ($acad at 0 and $ole) or ($fas at 0 and $ole) or (( all of ($lsp*)) and $ole)
}rule OneNote_BuildPath
{
    meta:
        id = "5CnUKuBFlXSTloxQ1egge0"
        fingerprint = "v1_sha256_f685bdd6dfe1428b26eb1b24b3cb35194a7b29e69777ba03088ae01d305a6cb2"
        version = "1.0"
        modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies malicious OneNote file by build path."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2023-02-02"

strings:
    //Z:\build\one\attachment.hta
    $path_0 = {5a003a005c006200750069006c0064005c006f006e0065005c006100740074006100630068006d0065006e0074002e00680074006100}
    //Z:\builder\O P E N.wsf
    $path_1 = {5a003a005c006200750069006c006400650072005c004f00200050002000450020004e002e00770073006600}

condition:
    filesize <200KB and any of them
}
import "hash"
import "pe"

rule PyInstaller
{
    meta:
        id = "53pJriB8wNwj40lonzlZNy"
        fingerprint = "v1_sha256_467ee2e27a999cc6ad0cdef852b9c675d6f02fcd2f4b3800abb0916f91728859"
        version = "1.0"
        date = "2020-01-01"
        modified = "2023-12-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable converted using PyInstaller. This rule by itself does NOT necessarily mean the detected file is malicious."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "pyi-windows-manifest-filename" ascii wide
        $ = "pyi-runtime-tmpdir" ascii wide
        $ = "PyInstaller: " ascii wide

    condition:
        uint16(0)==0x5a4d and any of them or ( for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="20d36c0a435caad0ae75d3e5f474650c"))
}
import "hash"
import "pe"

rule Rclone
{
    meta:
        id = "3QZTElvyUIk3LOYIZFpmuQ"
        fingerprint = "v1_sha256_f92c75b04f613da5a2dd396679792a6444d2514a96148ac380e10aafb928ca22"
        version = "1.0"
        date = "2021-07-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Rclone, sometimes used by attackers to exfiltrate data."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://rclone.org/"
        first_imported = "2021-12-30"

    strings:
        $ = "github.com/rclone/" ascii wide
        $ = "The Rclone Authors" ascii wide
        $ = "It copies the drive file with ID given to the path" ascii wide
        $ = "rc vfs/forget file=hello file2=goodbye dir=home/junk" ascii wide
        $ = "rc to flush the whole directory cache" ascii wide

    condition:
        any of them or for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="fc675e36c61c8b9d0b956bd05695cdda")
}
rule Specialist_Repack_Doc
{
    meta:
        id = "2aZP8f4zzUMzoe85czwgLB"
        fingerprint = "v1_sha256_e1c3fa0c03375f5551c6be98c04e6c05c423bc686609dd52f4f5b35e56a9b1b4"
        version = "1.0"
        date = "2022-01-01"
        modified = "2022-01-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Office documents created by a cracked Office version, SPecialiST RePack."
        category = "INFO"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://twitter.com/malwrhunterteam/status/1483132689586831365"
        first_imported = "2022-01-24"

    strings:
        $ = "SPecialiST RePack" ascii wide
        $ = {53 50 65 63 69 61 6C 69 53 54 20 52 65 50 61 63 6B}

    condition:
        any of them
}
rule VMProtectStub
{
    meta:
        id = "4hbuLTrJCbt8NmCS3uHre3"
        fingerprint = "v1_sha256_6a6465f37057d652bc6b2a386a0f7224d2e96b4f28ee48a1fa38a603894411bf"
        version = "1.0"
        date = "2020-05-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies VMProtect packer stub."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = ".?AV?$VirtualAllocationManager@VRealAllocationStrategy@@@@" ascii wide
        $ = ".?AVEncryptedFastDllStream@@" ascii wide
        $ = ".?AVGetBlock_CC@HardwareID@@" ascii wide
        $ = ".?AVHookManager@@" ascii wide
        $ = ".?AVIDllStream@@" ascii wide
        $ = ".?AVIGetBlock@HardwareID@@" ascii wide
        $ = ".?AVIHookManager@@" ascii wide
        $ = ".?AVIUrlBuilderSource@@" ascii wide
        $ = ".?AVIVirtualAllocationManager@@" ascii wide
        $ = ".?AVMyActivationSource@@" ascii wide

    condition:
        2 of them
}rule Webshell_in_image
{
    meta:
        id = "2Hfmxw6L30Gv9cJVOLWS46"
        fingerprint = "v1_sha256_e565b83b380f450e2148d0d5556d6f2b83526124dc5f67869a7ea70a652b670e"
        version = "1.0"
        date = "2020-01-01"
        modified = "2025-02-14"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies a webshell or backdoor in image files."
        category = "MALWARE"
        malware_type = "WEBSHELL"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $gif = {47 49 46 38 3? 61}
        $png = {89 50 4E 47 0D 0A 1A 0A}
        $jpeg = {FF D8 FF E0}
        $bmp = {42 4D}
        $s1 = "<%@ Page Language=" ascii wide
        $s2 = /<\?php[ -~]{30,}/ ascii wide nocase
        $s3 = /eval\([ -~]{30,}/ ascii wide nocase
        $s4 = /<eval[ -~]{30,}/ ascii wide nocase
        $s5 = /<%eval[ -~]{30,}/ ascii wide nocase

    condition:
        ($gif at 0 and any of ($s*)) or ($png at 0 and any of ($s*)) or ($jpeg at 0 and any of ($s*)) or ($bmp at 0 and any of ($s*))
}




rule oAuth_Phishing_PDF
{
    meta:
        id = "7FL2nghOWl1n7oP5SYzAZi"
        fingerprint = "v1_sha256_57971b1477626c7c7e3b35f4b86f13638f5ae45a3d5783d1a56105f883362184"
        version = "1.0"
        date = "2022-01-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies potential phishing PDFs that target oAuth."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://twitter.com/ffforward/status/1484127442679836676"
        first_imported = "2022-02-03"

    strings:
        $pdf = {25504446} //%PDF
        $s1 = "/URI (https://login.microsoftonline.com/common/oauth2/" nocase
        $s2 = "/URI (https://login.microsoftonline.com/consumers/oauth2" nocase
        $s3 = "/URI (https://accounts.google.com/o/oauth2" nocase

    condition:
        $pdf at 0 and any of ($s*)
}
rule Adfind
{
    meta:
        id = "3r9L5U9kKIFwBWRCoqJSnA"
        fingerprint = "v1_sha256_61c1c469012c6c5f8135fc1922db423f3d050685f0bd9879976cb0aeb2069572"
        version = "1.0"
        date = "2020-08-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adfind, a Command line Active Directory query tool."
        category = "TOOL"
        tool = "ADFIND"
        mitre_att = "S0552"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "http://www.joeware.net/freetools/tools/adfind/"
        first_imported = "2021-12-30"

    strings:
        $ = "E:\\DEV\\cpp\\vs\\AdFind\\AdFind\\AdFind.cpp" ascii wide
        $ = "adfind.cf" ascii wide
        $ = "adfind -" ascii wide
        $ = "adfind /" ascii wide
        $ = "you have encountered a STAT binary blob that" ascii wide

    condition:
        any of them
}rule CreateMiniDump
{
    meta:
        id = "44o6bzQYTVEQlqdta9AqtX"
        fingerprint = "v1_sha256_91ae892b53d9003d51c7c7ff3296344c2c67ae05045938e662a9fa4ba0cbd199"
        version = "1.0"
        date = "2021-03-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies CreateMiniDump, tool to dump LSASS."
        category = "TOOL"
        tool = "CREATEMINIDUMP"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass"
        first_imported = "2021-12-30"

    strings:
        $ = "[+] Got lsass.exe PID:" ascii wide
        $ = "[+] lsass dumped successfully!" ascii wide
        $ = { 40 55 57 4? 81 ec e8 04 00 00 4? 8d ?? ?4 40 4? 8b fc b9 3a 01 00 00 b8 cc cc cc cc f3 ab 4? 
  8b 05 ?? ?? ?? ?? 4? 33 c5 4? 89 8? ?? ?? ?? ?? c7 4? ?? 00 00 00 00 4? c7 4? ?? 00 00 00 00 4? 
  c7 44 ?? ?? 00 00 00 00 c7 44 ?? ?? 80 00 00 00 c7 44 ?? ?? 02 00 00 00 45 33 c9 45 33 c0 ba 00 
  00 00 10 4? 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4? 89 4? ?? 33 d2 b9 02 00 00 00 e8 ?? ?? ?? ?? 
  4? 89 4? ?? 4? 8d ?? 90 00 00 00 4? 8b f8 33 c0 b9 38 02 00 00 f3 aa c7 8? ?? ?? ?? ?? 38 02 00
  00 4? 8d 05 ?? ?? ?? ?? 4? 89 ?? ?? ?? ?? ?? 4? 8d ?? 90 00 00 00 4? 8b 4? ?? e8 ?? ?? ?? ?? 85 
  c0 74 ?? 4? 8d 15 ?? ?? ?? ?? 4? 8b ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 74 ?? 4? 8d ?? 90 00 
  00 00 4? 8b 4? ?? e8 ?? ?? ?? ?? 4? 8d ?? bc 00 00 00 4? 89 8? ?? ?? ?? ?? 8b 8? ?? ?? ?? ?? 89 4? ?? }

    condition:
        any of them
}import "hash"
import "pe"

rule DefenderControl
{
    meta:
        id = "6Qe6SBz5G4UVghZFivPH6P"
        fingerprint = "v1_sha256_54fd7b5200bd75fa8afbe7867aff1021c86e2ad1678b36c834fad7406101055c"
        version = "1.0"
        date = "2021-04-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Defender Control, used by attackers to disable Windows Defender."
        category = "MALWARE"
        malware = "DEFENDERCONTROL"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://www.sordum.org/9480/defender-control-v1-8/"
        first_imported = "2021-12-30"

    strings:
        $ = "www.sordum.org" ascii wide
        $ = "dControl.exe" ascii wide

    condition:
        all of them or ( for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="ff620e5c0a0bdcc11c3b416936bc661d"))
}import "pe"

rule Gmer
{
    meta:
        id = "73P9ylXrMixOQJv4q5pKk9"
        fingerprint = "v1_sha256_e4d89bcc78c93e6f0ed53dcbffce41baffca3147e1115f736f2160775b9e5c82"
        version = "1.0"
        date = "2021-07-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Gmer, sometimes used by attackers to disable security software."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "http://www.gmer.net/"
        first_imported = "2021-12-30"

    strings:
        $ = "GMER %s - %s" ascii wide
        $ = "IDI_GMER" ascii wide fullword
        $ = "E:\\projects\\cpp\\gmer\\Release\\gmer.pdb"

    condition:
        any of them
}import "pe"

rule Gmer_Driver
{
    meta:
        id = "4Z59oqlUIoVcMGhNZLcKFN"
        fingerprint = "v1_sha256_551ddfbdc0c07120ff0f04f63d940ba123083082da6453394baf9064014b9c3a"
        version = "1.0"
        date = "2021-07-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Gmer's driver, sometimes used by attackers to disable security software."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "http://www.gmer.net/"
        first_imported = "2021-12-30"

    strings:
        $ = "e:\\projects\\cpp\\gmer\\driver64\\objfre_wlh_amd64\\amd64\\gmer64.pdb"
        $ = "GMER Driver http://www.gmer.net" ascii wide

    condition:
        any of them or pe.version_info["OriginalFilename"] contains "gmer64.sys" or pe.version_info["InternalName"] contains "gmer64.sys"
}import "pe"

rule HiddenVNC
{
    meta:
        id = "4gktTPQ1aEQQCewaPABTOp"
        fingerprint = "v1_sha256_4db0b4caaceeb46142dc7baada0e4f9b7c6ea0f4fc1f207f5d75ac1dc412b884"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies HiddenVNC, which can start remote sessions."
        category = "MALWARE"
        mitre_att = "T1021.005"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "#hvnc" ascii wide
        $ = "VNC is starting your browser..." ascii wide
        $ = "HvncAction" ascii wide
        $ = "HvncCommunication" ascii wide
        $ = "hvncDesktop" ascii wide

    condition:
        2 of them or (pe.exports("VncStartServer") and pe.exports("VncStopServer"))
}rule IISRaid
{
    meta:
        id = "77UFLTMhxOu4ngB5Wyx2D9"
        fingerprint = "v1_sha256_4c39ae6852024865407e0b1f02c8b1cb6fc89290beac354bd4f66540a6437a36"
        version = "1.0"
        date = "2021-08-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IISRaid."
        category = "MALWARE"
        malware = "IISRAID"
        malware_type = "BACKDOOR"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://github.com/0x09AL/IIS-Raid"
        first_imported = "2021-12-30"

    strings:
        $pdb1 = "\\IIS-Raid-master\\" ascii wide
        $pdb2 = "\\IIS-Backdoor.pdb"
        $s1 = "C:\\Windows\\System32\\credwiz.exe" ascii wide
        $s2 = "C:\\Windows\\Temp\\creds.db" ascii wide
        $s3 = "CHttpModule::" ascii wide
        $s4 = "%02d/%02d/%04d %02d:%02d:%02d | %s" ascii wide

    condition:
        any of ($pdb*) or 3 of ($s*)
}rule Impacket
{
    meta:
        id = "6BTSuw3vt2UNLJ1nlopmb2"
        fingerprint = "v1_sha256_60ee959c906d05cdc29bf3d7788270794fa7f2994f7a12e1be18ac80e1c32923"
        version = "1.0"
        date = "2020-08-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Impacket, a collection of Python classes for working with network protocols."
        category = "TOOL"
        tool = "IMPACKET"
        mitre_att = "S0357"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://github.com/SecureAuthCorp/impacket"
        first_imported = "2021-12-30"

    strings:
        $ = "impacket.crypto" ascii wide
        $ = "impacket.dcerpc" ascii wide
        $ = "impacket.examples" ascii wide
        $ = "impacket.hresult_errors" ascii wide
        $ = "impacket.krb5" ascii wide
        $ = "impacket.nmb" ascii wide
        $ = "impacket.nt_errors" ascii wide
        $ = "impacket.ntlm" ascii wide
        $ = "impacket.smb" ascii wide
        $ = "impacket.smb3" ascii wide
        $ = "impacket.smb3structs" ascii wide
        $ = "impacket.smbconnection" ascii wide
        $ = "impacket.spnego" ascii wide
        $ = "impacket.structure" ascii wide
        $ = "impacket.system_errors" ascii wide
        $ = "impacket.uuid" ascii wide
        $ = "impacket.version" ascii wide
        $ = "impacket.winregistry" ascii wide

    condition:
        any of them
}rule KPortScan
{
    meta:
        id = "1gVPbQu7nEiXDTAw5njqI2"
        fingerprint = "v1_sha256_c45db1bac5e77a121f0f1c552640c4381364897b64bb59359de4c5b9b040fed4"
        version = "1.0"
        date = "2020-08-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies KPortScan, port scanner."
        category = "MALWARE"
        malware_type = "SCANNER"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $s1 = "KPortScan 3.0" ascii wide
        $s2 = "KPortScan3.exe" ascii wide
        $x1 = "Count of goods:" ascii wide
        $x2 = "Current range:" ascii wide
        $x3 = "IP ranges list is clear" ascii wide
        $x4 = "ip,port,state" ascii wide
        $x5 = "on_loadFinished(QNetworkReply*)" ascii wide
        $x6 = "on_scanDiapFinished()" ascii wide
        $x7 = "on_scanFinished()" ascii wide
        $x8 = "scanDiapFinished()" ascii wide
        $x9 = "scanFinished()" ascii wide
        $x10 = "with port" ascii wide
        $x11 = "without port" ascii wide

    condition:
        any of ($s*) or 3 of ($x*)
}rule LaZagne
{
    meta:
        id = "63YF1LBaSa3jA6xDbP61bx"
        fingerprint = "v1_sha256_ccc944e40198dda734403e333fb78cb1e44480d945a6ba0c7b41828cda6f23a1"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LaZagne, credentials recovery project."
        category = "TOOL"
        tool = "LAZAGNE"
        mitre_att = "S0349"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://github.com/AlessandroZ/LaZagne"
        first_imported = "2021-12-30"

    strings:
        $ = "[!] Specify a directory, not a file !" ascii wide
        $ = "lazagne.config" ascii wide
        $ = "lazagne.softwares" ascii wide
        $ = "blazagne.exe.manifest" ascii wide
        $ = "slaZagne" ascii wide fullword

    condition:
        any of them
}rule NLBrute
{
    meta:
        id = "2ZdHPVCdo7jc2o6xQPJsU1"
        fingerprint = "v1_sha256_f5585eb6605b9ff34af470f2238565e7f2b754f3484c0cced65fed77921fac1d"
        version = "1.0"
        date = "2020-08-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies NLBrute, an RDP brute-forcing tool."
        category = "TOOL"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "SERVER:PORT@DOMAIN\\USER;PASSWORD" ascii wide

    condition:
        any of them
}import "pe"

rule PowerTool
{
    meta:
        id = "58Gbim3kx5YhwwwSN8oiHg"
        fingerprint = "v1_sha256_afd6109c5ff0248cdf792ac4bf1e67928f2549f453507e7c293da25c73db7609"
        version = "1.0"
        date = "2021-07-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PowerTool, sometimes used by attackers to disable security software."
        category = "MALWARE"
        malware = "POWERTOOL"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml"
        first_imported = "2021-12-30"

    strings:
        $ = "C:\\dev\\pt64_en\\Release\\PowerTool.pdb"
        $ = "Detection may be stuck, First confirm whether the device hijack in [Disk trace]" ascii wide
        $ = "SuspiciousDevice Error reading MBR(Kernel Mode) !" ascii wide
        $ = "Modify kill process Bug." ascii wide
        $ = "Chage language nedd to restart PowerTool" ascii wide
        $ = ".?AVCPowerToolApp@@" ascii wide
        $ = ".?AVCPowerToolDlg@@" ascii wide

    condition:
        any of them
}rule RDPWrap
{
    meta:
        id = "gDfPjuYKUPgN5K0x5XkRA"
        fingerprint = "v1_sha256_23ff4de1b2a63c10b788ced3b722a1a857ec33df28d54f38da2a9793c036a78a"
        version = "1.0"
        date = "2020-05-01"
        modified = "2022-11-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RDP Wrapper, sometimes used by attackers to maintain persistence."
        category = "MALWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://github.com/stascorp/rdpwrap"
        first_imported = "2021-12-30"

    strings:
        $ = "rdpwrap.dll" ascii wide
        $ = "rdpwrap.ini" ascii wide
        $ = "RDP Wrapper" ascii wide
        $ = "RDPWInst" ascii wide
        $ = "Stas'M Corp." ascii wide
        $ = "stascorp" ascii wide

    condition:
        2 of them
}
rule Responder
{
    meta:
        id = "5V24vdPhf2fsswfU5HHbVg"
        fingerprint = "v1_sha256_33f588095d506682f1bfdfd61bff0f377149dfa8951af60755a3d2dcb16091ea"
        version = "1.0"
        date = "2020-08-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Responder, an LLMNR, NBT-NS and MDNS poisoner."
        category = "TOOL"
        tool = "RESPONDER"
        mitre_att = "S0174"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://github.com/lgandx/Responder"
        first_imported = "2021-12-30"

    strings:
        $ = "[*] [LLMNR]" ascii wide
        $ = "[*] [NBT-NS]" ascii wide
        $ = "[*] [MDNS]" ascii wide
        $ = "[FINGER] OS Version" ascii wide
        $ = "[FINGER] Client Version" ascii wide
        $ = "serve_thread_udp_broadcast" ascii wide
        $ = "serve_thread_tcp_auth" ascii wide
        $ = "serve_NBTNS_poisoner" ascii wide
        $ = "serve_MDNS_poisoner" ascii wide
        $ = "serve_LLMNR_poisoner" ascii wide
        $ = "poisoners.LLMNR " ascii wide
        $ = "poisoners.NBTNS" ascii wide
        $ = "poisoners.MDNS" ascii wide

    condition:
        any of them
}rule Windows_Credentials_Editor
{
    meta:
        id = "3iRMd6PV7nOXHEFkZT0itp"
        fingerprint = "v1_sha256_9a9eacbeeca0190c84e4b6283cb9e7f4df459ddba1f3c9a461db1382300d24ed"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Windows Credentials Editor (WCE), post-exploitation tool."
        category = "TOOL"
        tool = "WINDOWS CREDENTIAL EDITOR"
        mitre_att = "S0005"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://www.ampliasecurity.com/research/windows-credentials-editor/"
        first_imported = "2021-12-30"

    strings:
        $ = "Windows Credentials Editor" ascii wide
        $ = "Can't enumerate logon sessions!" ascii wide
        $ = "Cannot get PID of LSASS.EXE!" ascii wide
        $ = "Error: cannot dump TGT" ascii wide
        $ = "Error: Cannot extract auxiliary DLL!" ascii wide
        $ = "Error: cannot generate LM Hash." ascii wide
        $ = "Error: cannot generate NT Hash." ascii wide
        $ = "Error: Cannot open LSASS.EXE!." ascii wide
        $ = "Error in cmdline!." ascii wide
        $ = "Forced Safe Mode Error: cannot read credentials using 'safe mode'." ascii wide
        $ = "Reading by injecting code! (less-safe mode)" ascii wide
        $ = "username is too long!." ascii wide
        $ = "Using WCE Windows Service.." ascii wide
        $ = "Using WCE Windows Service..." ascii wide
        $ = "Warning: I will not be able to extract the TGT session key" ascii wide
        $ = "WCEAddNTLMCredentials" ascii wide
        $ = "wceaux.dll" ascii wide fullword
        $ = "WCEGetNTLMCredentials" ascii wide
        $ = "wce_ccache" ascii wide fullword
        $ = "wce_krbtkts" ascii wide fullword

    condition:
        3 of them
}rule Avaddon
{
    meta:
        id = "7PD7FKbfsbEN7PDykWMYVr"
        fingerprint = "v1_sha256_3f00ff6a1e626bd62bc33f8751e4a0b5aca0ed69efe2c0af0c72839a9d2bf5f1"
        version = "1.0"
        date = "2021-05-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Avaddon ransomware."
        category = "MALWARE"
        malware = "AVADDON"
        malware_type = "RANSOMWARE"
        mitre_att = "S0640"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $s1 = "\"ext\":" ascii wide
        $s2 = "\"rcid\":" ascii wide
        $s3 = "\"hdd\":" ascii wide
        $s4 = "\"name\":" ascii wide
        $s5 = "\"size\":" ascii wide
        $s6 = "\"type\":" ascii wide
        $s7 = "\"lang\":" ascii wide
        $s8 = "\"ip\":" ascii wide
        $code = { 83 7f 14 10 8b c7 c7 4? ?? 00 00 00 00 72 ?? 8b 07 6a 00 6a 00 
    8d ?? f8 51 6a 00 6a 01 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 56 
        8b 7? ?? ff 15 ?? ?? ?? ?? 56 6a 00 50 ff 15 ?? ?? ?? ?? 8b f0 85 
        f6 74 ?? 83 7f 14 10 72 ?? 8b 3f }

    condition:
        uint16(0)==0x5a4d and (5 of ($s*) or $code)
}rule BlackKingDom
{
    meta:
        id = "3oCa4Gmqww7XfNy1UGWe45"
        fingerprint = "v1_sha256_572be16f83503bc93d42c159783d1887aef2631992f09eb976f00f9c47e9acf3"
        version = "1.0"
        date = "2021-03-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies (decompiled) Black KingDom ransomware."
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "BLACLIST" ascii wide
        $ = "Black KingDom" ascii wide
        $ = "FUCKING_WINDOW" ascii wide
        $ = "PleasStopMe" ascii wide
        $ = "THE AMOUNT DOUBLED" ascii wide
        $ = "WOWBICH" ascii wide
        $ = "clear_logs_plz" ascii wide
        $ = "decrypt_file.TxT" ascii wide
        $ = "disable_Mou_And_Key" ascii wide
        $ = "encrypt_file" ascii wide
        $ = "for_fortnet" ascii wide
        $ = "start_encrypt" ascii wide
        $ = "where_my_key" ascii wide

    condition:
        3 of them
}rule CryLock
{
    meta:
        id = "5ruF081EHzxK67xYFV84hk"
        fingerprint = "v1_sha256_b78681172e3415615c1f6dc9490bb5a4e7a6f0b3da5ceb4466e81c1c344ba31d"
        version = "1.0"
        date = "2020-09-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies CryLock aka Cryakl ransomware."
        category = "MALWARE"
        malware = "CRYLOCK"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "///END ENCRYPT ONLY EXTENATIONS" ascii wide
        $ = "///END UNENCRYPT EXTENATIONS" ascii wide
        $ = "///END COMMANDS LIST" ascii wide
        $ = "///END PROCESSES KILL LIST" ascii wide
        $ = "///END SERVICES STOP LIST" ascii wide
        $ = "///END PROCESSES WHITE LIST" ascii wide
        $ = "///END UNENCRYPT FILES LIST" ascii wide
        $ = "///END UNENCRYPT FOLDERS LIST" ascii wide
        $ = "{ENCRYPTENDED}" ascii wide
        $ = "{ENCRYPTSTART}" ascii wide

    condition:
        2 of them
}rule Darkside
{
    meta:
        id = "1vT0gIEQU23w7XEV3ulH8H"
        fingerprint = "v1_sha256_c15129be4cf25ad41423cfa836b5cbe3fa8294c4e6737f1f429c47c1795a68c8"
        version = "1.0"
        date = "2021-05-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Darkside ransomware."
        category = "MALWARE"
        malware = "DARKSIDE"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        first_imported = "2021-12-30"

    strings:
        $ = "darkside_readme.txt" ascii wide
        $ = "[ Welcome to DarkSide ]" ascii wide
        $ = { 66 c7 04 47 2a 00 c7 44 47 02 72 00 65 00 c7 44 47 06 63 00 79 00 c7 44 47 0a 63 00 6c 00 c7 44 47 0e 65 00 2a 00 66 c7 44 47 12 00 00 }
        $ = { c7 00 2a 00 72 00 c7 40 04 65 00 63 00 c7 40 08 79 00 63 00 c7 40 0c 6c 00 65 00 c7 40 10 2a 00 00 00 }

    condition:
        any of them
}rule DearCry
{
    meta:
        id = "5gsdoT1uTEDAuUczymThTj"
        fingerprint = "v1_sha256_9978f53c72118742cbadcca5c4751a9672461985cb7308995576fe4f6e027953"
        version = "1.0"
        date = "2021-03-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies DearCry ransomware."
        category = "MALWARE"
        malware = "DEARCRY"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        reference = "https://twitter.com/MsftSecIntel/status/1370236539427459076"
        first_imported = "2021-12-30"

    strings:
        $pdb = "C:\\Users\\john\\Documents\\Visual Studio 2008\\Projects\\EncryptFile -svcV2\\Release\\EncryptFile.exe.pdb"
        $key = {4D 49 49 42 43 41 4B 43 41 51 45 41 79 4C 42 43 6C 7A 39 68 73 46 47 52 66 39 66 6B 33 7A 30 7A 6D 59 32 72 7A 32 4A 31 
    71 71 47 66 56 34 38 44 53 6A 50 56 34 6C 63 77 6E 68 43 69 34 2F 35 2B 0A 43 36 55 73 41 68 6B 2F 64 49 34 2F 35 48 77 62 66 5A 
    42 41 69 4D 79 53 58 4E 42 33 44 78 56 42 32 68 4F 72 6A 44 6A 49 65 56 41 6B 46 6A 51 67 5A 31 39 42 2B 4B 51 46 57 6B 53 6F 31 
    75 62 65 0A 56 64 48 6A 77 64 76 37 34 65 76 45 2F 75 72 39 4C 76 39 48 4D 2B 38 39 69 5A 64 7A 45 70 56 50 4F 2B 41 6A 4F 54 74 
    73 51 67 46 4E 74 6D 56 65 63 43 32 76 6D 77 39 6D 36 30 64 67 79 52 2F 31 0A 43 4A 51 53 67 36 4D 6F 62 6C 6F 32 4E 56 46 35 30 
    41 4B 33 63 49 47 32 2F 6C 56 68 38 32 65 62 67 65 64 58 73 62 56 4A 70 6A 56 4D 63 30 33 61 54 50 57 56 34 73 4E 57 6A 54 4F 33 
    6F 2B 61 58 0A 36 5A 2B 56 47 56 4C 6A 75 76 63 70 66 4C 44 5A 62 33 74 59 70 70 6B 71 5A 7A 41 48 66 72 43 74 37 6C 56 30 71 4F
    34 37 46 56 38 73 46 43 6C 74 75 6F 4E 69 4E 47 4B 69 50 30 38 34 4B 49 37 62 0A 33 58 45 4A 65 70 62 53 4A 42 33 55 57 34 6F 34 
    43 34 7A 48 46 72 71 6D 64 79 4F 6F 55 6C 6E 71 63 51 49 42 41 77 3D 3D}

    condition:
        any of them
}rule Ekans
{
    meta:
        id = "6rvuyjUKyIqg6gnvERKsP"
        fingerprint = "v1_sha256_095556a29b501aace96d5b324cdb731a2de7cb616847b8f3d8e826f992f7aaf9"
        version = "1.0"
        date = "2020-03-01"
        modified = "2023-12-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Ekans aka Snake ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "EKANS"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        first_imported = "2021-12-30"

    strings:
        $ = "already encrypted!" ascii wide
        $ = "error encrypting %v : %v" ascii wide
        $ = "faild to get process list" ascii wide
        $ = "There can be only one" ascii wide fullword
        $ = "total lengt: %v" ascii wide fullword

    condition:
        3 of them
}
rule Fusion
{
    meta:
        id = "6Kqx4CGJ13GhtY3lK4FezC"
        fingerprint = "v1_sha256_f4ea9396c2c37576573227f838d91c83f6ce3d4f0a2c1446e73e5b8b5e8a4c7e"
        version = "1.0"
        date = "2021-06-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Fusion ransomware, Go variant of Nemty/Nefilim."
        category = "MALWARE"
        malware = "FUSION"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        first_imported = "2021-12-30"

    strings:
        $s1 = "main.getdrives" ascii wide
        $s2 = "main.SaveNote" ascii wide
        $s3 = "main.FileSearch" ascii wide
        $s4 = "main.BytesToPublicKey" ascii wide
        $s5 = "main.GenerateRandomBytes" ascii wide
        $x1 = /Fa[i1]led to fi.Close/ ascii wide
        $x2 = /Fa[i1]led to fi2.Close/ ascii wide
        $x3 = /Fa[i1]led to get stat/ ascii wide
        $x4 = /Fa[i1]led to os.OpenFile/ ascii wide
        $pdb1 = "C:/OpenServer/domains/build/aes.go" ascii wide
        $pdb2 = "C:/Users/eugene/Desktop/test go/test.go" ascii wide
        $pdb3 = "C:/Users/eugene/Desktop/web/src/aes_" ascii wide

    condition:
        4 of ($s*) or 3 of ($x*) or any of ($pdb*)
}rule Maze
{
    meta:
        id = "3TD1oAJABfAczOtSUn2Sv1"
        fingerprint = "v1_sha256_2d8a5afde45dfc4499ce1f02e8078496b473a0fb6403a7824d6734fe01ec3966"
        version = "1.0"
        date = "2019-11-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Maze ransomware in memory or unpacked."
        category = "MALWARE"
        malware = "MAZE"
        malware_type = "RANSOMWARE"
        mitre_att = "S0449"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        first_imported = "2021-12-30"

    strings:
        $ = "Enc: %s" ascii wide
        $ = "Encrypting whole system" ascii wide
        $ = "Encrypting specified folder in --path parameter..." ascii wide
        $ = "!Finished in %d ms!" ascii wide
        $ = "--logging" ascii wide
        $ = "--nomutex" ascii wide
        $ = "--noshares" ascii wide
        $ = "--path" ascii wide
        $ = "Logging enabled | Maze" ascii wide
        $ = "NO SHARES | " ascii wide
        $ = "NO MUTEX | " ascii wide
        $ = "Encrypting:" ascii wide
        $ = "You need to buy decryptor in order to restore the files." ascii wide
        $ = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" ascii wide
        $ = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" ascii wide
        $ = "DECRYPT-FILES.txt" ascii wide fullword

    condition:
        5 of them
}rule Pysa
{
    meta:
        id = "3dOx7WNeK3QjOnvMlYezdj"
        fingerprint = "v1_sha256_bbbceb2ca10c968e6e3b04fea703da95d59ecc6d68c9cca79880aedbc36f6a62"
        version = "1.0"
        date = "2021-03-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Pysa aka Mespinoza ransomware."
        category = "MALWARE"
        malware = "PYSA"
        malware_type = "RANSOMWARE"
        mitre_att = "S0583"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        first_imported = "2021-12-30"

    strings:
        $code = { 8a 0? 41 84 c0 75 ?? 2b ce 8b 35 ?? ?? ?? ?? 8d 41 01 50 5? 6a 07 6a 00 68 ?? ?? ?? 
    ?? ff 7? ?? ff d? 6a 05 68 ?? ?? ?? ?? 6a 07 6a 00 68 ?? ?? ?? ?? ff 7? ?? ff d? ff 7? ?? ff 
    15 ?? ?? ?? ?? 8b 4? ?? 33 cd 5e e8 ?? ?? ?? ?? 8b e5 5d c3 }
        $s1 = "n.pysa" ascii wide fullword
        $s2 = "%s\\Readme.README" ascii wide
        $s3 = "Every byte on any types of your devices was encrypted." ascii wide

    condition:
        $code or 2 of ($s*)
}import "pe"

rule REvil_Cert
{
    meta:
        id = "6JiE39Km6ntepePqP0xCJ2"
        fingerprint = "v1_sha256_f0862143f03b67d071174b14f8e0c8dead3b4d8228778fe89648a92ae5dbcafd"
        version = "1.0"
        date = "2021-07-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies the digital certificate PB03 TRANSPORT LTD, used by REvil in the Kaseya supply chain attack."
        category = "MALWARE"
        malware = "REVIL"
        malware_type = "RANSOMWARE"
        mitre_att = "S0496"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"
        first_imported = "2021-12-30"

    condition:
        uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0")
}rule REvil_Dropper
{
    meta:
        id = "18x6OazePZa0J8loDsLg16"
        fingerprint = "v1_sha256_7d6062f2c5a12289888e5e912b1e658bff6eca01f24d1228b674fe9971489a34"
        version = "1.0"
        date = "2021-07-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies the dropper used by REvil in the Kaseya supply chain attack."
        category = "MALWARE"
        malware = "REVIL"
        malware_type = "RANSOMWARE"
        mitre_att = "S0496"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"
        hash = "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e"
        first_imported = "2021-12-30"

    strings:
        $ = { 55 8b ec 56 8b 35 24 d0 40 00 68 04 1c 41 00 6a 65 6a 00 ff 
     d6 85 c0 0f 84 98 00 00 00 50 6a 00 ff 15 20 d0 40 00 85 c0 0f 84 
      87 00 00 00 50 ff 15 18 d0 40 00 68 14 1c 41 00 6a 66 6a 00 a3 a0 
      43 41 00 ff d6 85 c0 74 6c 50 33 f6 56 ff 15 20 d0 40 00 85 c0 74 
      5e 50 ff 15 18 d0 40 00 68 24 1c 41 00 ba 88 55 0c 00 a3 a4 43 41 
      00 8b c8 e8 9a fe ff ff 8b 0d a0 43 41 00 ba d0 56 00 00 c7 04 ?4 
      38 1c 41 00 e8 83 fe ff ff c7 04 ?4 ec 43 41 00 68 a8 43 41 00 56 
      56 68 30 02 00 00 56 56 56 ff 75 10 c7 05 a8 43 41 00 44 00 00 00 
      50 ff 15 28 d0 40 00 }
        $ = { 55 8b ec 83 ec 08 e8 55 ff ff ff 85 c0 75 04 33 c0 eb 67 68 
    98 27 41 00 68 68 b7 0c 00 a1 f4 32 41 00 50 e8 58 fe ff ff 83 c4 
    0c 89 45 f8 68 80 27 41 00 68 d0 56 00 00 8b 0d f0 32 41 00 51 e8 
    3c fe ff ff 83 c4 0c 89 45 fc c7 05 f8 32 41 00 44 00 00 00 68 3c 
    33 41 00 68 f8 32 41 00 6a 00 6a 00 6a 08 6a 00 6a 00 6a 00 8b 55 
    10 52 8b 45 fc 50 ff 15 28 c0 40 00 33 c0 }

    condition:
        any of them
}rule RagnarLocker
{
    meta:
        id = "6rhZNZfkxwPqtaQZJyDAMM"
        fingerprint = "v1_sha256_e6aa00382f22cdbe5058dd8f4d4985313f85b0fc292cfeb4ebb7daebec35a579"
        version = "1.0"
        date = "2020-07-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RagnarLocker ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "RAGNAR LOCKER"
        malware_type = "RANSOMWARE"
        mitre_att = "S0481"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        first_imported = "2021-12-30"

    strings:
        $ = "RAGNRPW" ascii wide
        $ = "---END KEY R_R---" ascii wide
        $ = "---BEGIN KEY R_R---" ascii wide

    condition:
        any of them
}rule Satan_Mutexes
{
    meta:
        id = "2hYeKDfTUfNKI16OXKF2Ly"
        fingerprint = "v1_sha256_9b705c24637daf7a707ddb1781f04bd4a31a358724b43ef2930f11a2908256ab"
        version = "1.0"
        date = "2020-01-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Satan ransomware (and its variants) by mutex."
        category = "MALWARE"
        malware = "SATAN"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        reference = "https://bartblaze.blogspot.com/2020/01/satan-ransomware-rebrands-as-5ss5c.html"
        first_imported = "2021-12-30"

    strings:
        $ = "SATANAPP" ascii wide
        $ = "SATAN_SCAN_APP" ascii wide
        $ = "STA__APP" ascii wide
        $ = "DBGERAPP" ascii wide
        $ = "DBG_CPP" ascii wide
        $ = "run_STT" ascii wide
        $ = "SSS_Scan" ascii wide
        $ = "SSSS_Scan" ascii wide
        $ = "5ss5c_CRYPT" ascii wide

    condition:
        any of them
}rule Sfile
{
    meta:
        id = "2af9VNrCMkqlKGUH9hv1WN"
        fingerprint = "v1_sha256_ddab486fcff03ba6dd632468949ffe3551a9795cc4bfdf9f96abb0fd3b80dbf5"
        version = "1.0"
        date = "2020-09-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Sfile aka Escal ransomware."
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        first_imported = "2021-12-30"

    strings:
        $pdb = "D:\\code\\ransomware_win\\bin\\ransomware.pdb"
        $ = "%s SORTING time : %s" ascii wide
        $ = "%ws -> WorkModeDecryptFiles : %d of %d files decrypted +%d (%d MB)..." ascii wide
        $ = "%ws -> WorkModeEncryptFiles : %d of %d files encrypted +%d [bps : %d, size = %d MB] (%d skipped, ld = %d.%d.%d %d:%d:%d, lf = %ws)..." ascii wide
        $ = "%ws -> WorkModeEnded" ascii wide
        $ = "%ws -> WorkModeFindFiles : %d files / %d folders found (already (de?)crypted %d/%d) (lf = %ws)..." ascii wide
        $ = "%ws -> WorkModeSorting" ascii wide
        $ = "%ws ENCRYPTFILES count : %d (%d skipped), time : %s" ascii wide
        $ = "%ws FINDFILES RESULTS : dwDirectoriesCount = %d, dwFilesCount = %d MB = %d (FIND END)" ascii wide
        $ = "%ws FINDFILES time : %s" ascii wide
        $ = "DRIVE_FIXED : %ws" ascii wide
        $ = "EncryptDisk(%ws) DONE" ascii wide
        $ = "ScheduleRoutine() : gogogo" ascii wide
        $ = "ScheduleRoutine() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
        $ = "WARN! FileLength more then memory has %ws" ascii wide
        $ = "WaitForHours() : gogogo" ascii wide
        $ = "WaitForHours() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
        $ = "Your network has been penetrated." ascii wide
        $ = "--kill-susp" ascii wide
        $ = "--enable-shares" ascii wide

    condition:
        $pdb or 3 of them
}rule WhiteBlack
{
    meta:
        id = "eEJcE4XQzrV8pfeqHZVMy"
        fingerprint = "v1_sha256_c6c4c26cc7b340f5131950b0d2ba8565193c625130b9769c67689bf3029ae273"
        version = "1.0"
        date = "2022-01-01"
        modified = "2022-02-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies WhiteBlack ransomware."
        category = "MALWARE"
        malware = "WHITEBLACK"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        reference = "https://twitter.com/siri_urz/status/1377877204776976384"
        first_imported = "2022-02-03"

    strings:
        //_Str2 = strcat(_Str2,".encrpt3d"); Encrypt block
        $ = { 55 57 56 53 4? 83 ec 28 31 db bd 00 01 00 00 89 cf 31 c9 ff 15 ?? ?? ?? ?? 89 c1 e8 ?? ?? ?? ?? 4? 63 cf e8 ?? ?? ?? ?? 4? 89 c6 39 df 7e ?? e8 ?? ?? ?? ?? 99 f7 fd 88 14 1e 4? ff c3 eb ?? 4? 89 f0 4? 83 c4 28 5b 5e 5f 5d c3 4? 55 4? 54 55 57 56 53 4? 83 ec 28 4? 8d 15 ?? ?? ?? ?? 31 f6 4? 8d 2d ?? ?? ?? ?? 4? 89 cd e8 ?? ?? ?? ?? b9 00 00 00 02 4? 89 c3 e8 ?? ?? ?? ?? 4? 89 c7 4? 89 d9 4? b8 00 00 00 02 ba 01 00 00 00 4? 89 f9 e8 ?? ?? ?? ?? 85 c0 4? 89 c4 74 ?? 81 fe ff ff ff 3f 7f ?? 4? 89 e0 4? 89 fa 4? 89 e? e8 ?? ?? ?? ?? 4? 31 c0 89 f2 4? 89 d9 e8 ?? ?? ?? ?? 4? 01 e6 4? 63 c4 4? 89 f9 4? 89 d9 ba 01 00 00 00 e8 ?? ?? ?? ?? 4? 31 c0 89 f2 4? 89 d9 e8 ?? ?? ?? ?? eb ?? 4? 89 f9 4? 89 ef e8 ?? ?? ?? ?? 4? 89 d9 e8 ?? ?? ?? ?? 31 c0 4? 83 c9 ff f2 ae 4? 89 ce 4? f7 d6 4? 89 f1 4? 83 c1 09 e8 ?? ?? ?? ?? 4? 89 ea 4? 89 c1 e8 ?? ?? ?? ?? 4? 8d 15 ?? ?? ?? ?? 4? 89 c1 e8 ?? ?? ?? ?? 4? 89 e9 4? 89 c2 4? 83 c4 28 }

    condition:
        any of them
}
rule WickrMe
{
    meta:
        id = "1QZckgQpPfixJaILsQvdAT"
        fingerprint = "v1_sha256_b8f26e413aa0f133b78bed314553f55de05d5d5e4a0090798b8128a3e6767821"
        version = "1.0"
        date = "2021-04-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies WickrMe (aka Hello) ransomware."
        category = "MALWARE"
        malware = "WICKRME"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        reference = "https://www.trendmicro.com/en_ca/research/21/d/hello-ransomware-uses-updated-china-chopper-web-shell-sharepoint-vulnerability.html"
        first_imported = "2021-12-30"

    strings:
        $ = "[+] Config Service..." ascii wide
        $ = "[+] Config Services Finished" ascii wide
        $ = "[+] Config Shadows Finished" ascii wide
        $ = "[+] Delete Backup Files..." ascii wide
        $ = "[+] Generate contact file {0} successfully" ascii wide
        $ = "[+] Generate contact file {0} failed! " ascii wide
        $ = "[+] Get Encrypt Files..." ascii wide
        $ = "[+] Starting..." ascii wide
        $ = "[-] No Admin Rights" ascii wide
        $ = "[-] Exit" ascii wide

    condition:
        4 of them
}rule WinLock
{
    meta:
        id = "4W8llhUvViKq7CYThxDpsF"
        fingerprint = "v1_sha256_30fc539542260296a2a67fa0a117a41a8e06a746b04ebdcecb5882230084179c"
        version = "1.0"
        date = "2020-08-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies WinLock (aka Blocker) ransomware variants generically."
        category = "MALWARE"
        malware = "WINLOCK"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        first_imported = "2021-12-30"

    strings:
        $s1 = "twexx32.dll" ascii wide
        $s2 = "s?cmd=ul&id=%s" ascii wide
        $s3 = "card_ukash.png" ascii wide
        $s4 = "toneo_card.png" ascii wide
        $pdb = "C:\\Kuzja 1.4\\vir.vbp" ascii wide
        $x1 = "AntiWinLockerTray.exe" ascii wide
        $x2 = "Computer name:" ascii wide
        $x3 = "Current Date:" ascii wide
        $x4 = "Information about blocking" ascii wide
        $x5 = "Key Windows:" ascii wide
        $x6 = "Password attempts:" ascii wide
        $x7 = "Registered on:" ascii wide
        $x8 = "ServiceAntiWinLocker.exe" ascii wide
        $x9 = "Time of Operation system:" ascii wide
        $x10 = "To removing the system:" ascii wide

    condition:
        3 of ($s*) or $pdb or 5 of ($x*)
}rule XiaoBa
{
    meta:
        id = "R0ND3ewH2Nge9gS5kOIis"
        fingerprint = "v1_sha256_67856bf5d96b0cd6dba0969eaf47bcea048fd27ca9d01c898eef8161a4aa8aae"
        version = "1.0"
        date = "2019-09-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies XiaoBa ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "XIAOBA"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        first_imported = "2021-12-30"

    strings:
        $ = "BY:TIANGE" ascii wide
        $ = "Your disk have a lock" ascii wide
        $ = "Please enter the unlock password" ascii wide
        $ = "Please input the unlock password" ascii wide
        $ = "I am very sorry that all your files have been encrypted" ascii wide

    condition:
        any of them
}rule Zeppelin
{
    meta:
        id = "2Y0C2KLmdiRNTTIg4k6zeT"
        fingerprint = "v1_sha256_1ae1006f028be5179d4566a7f28b289a4f9719618f40653221c521e18c649455"
        version = "1.0"
        date = "2019-11-01"
        modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Zeppelin ransomware and variants (Buran, Vega etc.)"
        category = "MALWARE"
        malware = "ZEPPELIN"
        malware_type = "RANSOMWARE"
        mitre_att = "S1074"
        mitre_att = "S0670"
        mitre_att = "S0605"
        first_imported = "2021-12-30"

    strings:
        $s1 = "TUnlockAndEncryptU" ascii wide
        $s2 = "TDrivesAndShares" ascii wide
        $s3 = "TExcludeFoldersU" ascii wide
        $s4 = "TExcludeFiles" ascii wide
        $s5 = "TTaskKillerU" ascii wide
        $s6 = "TPresenceU" ascii wide
        $s7 = "TSearcherU" ascii wide
        $s8 = "TReadme" ascii wide
        $s9 = "TKeyObj" ascii wide
        $x = "TZeppelinU" ascii wide

    condition:
        2 of ($s*) or $x
}
