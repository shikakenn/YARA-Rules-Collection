/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-06-13
    Identifier: CN-Tools Hacktools
    Reference: Diclosed hacktool set at http://w2op.us/ (Mirror: http://tools.zjqhr.com)
*/

rule mswin_check_lm_group {
    meta:
        id = "4HFhGcqAqnEfrPa1dyZxIu"
        fingerprint = "v1_sha256_8c325ec2746426d6c82bb4da61e88f6b7bf392d29a60d480b3107e43e2459d97"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file mswin_check_lm_group.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "115d87d7e7a3d08802a9e5fd6cd08e2ec633c367"

    strings:
        $s1 = "Valid_Global_Groups: checking group membership of '%s\\%s'." fullword ascii
        $s2 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
        $s3 = "-D    default user Domain" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 380KB and all of them
}

rule WAF_Bypass {
    meta:
        id = "6nn8ufclhpn95C9LOej9wh"
        fingerprint = "v1_sha256_e66d51b465e5d919555084d299a22f07a949a0a9adf4a3f246f6b5222d39b91a"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file WAF-Bypass.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "860a9d7aac2ce3a40ac54a4a0bd442c6b945fa4e"

    strings:
        $s1 = "Email: blacksplitn@gmail.com" fullword wide
        $s2 = "User-Agent:" fullword wide
        $s3 = "Send Failed.in RemoteThread" fullword ascii
        $s4 = "www.example.com" fullword wide
        $s5 = "Get Domain:%s IP Failed." fullword ascii
        $s6 = "Connect To Server Failed." fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 7992KB and 5 of them
}

rule Guilin_veterans_cookie_spoofing_tool {
    meta:
        id = "4LUqFxJKqSvsjFwq4HooXL"
        fingerprint = "v1_sha256_4c438157df054477edd2c3b7219bc846185b229a66e1ef7fb059e85576a7f934"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Guilin veterans cookie spoofing tool.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "06b1969bc35b2ee8d66f7ce8a2120d3016a00bb1"

    strings:
        $s0 = "kernel32.dll^G" fullword ascii
        $s1 = "\\.Sus\"B" fullword ascii
        $s4 = "u56Load3" fullword ascii
        $s11 = "O MYTMP(iM) VALUES (" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1387KB and all of them
}

rule MarathonTool {
    meta:
        id = "4SW1XfIG2YFk9sDxCP09Vx"
        fingerprint = "v1_sha256_2d52d640ef44d933791d1da0d1263dba15702180c730500e04d364dd6b4d6081"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file MarathonTool.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "084a27cd3404554cc799d0e689f65880e10b59e3"

    strings:
        $s0 = "MarathonTool" ascii
        $s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
        $s18 = "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 1040KB and all of them
}

rule PLUGIN_TracKid {
    meta:
        id = "2yzV9o7kBOBaPvCzwjXhao"
        fingerprint = "v1_sha256_a62112dbf2ef696e4eb7f6787a0e0930c29d9834f46c87493954498fa4b375f6"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file TracKid.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "a114181b334e850d4b33e9be2794f5bb0eb59a09"

    strings:
        $s0 = "E-mail: cracker_prince@163.com" fullword ascii
        $s1 = ".\\TracKid Log\\%s.txt" fullword ascii
        $s2 = "Coded by prince" fullword ascii
        $s3 = "TracKid.dll" fullword ascii
        $s4 = ".\\TracKid Log" fullword ascii
        $s5 = "%08x -- %s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}

rule Pc_pc2015 {
    meta:
        id = "10RDo8shQPKhu9wplEepKP"
        fingerprint = "v1_sha256_5d4969d5c76354820029060dfb33d8527addf5c3d033e845bcfa439214ee052b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file pc2015.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "de4f098611ac9eece91b079050b2d0b23afe0bcb"

    strings:
        $s0 = "\\svchost.exe" fullword ascii
        $s1 = "LON\\OD\\O-\\O)\\O%\\O!\\O=\\O9\\O5\\O1\\O" fullword ascii
        $s8 = "%s%08x.001" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 309KB and all of them
}

rule sekurlsa {
    meta:
        id = "5deH7uM1S94aPOKL7QEHEw"
        fingerprint = "v1_sha256_dea05c7f19a834cc936c452ca2f6f4286e6c3dae002747c27913960199451c3f"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file sekurlsa.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"

    strings:
        $s1 = "Bienvenue dans un processus distant" fullword wide
        $s2 = "Format d'appel invalide : addLogonSession [idSecAppHigh] idSecAppLow Utilisateur" wide
        $s3 = "SECURITY\\Policy\\Secrets" fullword wide
        $s4 = "Injection de donn" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}

rule mysqlfast {
    meta:
        id = "7VWsX7xUrKg228CnE2uYtj"
        fingerprint = "v1_sha256_3ea75954831e705d0d25efa115288e66868d9b814f0990fd048bbe1209a8d933"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file mysqlfast.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "32b60350390fe7024af7b4b8fbf50f13306c546f"

    strings:
        $s2 = "Invalid password hash: %s" fullword ascii
        $s3 = "-= MySql Hash Cracker =- " fullword ascii
        $s4 = "Usage: %s hash" fullword ascii
        $s5 = "Hash: %08lx%08lx" fullword ascii
        $s6 = "Found pass: " fullword ascii
        $s7 = "Pass not found" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 900KB and 4 of them
}

rule DTools2_02_DTools {
    meta:
        id = "1KPfhwOck7Pm6rTgbiOQlJ"
        fingerprint = "v1_sha256_51e30d39f388546ac233b4b97a38f225c90d2f006bc509dd7eecfb408aef9be5"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file DTools.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "9f99771427120d09ec7afa3b21a1cb9ed720af12"

    strings:
        $s0 = "kernel32.dll" ascii
        $s1 = "TSETPASSWORDFORM" fullword wide
        $s2 = "TGETNTUSERNAMEFORM" fullword wide
        $s3 = "TPORTFORM" fullword wide
        $s4 = "ShellFold" fullword ascii
        $s5 = "DefaultPHotLigh" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule dll_PacketX {
    meta:
        id = "NN6bTQa9wWHxKgDvutTPr"
        fingerprint = "v1_sha256_161d174376c599b1b794fa1174349ae12b198842d89769baec4b9664729a3983"
        version = "1.0"
        score = 50
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file PacketX.dll - ActiveX wrapper for WinPcap packet capture library"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "3f0908e0a38512d2a4fb05a824aa0f6cf3ba3b71"

    strings:
        $s9 = "[Failed to load winpcap packet.dll." wide
        $s10 = "PacketX Version" wide
    condition:
        uint16(0) == 0x5a4d and filesize < 1920KB and all of them
}

rule SqlDbx_zhs {
    meta:
        id = "1RPHJeCc4vmsqeAoh7iDgm"
        fingerprint = "v1_sha256_b0215d29c58c252c1717f08135eab65794a99ed669c2225bcba690ae7d7a034c"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file SqlDbx_zhs.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "e34228345498a48d7f529dbdffcd919da2dea414"

    strings:
        $s0 = "S.failed_logins \"Failed Login Attempts\", " fullword ascii
        $s7 = "SELECT ROLE, PASSWORD_REQUIRED FROM SYS.DBA_ROLES ORDER BY ROLE" fullword ascii
        $s8 = "SELECT spid 'SPID', status 'Status', db_name (dbid) 'Database', loginame 'Login'" ascii
        $s9 = "bcp.exe <:schema:>.<:table:> out \"<:file:>\" -n -S <:server:> -U <:user:> -P <:" ascii
        $s11 = "L.login_policy_name AS \"Login Policy\", " fullword ascii
        $s12 = "mailto:support@sqldbx.com" fullword ascii
        $s15 = "S.last_login_time \"Last Login\", " fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule digest_edir_auth {
    meta:
        id = "5KzHK6L4qZ5aybn1K1FMDZ"
        fingerprint = "v1_sha256_1479e067efdbfdd737be71ef2966a89dcb0645d59ef042100062a9986b665e9b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file digest_edir_auth.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "1dc349c91d890e3a1b897c2e8bb0ee1beeb34bd5"

    strings:
        $s0 = "Error reading Universal Password: %d = %s" fullword ascii
        $s1 = "read password for binddn from file secretfile" fullword ascii
        $s4 = "user search filter pattern. %%s = login" fullword ascii
        $s5 = "-D binddn -w bindpasswd or -D binddn -W secretfile options" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule ms10048_x86 {
    meta:
        id = "1q9XFDQ7nAs9rF0CFjPEwB"
        fingerprint = "v1_sha256_50e45cae87f5d1cc4903a16f9283dd751d90cde0c71f3124467b4ff15bd34f1b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file ms10048-x86.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "e57b453966e4827e2effa4e153f2923e7d058702"

    strings:
        $s1 = "[ ] Resolving PsLookupProcessByProcessId" fullword ascii
        $s2 = "The target is most likely patched." fullword ascii
        $s3 = "Dojibiron by Ronald Huizer, (c) master@h4cker.us ." fullword ascii
        $s4 = "[ ] Creating evil window" fullword ascii
        $s5 = "%sHANDLEF_INDESTROY" fullword ascii
        $s6 = "[+] Set to %d exploit half succeeded" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 4 of them
}

rule Dos_ch {
    meta:
        id = "42z4cQ6dqaCOjY54VP0s29"
        fingerprint = "v1_sha256_49ab2c75267c2ed5c15c8fbdc6fa0f8826f6e7a45a2861d6ba4b293ffca6bcd6"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file ch.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "60bbb87b08af840f21536b313a76646e7c1f0ea7"

    strings:
        $s0 = "/Churraskito/-->Usage: Churraskito.exe \"command\" " fullword ascii
        $s4 = "fuck,can't find WMI process PID." fullword ascii
        $s5 = "/Churraskito/-->Found token %s " fullword ascii
        $s8 = "wmiprvse.exe" fullword ascii
        $s10 = "SELECT * FROM IIsWebInfo" fullword ascii
        $s17 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 260KB and 3 of them
}

rule DUBrute_DUBrute {
    meta:
        id = "5d4oRoGXmJHJmNcWChAvDX"
        fingerprint = "v1_sha256_1e6d8bd24a37e3f4b7de88989251ae904128ff1bf766d4a4408ff8990c6dfd2f"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file DUBrute.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "8aaae91791bf782c92b97c6e1b0f78fb2a9f3e65"

    strings:
        $s1 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
        $s2 = "IP - 0; Login - 0; Password - 0; Combination - 0" fullword ascii
        $s3 = "Create %d IP@Loginl;Password" fullword ascii
        $s4 = "UBrute.com" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1020KB and all of them
}

rule CookieTools {
    meta:
        id = "7R404Ytbr9tHvThTACpMLi"
        fingerprint = "v1_sha256_465859a9ad7092feede6e90cfd93922f9e868c5b72e928395bb41f2b6a8dc89d"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file CookieTools.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "b6a3727fe3d214f4fb03aa43fb2bc6fadc42c8be"

    strings:
        $s0 = "http://210.73.64.88/doorway/cgi-bin/getclientip.asp?IP=" fullword ascii
        $s2 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
        $s3 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
        $s8 = "OnGetPasswordP" fullword ascii
        $s12 = "http://www.chinesehack.org/" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule update_PcInit {
    meta:
        id = "tEWWWIXmYHT3uBZzuaO2z"
        fingerprint = "v1_sha256_350e12938d73300e3ae63ce82fc4f166dd789d2b9518c1119c4349216252e700"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file PcInit.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "a6facc4453f8cd81b8c18b3b3004fa4d8e2f5344"

    strings:
        $s1 = "\\svchost.exe" fullword ascii
        $s2 = "%s%08x.001" fullword ascii
        $s3 = "Global\\ps%08x" fullword ascii
        $s4 = "drivers\\" fullword ascii /* Goodware String - occured 2 times */
        $s5 = "StrStrA" fullword ascii /* Goodware String - occured 43 times */
        $s6 = "StrToIntA" fullword ascii /* Goodware String - occured 44 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 50KB and all of them
}

rule dat_NaslLib {
    meta:
        id = "1bKJqstby60RmNDpMtN6mO"
        fingerprint = "v1_sha256_7d2f3c67fe78028a51ba01c88d7eb62c38fe3c918bb03eee41b6583bc464ad78"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file NaslLib.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "fb0d4263118faaeed2d68e12fab24c59953e862d"

    strings:
        $s1 = "nessus_get_socket_from_connection: fd <%d> is closed" fullword ascii
        $s2 = "[*] \"%s\" completed, %d/%d/%d/%d:%d:%d - %d/%d/%d/%d:%d:%d" fullword ascii
        $s3 = "A FsSniffer backdoor seems to be running on this port%s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1360KB and all of them
}

rule Dos_1 {
    meta:
        id = "4FSw3fi9VVVKvXoJWOjCvz"
        fingerprint = "v1_sha256_d4cf3e738743e5402602e045cf590b969dca2d6f7f1bdd57cc398df3392560d9"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file 1.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "b554f0687a12ec3a137f321cc15e052ff219f28c"

    strings:
        $s1 = "/churrasco/-->Usage: Churrasco.exe \"command to run\"" fullword ascii
        $s2 = "/churrasco/-->Done, command should have ran as SYSTEM!" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule OtherTools_servu {
    meta:
        id = "22r6v2BrawgxDDY1ULlSnj"
        fingerprint = "v1_sha256_fc6462113f71788300b2053229b57d6bc6d6acc7c0de686489f0cb175b6b0290"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file svu.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "5c64e6879a9746a0d65226706e0edc7a"

    strings:
        $s0 = "MZKERNEL32.DLL" fullword ascii
        $s1 = "UpackByDwing@" fullword ascii
        $s2 = "GetProcAddress" fullword ascii
        $s3 = "WriteFile" fullword ascii
    condition:
        $s0 at 0 and filesize < 50KB and all of them
}

rule ncsa_auth {
    meta:
        id = "55Gj7fzbKmRIYIO8yhDNQg"
        fingerprint = "v1_sha256_48bb685bfea4fae3b71cee3d4188521b89d85747b8c14ba0dc66cda687f1b274"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file ncsa_auth.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "d87c984107adc3921720f4c76608dc6ed68b2d84"

    strings:
        $s0 = "Usage: ncsa_auth <passwordfile>" fullword ascii
        $s1 = "ERR Wrong password" fullword ascii
        $s2 = "ERR No such user" fullword ascii
        $s6 = "ncsa_auth: cannot create hash table" fullword ascii
        $s20 = "(%d) %s" fullword ascii /* Goodware String - occured 11 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 440KB and all of them
}

rule ustrrefadd {
    meta:
        id = "7g6nvRMZYVnH0CbWbPM2kL"
        fingerprint = "v1_sha256_e44f180e081494e28b35b4129eb2c1817ed3e83f23d86f0d3dd4dcf27941cdf1"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file ustrrefadd.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "b371b122460951e74094f3db3016264c9c8a0cfa"

    strings:
        $s0 = "E-Mail  : admin@luocong.com" fullword ascii
        $s1 = "Homepage: http://www.luocong.com" fullword ascii
        $s2 = ": %d  -  " fullword ascii
        $s3 = "ustrreffix.dll" fullword ascii
        $s5 = "Ultra String Reference plugin v%d.%02d" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 320KB and all of them
}

rule XScanLib {
    meta:
        id = "4xuqotDBxCE27hXO0Tkvgk"
        fingerprint = "v1_sha256_ff18c527df9ff2a4d72bcc5e4905d6f42877d42536edcb13608c6e0e6773aa63"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file XScanLib.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "c5cb4f75cf241f5a9aea324783193433a42a13b0"

    strings:
        $s4 = "XScanLib.dll" fullword ascii
        $s6 = "Ports/%s/%d" fullword ascii
        $s8 = "DEFAULT-TCP-PORT" fullword ascii
        $s9 = "PlugCheckTcpPort" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 360KB and all of them
}

rule IDTools_For_WinXP_IdtTool {
    meta:
        id = "6Twa458oB4lqFvYSNhtrWI"
        fingerprint = "v1_sha256_9e14db3721afaba3ea5e9767afff593bf2b137306fe673acd7926bf6efc78391"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file IdtTool.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "ebab6e4cb7ea82c8dc1fe4154e040e241f4672c6"

    strings:
        $s2 = "IdtTool.sys" fullword ascii
        $s4 = "Idt Tool bY tMd[CsP]" fullword wide
        $s6 = "\\\\.\\slIdtTool" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule GoodToolset_ms11046 {
    meta:
        id = "3E5u0j3b5ShzwYdv4vFwAK"
        fingerprint = "v1_sha256_2fb36a589613f97d0c3a4da58c65352689062a8ba6d432b5f3cf3b51a7e77f8c"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file ms11046.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"

    strings:
        $s1 = "[*] Token system command" fullword ascii
        $s2 = "[*] command add user 90sec 90sec" fullword ascii
        $s3 = "[*] Add to Administrators success" fullword ascii
        $s4 = "[*] User has been successfully added" fullword ascii
        $s5 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii  /* Goodware String - occured 3 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 840KB and 2 of them
}

rule Cmdshell32 {
    meta:
        id = "37NVKWzY4AjMrwGsarX1Q5"
        fingerprint = "v1_sha256_cfe3d72d33d7a3c2b70d4fa0767a921c1cfcd360b2094af40b067789cace95af"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Cmdshell32.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "3c41116d20e06dcb179e7346901c1c11cd81c596"

    strings:
        $s1 = "cmdshell.exe" fullword wide
        $s2 = "cmdshell" fullword ascii
        $s3 = "[Root@CmdShell ~]#" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 62KB and all of them
}

rule Sniffer_analyzer_SSClone_1210_full_version {
    meta:
        id = "6U6RRhwv3jy1MhrK7Xw0HJ"
        fingerprint = "v1_sha256_982a213a106794e2cddb6148b3d3a119ae17fc318ad03237da1018e1859523d7"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Sniffer analyzer SSClone 1210 full version.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "6882125babb60bd0a7b2f1943a40b965b7a03d4e"

    strings:
        $s0 = "http://www.vip80000.com/hot/index.html" fullword ascii
        $s1 = "GetConnectString" fullword ascii
        $s2 = "CnCerT.Safe.SSClone.dll" fullword ascii
        $s3 = "(*.JPG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 3580KB and all of them
}

rule x64_klock {
    meta:
        id = "2gHPXaPotHCDB2C54wqcye"
        fingerprint = "v1_sha256_2287f221402ea08ce79b777730dc0123b3e4ea299ac5d19e13ad83de9f1a56e6"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file klock.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"

    strings:
        $s1 = "Bienvenue dans un processus distant" fullword wide
        $s2 = "klock.dll" fullword ascii
        $s3 = "Erreur : le bureau courant (" fullword wide
        $s4 = "klock de mimikatz pour Windows" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 907KB and all of them
}

rule Dos_Down32 {
    meta:
        id = "4Qiqvp3RS50CVy6SJ78bTO"
        fingerprint = "v1_sha256_c1aaaaaaae2ea720d3fc1516d88d678895bcda81344e8c1f4f57e5a20e770123"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Down32.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "0365738acd728021b0ea2967c867f1014fd7dd75"

    strings:
        $s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
        $s6 = "down.exe" fullword wide
        $s15 = "get_Form1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 137KB and all of them
}

rule MarathonTool_2 {
    meta:
        id = "1nntugq4vqM5eERSkoNMDG"
        fingerprint = "v1_sha256_7581b63a7bddeac93c65b2943b9f5f568464d8f300bc7385ca73880996bd390b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file MarathonTool.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "75b5d25cdaa6a035981e5a33198fef0117c27c9c"

    strings:
        $s3 = "http://localhost/retomysql/pista.aspx?id_pista=1" fullword wide
        $s6 = "SELECT ASCII(SUBSTR(username,{0},1)) FROM USER_USERS" fullword wide
        $s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule Tools_termsrv {
    meta:
        id = "4vHyUytjw1iASH7ESRDnQY"
        fingerprint = "v1_sha256_b752ac625d1f36e4e83d0c5cef1105ba318f5a63ecb65f1fb8b568d1c0c7c5c0"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file termsrv.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "294a693d252f8f4c85ad92ee8c618cebd94ef247"

    strings:
        $s1 = "Iv\\SmSsWinStationApiPort" fullword ascii
        $s2 = " TSInternetUser " fullword wide
        $s3 = "KvInterlockedCompareExchange" fullword ascii
        $s4 = " WINS/DNS " fullword wide
        $s5 = "winerror=%1" fullword wide
        $s6 = "TermService " fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}

rule scanms_scanms {
    meta:
        id = "153RNBKZTut3dZzDf355kx"
        fingerprint = "v1_sha256_d6b33e603953194dab67104cbb9649710515050cf73afb18b2c9083a9e228e6d"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file scanms.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "47787dee6ddea2cb44ff27b6a5fd729273cea51a"

    strings:
        $s1 = "--- ScanMs Tool --- (c) 2003 Internet Security Systems ---" fullword ascii
        $s2 = "Scans for systems vulnerable to MS03-026 vuln" fullword ascii
        $s3 = "More accurate for WinXP/Win2k, less accurate for WinNT" fullword ascii /* PEStudio Blacklist: os */
        $s4 = "added %d.%d.%d.%d-%d.%d.%d.%d" fullword ascii
        $s5 = "Internet Explorer 1.0" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and 3 of them
}

rule CN_Tools_PcShare {
    meta:
        id = "1jzYHTRqIbCldXMuSZT7iQ"
        fingerprint = "v1_sha256_57bd1629abe0af1345f505514b99deb4e63ebce7363f3b0abcb76e7201d9b7b7"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file PcShare.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "ee7ba9784fae413d644cdf5a093bd93b73537652"

    strings:
        $s0 = "title=%s%s-%s;id=%s;hwnd=%d;mainhwnd=%d;mainprocess=%d;cmd=%d;" fullword wide
        $s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
        $s2 = "http://www.pcshares.cn/pcshare200/lostpass.asp" fullword wide
        $s5 = "port=%s;name=%s;pass=%s;" fullword wide
        $s16 = "%s\\ini\\*.dat" fullword wide
        $s17 = "pcinit.exe" fullword wide
        $s18 = "http://www.pcshare.cn" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 6000KB and 3 of them
}

rule pw_inspector {
    meta:
        id = "5wNPTlVzF6j9FCw8sSVC61"
        fingerprint = "v1_sha256_3b54466d80692923b93689a9e43e30dfbc63e5982cb633120795817098d68e05"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file pw-inspector.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "4f8e3e101098fc3da65ed06117b3cb73c0a66215"

    strings:
        $s1 = "-m MINLEN  minimum length of a valid password" fullword ascii
        $s2 = "http://www.thc.org" fullword ascii
        $s3 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 460KB and all of them
}

rule Dll_LoadEx {
    meta:
        id = "1f3TzaK6LmcNgVooO7L3HC"
        fingerprint = "v1_sha256_2d34baebfda884b7672ca228aed01bbc29dd85d7dbebcae166d49d2b90bf2c5a"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Dll_LoadEx.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "213d9d0afb22fe723ff570cf69ff8cdb33ada150"

    strings:
        $s0 = "WiNrOOt@126.com" fullword wide
        $s1 = "Dll_LoadEx.EXE" fullword wide
        $s3 = "You Already Loaded This DLL ! :(" fullword ascii
        $s10 = "Dll_LoadEx Microsoft " fullword wide
        $s17 = "Can't Load This Dll ! :(" fullword ascii
        $s18 = "WiNrOOt" fullword wide
        $s20 = " Dll_LoadEx(&A)..." fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 120KB and 3 of them
}

rule dat_report {
    meta:
        id = "2BXsN57Hevy9RkAWtHsBSJ"
        fingerprint = "v1_sha256_e3b21f37fae388958758af535727844d6e9696862fd9968340e1a619592c53b6"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file report.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "4582a7c1d499bb96dad8e9b227e9d5de9becdfc2"

    strings:
        $s1 = "<a href=\"http://www.xfocus.net\">X-Scan</a>" fullword ascii
        $s2 = "REPORT-ANALYSIS-OF-HOST" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 480KB and all of them
}

rule Dos_iis7 {
    meta:
        id = "5uoC4C3C5kaDw9yJz7qcRw"
        fingerprint = "v1_sha256_e0cbcb63cd2a542e6394792070392d393b2a3485f5a5ef3c6ba0f113ae9270ec"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file iis7.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"

    strings:
        $s0 = "\\\\localhost" fullword ascii
        $s1 = "iis.run" fullword ascii
        $s3 = ">Could not connecto %s" fullword ascii
        $s5 = "WHOAMI" ascii
        $s13 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule SwitchSniffer {
    meta:
        id = "1gIi6jdvfBEHo2JxqvzAfe"
        fingerprint = "v1_sha256_4c75473399a7d47b63c6247248fd2792c675740ac671028b1c0a8ba1a02f35aa"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file SwitchSniffer.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "1e7507162154f67dff4417f1f5d18b4ade5cf0cd"

    strings:
        $s0 = "NextSecurity.NET" fullword wide
        $s2 = "SwitchSniffer Setup" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule dbexpora {
    meta:
        id = "33jfWHPPUpRgFcM3G178wf"
        fingerprint = "v1_sha256_2dad6cedae6a3a446c2c4829516bffa5608ea4d1c13c907796cf4d13ec37965e"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file dbexpora.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "b55b007ef091b2f33f7042814614564625a8c79f"

    strings:
        $s0 = "SELECT A.USER FROM SYS.USER_USERS A " fullword ascii
        $s12 = "OCI 8 - OCIDescriptorFree" fullword ascii
        $s13 = "ORACommand *" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 835KB and all of them
}

rule SQLCracker {
    meta:
        id = "1K6nyjG0ygvX3fgSE9Itws"
        fingerprint = "v1_sha256_3724f4b746da413f99880564ae72bc0de867120f1f7eacaf856d42492ebe359e"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file SQLCracker.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "1aa5755da1a9b050c4c49fc5c58fa133b8380410"

    strings:
        $s0 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */
        $s1 = "_CIcos" fullword ascii
        $s2 = "kernel32.dll" fullword ascii
        $s3 = "cKmhV" fullword ascii
        $s4 = "080404B0" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 125KB and all of them
}

rule FreeVersion_debug {
    meta:
        id = "KhLZVCYnHDHwzkMxZPyTd"
        fingerprint = "v1_sha256_720606738499f87ad80d394466fc4d2010aa151c27f3890bb1c9f39590fa335e"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file debug.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"

    strings:
        $s0 = "c:\\Documents and Settings\\Administrator\\" fullword ascii
        $s1 = "Got WMI process Pid: %d" ascii
        $s2 = "This exploit will execute" ascii
        $s6 = "Found token %s " ascii
        $s7 = "Running reverse shell" ascii
        $s10 = "wmiprvse.exe" fullword ascii
        $s12 = "SELECT * FROM IIsWebInfo" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 820KB and 3 of them
}

rule Dos_look {
    meta:
        id = "1XjoKiNbqvIaxNYRkc3NxC"
        fingerprint = "v1_sha256_341c72eaa5db1953e008423374c3f322de0f8dc33fd8181362172982b52e2b8a"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file look.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "e1a37f31170e812185cf00a838835ee59b8f64ba"

    strings:
        $s1 = "<description>CHKen QQ:41901298</description>" fullword ascii
        $s2 = "version=\"9.9.9.9\"" fullword ascii
        $s3 = "name=\"CH.Ken.Tool\"" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 40KB and all of them
}

rule NtGodMode {
    meta:
        id = "7fWwjw98khXvSwpAILyKud"
        fingerprint = "v1_sha256_55efa908ebfcede207d3fe0b1072cce262af0e627e91ba8746e7a8924b8e75bd"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file NtGodMode.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "8baac735e37523d28fdb6e736d03c67274f7db77"

    strings:
        $s0 = "to HOST!" fullword ascii
        $s1 = "SS.EXE" fullword ascii
        $s5 = "lstrlen0" fullword ascii
        $s6 = "Virtual" fullword ascii  /* Goodware String - occured 6 times */
        $s19 = "RtlUnw" fullword ascii /* Goodware String - occured 1 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 45KB and all of them
}

rule Dos_NC {
    meta:
        id = "3CQKxMWCZUbYOnPPOrXeE0"
        fingerprint = "v1_sha256_59021331c180994b4d51d234293348dd812833fe8ae0d7fbead20f924b630049"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file NC.EXE"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "57f0839433234285cc9df96198a6ca58248a4707"

    strings:
        $s1 = "nc -l -p port [options] [hostname] [port]" fullword ascii
        $s2 = "invalid connection to [%s] from %s [%s] %d" fullword ascii
        $s3 = "post-rcv getsockname failed" fullword ascii
        $s4 = "Failed to execute shell, error = %s" fullword ascii
        $s5 = "UDP listen needs -p arg" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 290KB and all of them
}

rule WebCrack4_RouterPasswordCracking {
    meta:
        id = "3dBZEcyUkPu6t5cYYVzQFU"
        fingerprint = "v1_sha256_48456f82163806852ecef3d71c2c8247f6c74c31ce28472c80a914a98247bdb3"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file WebCrack4-RouterPasswordCracking.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "00c68d1b1aa655dfd5bb693c13cdda9dbd34c638"

    strings:
        $s0 = "http://www.site.com/test.dll?user=%USERNAME&pass=%PASSWORD" fullword ascii
        $s1 = "Username: \"%s\", Password: \"%s\", Remarks: \"%s\"" fullword ascii
        $s14 = "user:\"%s\" pass: \"%s\" result=\"%s\"" fullword ascii
        $s16 = "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)" fullword ascii
        $s20 = "List count out of bounds (%d)+Operation not allowed on sorted string list%String" wide
    condition:
        uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule HScan_v1_20_oncrpc {
    meta:
        id = "leZudE9PEjE5HNoIjXEcO"
        fingerprint = "v1_sha256_e0cbd2f7e612b016948cbbe910b498d091517fdaa6206a72ef70b2090e64eb41"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file oncrpc.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "e8f047eed8d4f6d2f5dbaffdd0e6e4a09c5298a2"

    strings:
        $s1 = "clnt_raw.c - Fatal header serialization error." fullword ascii
        $s2 = "svctcp_.c - cannot getsockname or listen" fullword ascii
        $s3 = "too many connections (%d), compilation constant FD_SETSIZE was only %d" fullword ascii
        $s4 = "svc_run: - select failed" fullword ascii
        $s5 = "@(#)bindresvport.c" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 340KB and 4 of them
}

rule hscan_gui {
    meta:
        id = "2APrf7etZNQfdQcQMrmKlT"
        fingerprint = "v1_sha256_c87cfe78324638ac9d35c7fd1e47f24014c470b0892ceceaf394278d9706157b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file hscan-gui.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "1885f0b7be87f51c304b39bc04b9423539825c69"

    strings:
        $s0 = "Hscan.EXE" fullword wide
        $s1 = "RestTool.EXE" fullword ascii
        $s3 = "Hscan Application " fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 550KB and all of them
}

rule S_MultiFunction_Scanners_s {
    meta:
        id = "1G8JIcBgYYeBe3oKIhpgeY"
        fingerprint = "v1_sha256_96f0692c54d74388f8602a03475d95a2fcd89692dd189f9363592745a70c234b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file s.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "79b60ffa1c0f73b3c47e72118e0f600fcd86b355"

    strings:
        $s0 = "C:\\WINDOWS\\temp\\pojie.exe /l=" fullword ascii
        $s1 = "C:\\WINDOWS\\temp\\s.exe" fullword ascii
        $s2 = "C:\\WINDOWS\\temp\\s.exe tcp " fullword ascii
        $s3 = "explorer.exe http://www.hackdos.com" fullword ascii
        $s4 = "C:\\WINDOWS\\temp\\pojie.exe" fullword ascii
        $s5 = "Failed to read file or invalid data in file!" fullword ascii
        $s6 = "www.hackdos.com" fullword ascii
        $s7 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
        $s11 = "The interface of kernel library is invalid!" fullword ascii
        $s12 = "eventvwr" fullword ascii
        $s13 = "Failed to decompress data!" fullword ascii
        $s14 = "NOTEPAD.EXE result.txt" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8000KB and 4 of them
}

rule mswin_ntlm_auth {
    meta:
        id = "4evRH1DjcsS7SB6jxPs1cC"
        fingerprint = "v1_sha256_6c423015847ade8b9c67a525d95e2b2070d940a165040744ec1fdcbd934a1c36"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file mswin_ntlm_auth.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "390af28581db224af38a885b7ffad819c9b3be89"

    strings:
        $s1 = "Login attempt had result %d" fullword ascii
        $s2 = "Username string exceeds %d bytes, rejecting" fullword ascii
        $s3 = "checking domain: '%s', user: '%s'" fullword ascii
        $s4 = "Usage: %s [-d] [-v] [-A|D LocalUserGroup] [-h]" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 380KB and all of them
}

rule Dos_GetPass {
    meta:
        id = "1GThCCyLWDHdh1QZHeIOxS"
        fingerprint = "v1_sha256_ea1410984fb1f66422faa943f1f16873f4e0d5ff1afa68c2d28f36889e214a52"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file GetPass.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "d18d952b24110b83abd17e042f9deee679de6a1a"

    strings:
        $s0 = "GetLogonS" ascii
        $s3 = "/showthread.php?t=156643" ascii
        $s8 = "To Run As Administ" ascii
        $s18 = "EnableDebugPrivileg" fullword ascii
        $s19 = "sedebugnameValue" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 890KB and all of them
}

rule update_PcMain {
    meta:
        id = "6vhXrLFLGALbiYlpdpkQgN"
        fingerprint = "v1_sha256_a5dc21dfdbeb9f391b4f784f18e062b4edb53aaa0ad47e4b86a0b38bfd163c06"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file PcMain.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "aa68323aaec0269b0f7e697e69cce4d00a949caa"

    strings:
        $s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322" ascii
        $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
        $s2 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" fullword ascii
        $s3 = "\\svchost.exe -k " fullword ascii
        $s4 = "SYSTEM\\ControlSet001\\Services\\%s" fullword ascii
        $s9 = "Global\\%s-key-event" fullword ascii
        $s10 = "%d%d.exe" fullword ascii
        $s14 = "%d.exe" fullword ascii
        $s15 = "Global\\%s-key-metux" fullword ascii
        $s18 = "GET / HTTP/1.1" fullword ascii
        $s19 = "\\Services\\" fullword ascii
        $s20 = "qy001id=%d;qy001guid=%s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}

rule Dos_sys {
    meta:
        id = "15IDCyqUCrkKf9tEM7Ka9a"
        fingerprint = "v1_sha256_3b3f55c45ebfe4ab6d8e6b06a3c452c84d4f755f984d913c683a49a8fd570d9d"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file sys.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "b5837047443f8bc62284a0045982aaae8bab6f18"

    strings:
        $s0 = "'SeDebugPrivilegeOpen " fullword ascii
        $s6 = "Author: Cyg07*2" fullword ascii
        $s12 = "from golds7n[LAG]'J" fullword ascii
        $s14 = "DAMAGE" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule dat_xpf {
    meta:
        id = "5e24E943WFavGpvspVsZlw"
        fingerprint = "v1_sha256_3a56071d14c14373e3bfdb051e3e0860e05e0a275bd894530c6bd94fad4680ea"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file xpf.sys"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "761125ab594f8dc996da4ce8ce50deba49c81846"

    strings:
        $s1 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
        $s2 = "\\Device\\XScanPF" fullword wide
        $s3 = "\\DosDevices\\XScanPF" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule Project1 {
    meta:
        id = "5WeQqxKHwexZWZUB53wmOH"
        fingerprint = "v1_sha256_c26590f13a185eb42a27d27e6b5996f7fdf4d5c146fb74062686f356ec4db47d"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Project1.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"

    strings:
        $s1 = "EXEC master.dbo.sp_addextendedproc 'xp_cmdshell','xplog70.dll'" fullword ascii
        $s2 = "Password.txt" fullword ascii
        $s3 = "LoginPrompt" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule Arp_EMP_v1_0 {
    meta:
        id = "4DEUEYIYVtdwIY5htTa5F9"
        fingerprint = "v1_sha256_e46b0f730945dad3c75b6865f30005f4d5fa09c53e3a27c275ca22da9cc89e8d"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Arp EMP v1.0.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"

    strings:
        $s0 = "Arp EMP v1.0.exe" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule CN_Tools_MyUPnP {
    meta:
        id = "6HzL4zuUUGsd2ChdwjSaUB"
        fingerprint = "v1_sha256_0bdd0d98dc5218bbe799e5e510c5f27d74a1ef398b09962f4267f846088f726e"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file MyUPnP.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "15b6fca7e42cd2800ba82c739552e7ffee967000"

    strings:
        $s1 = "<description>BYTELINKER.COM</description>" fullword ascii
        $s2 = "myupnp.exe" fullword ascii
        $s3 = "LOADER ERROR" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1500KB and all of them
}

rule logfile_daemon {
    meta:
        id = "JeMsfhTGgyd95995kB9N0"
        fingerprint = "v1_sha256_4aa7550ba66789932f2ff8a6bb960f3f6581e5845df41c28d88b46f8f90b40be"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file logfile-daemon.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "132a8f628109cda7eb58c91f1c5e5e626cbfd14a"

    strings:
        $s0 = "Error: usage: %s <logfile>" fullword ascii
        $s1 = "vBWSSSj" fullword ascii /* Goodware String - occured 24 times */
        $s2 = "t-Ht!Ht" fullword ascii /* Goodware String - occured 25 times */
        $s3 = "QSUVW3" fullword ascii /* Goodware String - occured 162 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 260KB and all of them
}

rule CN_Tools_Shiell {
    meta:
        id = "6KtQkQQdU1I6DBNMXXJsY4"
        fingerprint = "v1_sha256_44c494c24c090b21c3c201d57f910e8f4d5132a863715a090fa1e18c9d349d48"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Shiell.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "b432d80c37abe354d344b949c8730929d8f9817a"

    strings:
        $s1 = "C:\\Users\\Tong\\Documents\\Visual Studio 2012\\Projects\\Shift shell" ascii
        $s2 = "C:\\Windows\\System32\\Shiell.exe" fullword wide
        $s3 = "Shift shell.exe" fullword wide
        $s4 = "\" /v debugger /t REG_SZ /d \"" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 1500KB and 2 of them
}

rule cndcom_cndcom {
    meta:
        id = "7jmKG2zzJxR3hqwfnLGLMc"
        fingerprint = "v1_sha256_2817b2a79957f0706cd97a19e776b723a9e3b785289355964474827131884a6b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file cndcom.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "08bbe6312342b28b43201125bd8c518531de8082"

    strings:
        $s1 = "- Rewritten by HDM last <hdm [at] metasploit.com>" fullword ascii
        $s2 = "- Usage: %s <Target ID> <Target IP>" fullword ascii
        $s3 = "- Remote DCOM RPC Buffer Overflow Exploit" fullword ascii
        $s4 = "- Warning:This Code is more like a dos tool!(Modify by pingker)" fullword ascii
        $s5 = "Windows NT SP6 (Chinese)" fullword ascii
        $s6 = "- Original code by FlashSky and Benjurry" fullword ascii
        $s7 = "\\C$\\123456111111111111111.doc" fullword wide
        $s8 = "shell3all.c" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule IsDebug_V1_4 {
    meta:
        id = "2bj4kG8RomebSeg3qsYOaS"
        fingerprint = "v1_sha256_d656327c33533b5ef7dc70ec00250ee35d878794fae189829a0ecad958f96616"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file IsDebug V1.4.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "ca32474c358b4402421ece1cb31714fbb088b69a"

    strings:
        $s0 = "IsDebug.dll" fullword ascii
        $s1 = "SV Dumper V1.0" fullword wide
        $s2 = "(IsDebuggerPresent byte Patcher)" fullword ascii
        $s8 = "Error WriteMemory failed" fullword ascii
        $s9 = "IsDebugPresent" fullword ascii
        $s10 = "idb_Autoload" fullword ascii
        $s11 = "Bin Files" fullword ascii
        $s12 = "MASM32 version" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 30KB and all of them
}

rule HTTPSCANNER {
    meta:
        id = "3hVY18wQa19eCuzOdmL7RP"
        fingerprint = "v1_sha256_0f1460101198d8b139b7cc0674bef2fc7b3d2a24249f521396b7bbe4318a83d5"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file HTTPSCANNER.EXE"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "ae2929346944c1ea3411a4562e9d5e2f765d088a"

    strings:
        $s1 = "HttpScanner.exe" fullword wide
        $s2 = "HttpScanner" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 3500KB and all of them
}

rule HScan_v1_20_PipeCmd {
    meta:
        id = "2fjcgqkfNRJhWeufHyOsac"
        fingerprint = "v1_sha256_91ed275896c2520893ba1af26b2563c0bd3564a9c5f9d812f35464469e27307b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file PipeCmd.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "64403ce63b28b544646a30da3be2f395788542d6"

    strings:
        $s1 = "%SystemRoot%\\system32\\PipeCmdSrv.exe" fullword ascii
        $s2 = "PipeCmd.exe" fullword wide
        $s3 = "Please Use NTCmd.exe Run This Program." fullword ascii
        $s4 = "%s\\pipe\\%s%s%d" fullword ascii
        $s5 = "\\\\.\\pipe\\%s%s%d" fullword ascii
        $s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
        $s7 = "This is a service executable! Couldn't start directly." fullword ascii
        $s8 = "Connecting to Remote Server ...Failed" fullword ascii
        $s9 = "PIPECMDSRV" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and 4 of them
}

rule Dos_fp {
    meta:
        id = "20xQxTA8zA2UOJbWHASmLy"
        fingerprint = "v1_sha256_cc09743269ee36862c95c9323ad271ca9b6c350cf25163d126fef0f86bc6f671"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file fp.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"

    strings:
        $s1 = "fpipe -l 53 -s 53 -r 80 192.168.1.101" fullword ascii
        $s2 = "FPipe.exe" fullword wide
        $s3 = "http://www.foundstone.com" fullword ascii
        $s4 = "%s %s port %d. Address is already in use" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 65KB and all of them
}

rule Dos_netstat {
    meta:
        id = "3SKENwjTL0skiPjcYyXssP"
        fingerprint = "v1_sha256_e2b908308616c3f2c94849b4f22f0e9bb130b5759d89161604505ff25681be55"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file netstat.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "d0444b7bd936b5fc490b865a604e97c22d97e598"

    strings:
        $s0 = "w03a2409.dll" fullword ascii
        $s1 = "Retransmission Timeout Algorithm    = unknown (%1!u!)" fullword wide  /* Goodware String - occured 2 times */
        $s2 = "Administrative Status  = %1!u!" fullword wide  /* Goodware String - occured 2 times */
        $s3 = "Packet Too Big            %1!-10u!  %2!-10u!" fullword wide  /* Goodware String - occured 2 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule CN_Tools_xsniff {
    meta:
        id = "3kQmjiVhWIODuRZeqAzA7a"
        fingerprint = "v1_sha256_a32d07ecd635ad71edaa37d9b1e5f66d8ce5a7f84f1bba6eb06deb1f49a879c8"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file xsniff.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "d61d7329ac74f66245a92c4505a327c85875c577"

    strings:
        $s0 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
        $s1 = "HOST: %s USER: %s, PASS: %s" fullword ascii
        $s2 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
        $s10 = "Code by glacier <glacier@xfocus.org>" fullword ascii
        $s11 = "%-5s%s->%s Bytes=%d TTL=%d Type: %d,%d ID=%d SEQ=%d" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule mswin_check_ad_group {
    meta:
        id = "43goRlchc5ffOibIgP7tiQ"
        fingerprint = "v1_sha256_1cf375788ea7642e7621e49b54ffd8ddd69ae11aab96b95b64a7663f79b94e43"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file mswin_check_ad_group.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "15fa3d91c5e4836f27b9809d4efedc5a947fb221"

    strings:
        $s1 = "Domain Global group mode enabled using '%s' as default domain." fullword ascii
        $s2 = "Warning: running in case insensitive mode !!!" fullword ascii
        $s3 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
        $s4 = "Windows group: %S, Squid group: %S" fullword ascii
        $s5 = "%s[%d]: " fullword ascii
        $s6 = "DC Active Directory Site is %s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 380KB and 4 of them
}

rule MSSqlPass {
    meta:
        id = "4SY8HVCKOTAXBHgTAzeQsO"
        fingerprint = "v1_sha256_8037316eb157f8693bd342911af5fe5292f3ef8a3c169c80bc70edbabd7a92e6"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file MSSqlPass.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "172b4e31ed15d1275ac07f3acbf499daf9a055d7"

    strings:
        $s0 = "Reveals the passwords stored in the Registry by Enterprise Manager of SQL Server" wide
        $s1 = "empv.exe" fullword wide
        $s2 = "Enterprise Manager PassView" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 120KB and all of them
}

rule WSockExpert {
    meta:
        id = "3tsWyyls7DUDBCyxxYDNxn"
        fingerprint = "v1_sha256_34ac3c5f0651ccab851d67da8863e0e305f981cf53a06d46c23f19736cc1c400"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file WSockExpert.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "2962bf7b0883ceda5e14b8dad86742f95b50f7bf"

    strings:
        $s1 = "OpenProcessCmdExecute!" fullword ascii
        $s2 = "http://www.hackp.com" fullword ascii
        $s3 = "'%s' is not a valid time!'%s' is not a valid date and time" fullword wide
        $s4 = "SaveSelectedFilterCmdExecute" fullword ascii
        $s5 = "PasswordChar@" fullword ascii
        $s6 = "WSockHook.DLL" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule Ms_Viru_racle {
    meta:
        id = "1Uqjot4nG6vh47RCjZQcKF"
        fingerprint = "v1_sha256_d36db04c6a62a72e9f3079d09aedc9056c0a5032b4594af4d02ba55373f8b6a4"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file racle.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "13116078fff5c87b56179c5438f008caf6c98ecb"

    strings:
        $s0 = "PsInitialSystemProcess @%p" fullword ascii
        $s1 = "PsLookupProcessByProcessId(%u) Failed" fullword ascii
        $s2 = "PsLookupProcessByProcessId(%u) => %p" fullword ascii
        $s3 = "FirstStage() Loaded, CurrentThread @%p Stack %p - %p" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 210KB and all of them
}

rule lamescan3 {
    meta:
        id = "XI9T8dh4s8pDaVOu9sY9y"
        fingerprint = "v1_sha256_8246128fa4378b0479a0c051965188c7c3fa0f52c8acc8934ef8af3155a85590"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file lamescan3.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "3130eefb79650dab2e323328b905e4d5d3a1d2f0"

    strings:
        $s1 = "dic\\loginlist.txt" fullword ascii
        $s2 = "Radmin.exe" fullword ascii
        $s3 = "lamescan3.pdf!" fullword ascii
        $s4 = "dic\\passlist.txt" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 3740KB and all of them
}

rule CN_Tools_pc {
    meta:
        id = "62AZXcOyBsMsE602phzrMA"
        fingerprint = "v1_sha256_648159c6c728e120af6532ca9251fa533c38d9f9b8439bfb1b65695a09e675a0"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file pc.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "5cf8caba170ec461c44394f4058669d225a94285"

    strings:
        $s0 = "\\svchost.exe" fullword ascii
        $s2 = "%s%08x.001" fullword ascii
        $s3 = "Qy001Service" fullword ascii
        $s4 = "/.MIKY" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Dos_Down64 {
    meta:
        id = "1OraqqgOOMQb52aVf1ocVl"
        fingerprint = "v1_sha256_e18b5721ef1fa364f6a09bd44ed018d9803d97a462bb1e91c4b8d3bcf09c4b4a"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Down64.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "43e455e43b49b953e17a5b885ffdcdf8b6b23226"

    strings:
        $s1 = "C:\\Windows\\Temp\\Down.txt" fullword wide
        $s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
        $s3 = "C:\\Windows\\Temp\\" fullword wide
        $s4 = "ProcessXElement" fullword ascii
        $s8 = "down.exe" fullword wide
        $s20 = "set_Timer1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule epathobj_exp32 {
    meta:
        id = "7eM5UaWnBjADkF7uYIJbma"
        fingerprint = "v1_sha256_aa9554d11b629bed3203a840b5a631ab28442bb5b6b90c08eb41058769a037c8"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file epathobj_exp32.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "ed86ff44bddcfdd630ade8ced39b4559316195ba"

    strings:
        $s0 = "Watchdog thread %d waiting on Mutex" fullword ascii
        $s1 = "Exploit ok run command" fullword ascii
        $s2 = "\\epathobj_exp\\Release\\epathobj_exp.pdb" fullword ascii
        $s3 = "Alllocated userspace PATHRECORD () %p" fullword ascii
        $s4 = "Mutex object did not timeout, list not patched" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 270KB and all of them
}

rule Tools_unknown {
    meta:
        id = "6aZDBwwRTTP8K631s41xrH"
        fingerprint = "v1_sha256_493bb63d4dd519efbf53a29fa44ef74f0a85943b2d9f49f11e3daa57c6b03d8e"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file unknown.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "4be8270c4faa1827177e2310a00af2d5bcd2a59f"

    strings:
        $s1 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
        $s2 = "GET /ok.asp?id=1__sql__ HTTP/1.1" fullword ascii
        $s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
        $s4 = "Failed to clear tab control Failed to delete tab at index %d\"Failed to retrieve" wide
        $s5 = "Host: 127.0.0.1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule PLUGIN_AJunk {
    meta:
        id = "10aq7jxwADNFUwL6pzZpF9"
        fingerprint = "v1_sha256_e37504aab506138493ddc0979697502819824ef00c7931599130fafb5d84a7a9"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file AJunk.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "eb430fcfe6d13b14ff6baa4b3f59817c0facec00"

    strings:
        $s1 = "AJunk.dll" fullword ascii
        $s2 = "AJunk.DLL" fullword wide
        $s3 = "AJunk Dynamic Link Library" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 560KB and all of them
}

rule IISPutScanner {
    meta:
        id = "6v4SRv1pH0t577NwsGHPzm"
        fingerprint = "v1_sha256_b2af9003cef528610280866bf00a9716b4421a5f7c65e7c8ec3202af9a592de1"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file IISPutScanner.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "9869c70d6a9ec2312c749aa17d4da362fa6e2592"

    strings:
        $s2 = "KERNEL32.DLL" fullword ascii
        $s3 = "ADVAPI32.DLL" fullword ascii
        $s4 = "VERSION.DLL" fullword ascii
        $s5 = "WSOCK32.DLL" fullword ascii
        $s6 = "COMCTL32.DLL" fullword ascii
        $s7 = "GDI32.DLL" fullword ascii
        $s8 = "SHELL32.DLL" fullword ascii
        $s9 = "USER32.DLL" fullword ascii
        $s10 = "OLEAUT32.DLL" fullword ascii
        $s11 = "LoadLibraryA" fullword ascii
        $s12 = "GetProcAddress" fullword ascii
        $s13 = "VirtualProtect" fullword ascii
        $s14 = "VirtualAlloc" fullword ascii
        $s15 = "VirtualFree" fullword ascii
        $s16 = "ExitProcess" fullword ascii
        $s17 = "RegCloseKey" fullword ascii
        $s18 = "GetFileVersionInfoA" fullword ascii
        $s19 = "ImageList_Add" fullword ascii
        $s20 = "BitBlt" fullword ascii
        $s21 = "ShellExecuteA" fullword ascii
        $s22 = "ActivateKeyboardLayout" fullword ascii
        $s23 = "BBABORT" fullword wide
        $s25 = "BBCANCEL" fullword wide
        $s26 = "BBCLOSE" fullword wide
        $s27 = "BBHELP" fullword wide
        $s28 = "BBIGNORE" fullword wide
        $s29 = "PREVIEWGLYPH" fullword wide
        $s30 = "DLGTEMPLATE" fullword wide
        $s31 = "TABOUTBOX" fullword wide
        $s32 = "TFORM1" fullword wide
        $s33 = "MAINICON" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and filesize > 350KB and all of them
}

rule IDTools_For_WinXP_IdtTool_2 {
    meta:
        id = "2cvm7Ng0ntWDxCyXwvQSk7"
        fingerprint = "v1_sha256_0e3b2e6f1542f2bc199636cb24aa0dc26a03d103531f3b2d60d1e3646ac584ec"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file IdtTool.sys"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "07feb31dd21d6f97614118b8a0adf231f8541a67"

    strings:
        $s0 = "\\Device\\devIdtTool" fullword wide
        $s1 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
        $s3 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
        $s6 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
        $s7 = "IoCreateDevice" fullword ascii /* Goodware String - occured 988 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 7KB and all of them
}

rule hkmjjiis6 {
    meta:
        id = "7I7fwezeVPw6S8bZyNowRs"
        fingerprint = "v1_sha256_4ea95b7a5bd24e0dfdcef045d101b7f15e18b20f1328901bb340d9aaad336981"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file hkmjjiis6.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"

    strings:
        $s1 = "comspec" fullword ascii
        $s2 = "user32.dlly" ascii
        $s3 = "runtime error" ascii
        $s4 = "WinSta0\\Defau" ascii
        $s5 = "AppIDFlags" fullword ascii
        $s6 = "GetLag" fullword ascii
        $s7 = "* FROM IIsWebInfo" ascii
        $s8 = "wmiprvse.exe" ascii
        $s9 = "LookupAcc" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule Dos_lcx {
    meta:
        id = "3kKkFsEwkE3uaoWZtByJE7"
        fingerprint = "v1_sha256_bbe215fb27825b4f4bbfa71808ac945f341efbc70a21f79689065982a843d7f1"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file lcx.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "b6ad5dd13592160d9f052bb47b0d6a87b80a406d"

    strings:
        $s0 = "c:\\Users\\careful_snow\\" ascii
        $s1 = "Desktop\\Htran\\Release\\Htran.pdb" ascii
        $s3 = "[SERVER]connection to %s:%d error" fullword ascii
        $s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
        $s6 = "=========== Code by lion & bkbll, Welcome to [url]http://www.cnhonker.com[/url] " ascii
        $s7 = "[-] There is a error...Create a new connection." fullword ascii
        $s8 = "[+] Accept a Client on port %d from %s" fullword ascii
        $s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
        $s13 = "[+] Make a Connection to %s:%d...." fullword ascii
        $s16 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
        $s17 = "[+] Waiting another Client on port:%d...." fullword ascii
        $s18 = "[+] Accept a Client on port %d from %s ......" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule x_way2_5_X_way {
    meta:
        id = "2eFglFFSLyeXtvGutdlkdA"
        fingerprint = "v1_sha256_6261de5db1e7527f7726effe26ed5f88638e6cb378db4c99183dddcd42ae231f"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file X-way.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "8ba8530fbda3e8342e8d4feabbf98c66a322dac6"

    strings:
        $s0 = "TTFTPSERVERFRM" fullword wide
        $s1 = "TPORTSCANSETFRM" fullword wide
        $s2 = "TIISSHELLFRM" fullword wide
        $s3 = "TADVSCANSETFRM" fullword wide
        $s4 = "ntwdblib.dll" fullword ascii
        $s5 = "TSNIFFERFRM" fullword wide
        $s6 = "TCRACKSETFRM" fullword wide
        $s7 = "TCRACKFRM" fullword wide
        $s8 = "dbnextrow" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and 5 of them
}

rule tools_Sqlcmd {
    meta:
        id = "1T9qI4y9iCVsNgrCddVP0P"
        fingerprint = "v1_sha256_aa600f7c56d72d767e9ca51d8b1ee2b2c62302ea1afbed39e4670debd30c5247"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Sqlcmd.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "99d56476e539750c599f76391d717c51c4955a33"

    strings:
        $s0 = "[Usage]:  %s <HostName|IP> <UserName> <Password>" fullword ascii
        $s1 = "=============By uhhuhy(Feb 18,2003) - http://www.cnhonker.net=============" fullword ascii /* PEStudio Blacklist: os */
        $s4 = "Cool! Connected to SQL server on %s successfully!" fullword ascii
        $s5 = "EXEC master..xp_cmdshell \"%s\"" fullword ascii
        $s6 = "=======================Sqlcmd v0.21 For HScan v1.20=======================" fullword ascii
        $s10 = "Error,exit!" fullword ascii
        $s11 = "Sqlcmd>" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 40KB and 3 of them
}

rule Sword1_5 {
    meta:
        id = "JdCOsbOW1bGY4xd1gOGl4"
        fingerprint = "v1_sha256_aac861e9298bf835feec2b1124e9e5f74e207b2a63952735e57d7def475009ab"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Sword1.5.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"

    strings:
        $s3 = "http://www.ip138.com/ip2city.asp" fullword wide
        $s4 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
        $s6 = "ListBox_Command" fullword wide
        $s13 = "md=7fef6171469e80d32c0559f88b377245&submit=MD5+Crack" fullword wide
        $s18 = "\\Set.ini" fullword wide
        $s19 = "OpenFileDialog1" fullword wide
        $s20 = " (*.txt)|*.txt" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 400KB and 4 of them
}

rule Tools_scan {
    meta:
        id = "5EflbUgAKX4rCXeQwRRufM"
        fingerprint = "v1_sha256_d8bf2e4a4634f74ce548a5824090502f2ccef382bdbcaf795df711e88a325912"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file scan.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "c580a0cc41997e840d2c0f83962e7f8b636a5a13"

    strings:
        $s2 = "Shanlu Studio" fullword wide
        $s3 = "_AutoAttackMain" fullword ascii
        $s4 = "_frmIpToAddr" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Dos_c {
    meta:
        id = "5JOGHQN2D9kC27g2uSQbeu"
        fingerprint = "v1_sha256_2865b50e6a323462fab39bd84571939c618cf6f00e147039f6e699ba4d195a00"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file c.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "3deb6bd52fdac6d5a3e9a91c585d67820ab4df78"

    strings:
        $s0 = "!Win32 .EXE." fullword ascii
        $s1 = ".MPRESS1" fullword ascii
        $s2 = ".MPRESS2" fullword ascii
        $s3 = "XOLEHLP.dll" fullword ascii
        $s4 = "</body></html>" fullword ascii
        $s8 = "DtcGetTransactionManagerExA" fullword ascii  /* Goodware String - occured 12 times */
        $s9 = "GetUserNameA" fullword ascii  /* Goodware String - occured 305 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule arpsniffer {
    meta:
        id = "5FFqJU0hONmPWxHcqSmqxQ"
        fingerprint = "v1_sha256_eb0a425be0fff87eb58689a4eee4b6729e8ee985e6224790111322d4b182caf1"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file arpsniffer.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "7d8753f56fc48413fc68102cff34b6583cb0066c"

    strings:
        $s1 = "SHELL" ascii
        $s2 = "PacketSendPacket" fullword ascii
        $s3 = "ArpSniff" ascii
        $s4 = "pcap_loop" fullword ascii  /* Goodware String - occured 3 times */
        $s5 = "packet.dll" fullword ascii  /* Goodware String - occured 4 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 120KB and all of them
}

rule pw_inspector_2 {
    meta:
        id = "1fk4r97QamhwN7KeQuUktk"
        fingerprint = "v1_sha256_7d2021ff471f03deb9e6d8b62fcb218ae3198f21fd7b8fa1fdd9b96228b8c2f8"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file pw-inspector.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "e0a1117ee4a29bb4cf43e3a80fb9eaa63bb377bf"

    strings:
        $s1 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
        $s2 = "Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p " ascii
        $s3 = "PW-Inspector" fullword ascii
        $s4 = "i:o:m:M:c:lunps" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule datPcShare {
    meta:
        id = "77e6sUY1yxvPidhwM8jp1w"
        fingerprint = "v1_sha256_15297a8019192371032fc11b966d1a89d951c176da6d64e80ca5a201f55341c0"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file datPcShare.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "87acb649ab0d33c62e27ea83241caa43144fc1c4"

    strings:
        $s1 = "PcShare.EXE" fullword wide
        $s2 = "MZKERNEL32.DLL" fullword ascii
        $s3 = "PcShare" fullword wide
        $s4 = "QQ:4564405" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Tools_xport {
    meta:
        id = "23HiOBljHK5IxhdJXb4Tbj"
        fingerprint = "v1_sha256_9eea73732643f74b4802af0672f5c3ab09cc54cfecd80f8903efc26b7ceaec29"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file xport.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "9584de562e7f8185f721e94ee3cceac60db26dda"

    strings:
        $s1 = "Match operate system failed, 0x%00004X:%u:%d(Window:TTL:DF)" fullword ascii
        $s2 = "Example: xport www.xxx.com 80 -m syn" fullword ascii
        $s3 = "%s - command line port scanner" fullword ascii
        $s4 = "xport 192.168.1.1 1-1024 -t 200 -v" fullword ascii
        $s5 = "Usage: xport <Host> <Ports Scope> [Options]" fullword ascii
        $s6 = ".\\port.ini" fullword ascii
        $s7 = "Port scan complete, total %d port, %d port is opened, use %d ms." fullword ascii
        $s8 = "Code by glacier <glacier@xfocus.org>" fullword ascii
        $s9 = "http://www.xfocus.org" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule fakeauth_auth {
    meta:
        id = "1pP4oBCN1e0tu6n6XKNDUM"
        fingerprint = "v1_sha256_2711e43d839390c6cd5ce1202b53373c36016d7bfea308b811842ea125f7e5b1"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file fakeauth_auth.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "4d6311159e10ffbb904059ccfda70fde2fee1f7e"

    strings:
        $s0 = "sending 'NA invalid credentials, user=%s' to squid" fullword ascii
        $s11 = "BH wrong packet type! user=%s" fullword ascii
        $s16 = "fakeauth_auth[%ld]: " fullword ascii
        $s20 = "sending 'TT %s' to squid" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 260KB and all of them
}

rule Pc_xai {
    meta:
        id = "YZoPF5T34PcwXlMIoHzXG"
        fingerprint = "v1_sha256_6525d3cb5eaeaaf76bb589c466e4f9864380d369cca83b12be7fbe2ff2e3c6cb"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file xai.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "f285a59fd931ce137c08bd1f0dae858cc2486491"

    strings:
        $s1 = "Powered by CoolDiyer @ C.Rufus Security Team 05/19/2008  http://www.xcodez.com/" fullword wide
        $s2 = "%SystemRoot%\\System32\\" fullword ascii
        $s3 = "%APPDATA%\\" fullword ascii
        $s4 = "---- C.Rufus Security Team ----" fullword wide
        $s5 = "www.snzzkz.com" fullword wide
        $s6 = "%CommonProgramFiles%\\" fullword ascii
        $s7 = "GetRand.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Radmin_Hash {
    meta:
        id = "5q8RbUmkPnIUdzUnyS7CiM"
        fingerprint = "v1_sha256_d6ee13a2ed30bb44471593386521f67be0d6ccd6f8a0ebf8557012a099f81d3d"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Radmin_Hash.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "be407bd5bf5bcd51d38d1308e17a1731cd52f66b"

    strings:
        $s1 = "<description>IEBars</description>" fullword ascii
        $s2 = "PECompact2" fullword ascii
        $s3 = "Radmin, Remote Administrator" fullword wide
        $s4 = "Radmin 3.0 Hash " fullword wide
        $s5 = "HASH1.0" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule OSEditor {
    meta:
        id = "69MlYNYtZOm8V57FsggQ53"
        fingerprint = "v1_sha256_6531c0b3c0f6123d9eda34ed028f05054e4805e5c329da4b29e4f37f9b5fc1b2"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file OSEditor.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "6773c3c6575cf9cfedbb772f3476bb999d09403d"

    strings:
        $s1 = "OSEditor.exe" fullword wide
        $s2 = "netsafe" wide
        $s3 = "OSC Editor" fullword wide
        $s4 = "GIF89" ascii
        $s5 = "Unlock" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule GoodToolset_ms11011 {
    meta:
        id = "6Q0OhLe8IXiAP81EnGYVAA"
        fingerprint = "v1_sha256_99dd27eba7da44c71098446e17abfe626de91e899e28c2d2e99e7b54b9e0c825"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file ms11011.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"

    strings:
        $s0 = "\\i386\\Hello.pdb" ascii
        $s1 = "OS not supported." fullword ascii
        $s3 = "Not supported." fullword wide  /* Goodware String - occured 3 times */
        $s4 = "SystemDefaultEUDCFont" fullword wide  /* Goodware String - occured 18 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule FreeVersion_release {
    meta:
        id = "2fYx8iBZTJBB6YBsJP7kts"
        fingerprint = "v1_sha256_38722afb3b955aced2e68e2048a3268722524f61784dcb45c6a695b5684230eb"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file release.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "f42e4b5748e92f7a450eb49fc89d6859f4afcebb"

    strings:
        $s1 = "-->Got WMI process Pid: %d " ascii
        $s2 = "This exploit will execute \"net user " ascii
        $s3 = "net user temp 123456 /add & net localgroup administrators temp /add" fullword ascii
        $s4 = "Running reverse shell" ascii
        $s5 = "wmiprvse.exe" fullword ascii
        $s6 = "SELECT * FROM IIsWebInfo" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule churrasco {
    meta:
        id = "3hNm6Z9RxHglislJZhH9Vz"
        fingerprint = "v1_sha256_36ca7c8d1579eeb571c182c033c312b3b231313b8950c1e24eeb3df793b004c4"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file churrasco.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "a8d4c177948a8e60d63de9d0ed948c50d0151364"

    strings:
        $s1 = "Done, command should have ran as SYSTEM!" ascii
        $s2 = "Running command with SYSTEM Token..." ascii
        $s3 = "Thread impersonating, got NETWORK SERVICE Token: 0x%x" ascii
        $s4 = "Found SYSTEM token 0x%x" ascii
        $s5 = "Thread not impersonating, looking for another thread..." ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}
rule x64_KiwiCmd {
    meta:
        id = "48KFMPZ5ubTtlKwhENMdXd"
        fingerprint = "v1_sha256_b49a70a49a67fbb57d643b38155482177f594bd1f01f5464c4f36b265aac48d8"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file KiwiCmd.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"

    strings:
        $s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
        $s2 = "Kiwi Cmd no-gpo" fullword wide
        $s3 = "KiwiAndCMD" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 400KB and 2 of them
}

rule sql1433_SQL {
    meta:
        id = "3tHbl87LUXERdEe4PgBlfa"
        fingerprint = "v1_sha256_5ceecc4f345cb603a0b03180f3f09f97e5f951b5d75c469aefffe3ec62916a8f"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file SQL.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "025e87deadd1c50b1021c26cb67b76b476fafd64"

    strings:
        /* WIDE: ProductName 1433 */
        $s0 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 31 00 34 00 33 00 33 }
        /* WIDE: ProductVersion 1,4,3,3 */
        $s1 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 31 00 2C 00 34 00 2C 00 33 00 2C 00 33 }
    condition:
        uint16(0) == 0x5a4d and filesize < 90KB and all of them
}

rule CookieTools2 {
    meta:
        id = "FurgMxqWgXBn7D5NYaOzm"
        fingerprint = "v1_sha256_4d9716409ec7cd20d38208c6ceb942c7fa81b067f2ad0db60bbbb47f5a684132"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file CookieTools2.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "cb67797f229fdb92360319e01277e1345305eb82"

    strings:
        $s1 = "www.gxgl.com&www.gxgl.net" fullword wide
        $s2 = "ip.asp?IP=" fullword ascii
        $s3 = "MSIE 5.5;" fullword ascii
        $s4 = "SOFTWARE\\Borland\\" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule cyclotron {
    meta:
        id = "3fgJOjk8ZJhZCXlnHwgdac"
        fingerprint = "v1_sha256_c9112afcb954077c5b6ba50b22614c42cfa057f110bebba6856e7f656c8c5008"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file cyclotron.sys"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "5b63473b6dc1e5942bf07c52c31ba28f2702b246"

    strings:
        $s1 = "\\Device\\IDTProt" fullword wide
        $s2 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
        $s3 = "\\??\\slIDTProt" fullword wide
        $s4 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
        $s5 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 3KB and all of them
}

rule xscan_gui {
    meta:
        id = "71QtgoXmz5U06oKNtPla3z"
        fingerprint = "v1_sha256_366db7eb19725a0a42ce371d7bfb50a22a259f0bc0252927af626e8c1c0b9b59"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file xscan_gui.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"

    strings:
        $s1 = "%s -mutex %s -host %s -index %d -config \"%s\"" fullword ascii
        $s2 = "www.target.com" fullword ascii
        $s3 = "%s\\scripts\\desc\\%s.desc" fullword ascii
        $s4 = "%c Active/Maximum host thread: %d/%d, Current/Maximum thread: %d/%d, Time(s): %l" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Tools_hscan {
    meta:
        id = "6Xmld78hAErlZbfNgiRNF5"
        fingerprint = "v1_sha256_9bc4800249bffcc4b8fc1191d600f0b9b2a7b0c1f067039c83c03671a0b4b5c5"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file hscan.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"

    strings:
        $s1 = "%s -f hosts.txt -port -ipc -pop -max 300,20 -time 10000" fullword ascii
        $s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,20" fullword ascii
        $s3 = "%s -h www.target.com -all" fullword ascii
        $s4 = ".\\report\\%s-%s.html" fullword ascii
        $s5 = ".\\log\\Hscan.log" fullword ascii
        $s6 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
        $s7 = "%s@ftpscan#FTP Account:  %s/[null]" fullword ascii
        $s8 = ".\\conf\\mysql_pass.dic" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule GoodToolset_pr {
    meta:
        id = "3OuoZw8YvHauWvQOKYJrqv"
        fingerprint = "v1_sha256_0673bc445422f4339c9e81ff8ae8a9b2bb9bc1f107b85fe34906444a1754c43b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file pr.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "f6676daf3292cff59ef15ed109c2d408369e8ac8"

    strings:
        $s1 = "-->Got WMI process Pid: %d " ascii
        $s2 = "-->This exploit gives you a Local System shell " ascii
        $s3 = "wmiprvse.exe" fullword ascii
        $s4 = "Try the first %d time" fullword ascii
        $s5 = "-->Build&&Change By p " ascii
        $s6 = "root\\MicrosoftIISv2" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule hydra_7_4_1_hydra {
    meta:
        id = "2Uuz7vXdq23uVLJNKC1rRO"
        fingerprint = "v1_sha256_f52696cbf7355c982d1a1e0c73dce65324845c5ffc13c541e326720332b4788d"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file hydra.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "3411d0380a1c1ebf58a454765f94d4f1dd714b5b"

    strings:
        $s1 = "%d of %d target%s%scompleted, %lu valid password%s found" fullword ascii
        $s2 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
        $s3 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
        $s4 = "[%d][smb] Host: %s Account: %s Error: PASSWORD EXPIRED" fullword ascii
        $s5 = "[ERROR] SMTP LOGIN AUTH, either this auth is disabled" fullword ascii
        $s6 = "\"/login.php:user=^USER^&pass=^PASS^&mid=123:incorrect\"" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule CN_Tools_srss_2 {
    meta:
        id = "3l11VakyBZuAKDLjoGl5dA"
        fingerprint = "v1_sha256_e674ac7a99a67e2ebe8b4c4232e3435dd041b794f6c08a87ef7b8179127d6fc7"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file srss.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "c418b30d004051bbf1b2d3be426936b95b5fea6f"

    strings:
        $x1 = "used pepack!" fullword ascii

        $s1 = "KERNEL32.dll" fullword ascii
        $s2 = "KERNEL32.DLL" fullword ascii
        $s3 = "LoadLibraryA" fullword ascii
        $s4 = "GetProcAddress" fullword ascii
        $s5 = "VirtualProtect" fullword ascii
        $s6 = "VirtualAlloc" fullword ascii
        $s7 = "VirtualFree" fullword ascii
        $s8 = "ExitProcess" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ( $x1 at 0 ) and filesize < 14KB and all of ($s*)
}

rule Dos_NtGod {
    meta:
        id = "6LSQJFwyCGwh9MSlvg8j9c"
        fingerprint = "v1_sha256_77b9204add5d25dcc36eabc07cabea2bdc67a23873c2faf7706e7fba5ed53f8b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file NtGod.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "adefd901d6bbd8437116f0170b9c28a76d4a87bf"

    strings:
        $s0 = "\\temp\\NtGodMode.exe" ascii
        $s4 = "NtGodMode.exe" fullword ascii
        $s10 = "ntgod.bat" fullword ascii
        $s19 = "sfxcmd" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule CN_Tools_VNCLink {
    meta:
        id = "24S3DAbRNpLe5bPFTdtj2y"
        fingerprint = "v1_sha256_21328e2a871dfcfda47991a1f1e897efd27471420d644c09a94004cf5b0f9869"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file VNCLink.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "cafb531822cbc0cfebbea864489eebba48081aa1"

    strings:
        $s1 = "C:\\temp\\vncviewer4.log" fullword ascii
        $s2 = "[BL4CK] Patched by redsand || http://blacksecurity.org" fullword ascii
        $s3 = "fake release extendedVkey 0x%x, keysym 0x%x" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 580KB and 2 of them
}

rule tools_NTCmd {
    meta:
        id = "W0PRZSnfdvaIM7wpxYDrX"
        fingerprint = "v1_sha256_c2487306a0d82ab76a048c001361c25bcd61d0f7a57a3b22df1c70299f0a72ba"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file NTCmd.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "a3ae8659b9a673aa346a60844208b371f7c05e3c"

    strings:
        $s1 = "pipecmd \\\\%s -U:%s -P:\"\" %s" fullword ascii
        $s2 = "[Usage]:  %s <HostName|IP> <Username> <Password>" fullword ascii
        $s3 = "pipecmd \\\\%s -U:%s -P:%s %s" fullword ascii
        $s4 = "============By uhhuhy (Feb 18,2003) - http://www.cnhonker.net============" fullword ascii /* PEStudio Blacklist: os */
        $s5 = "=======================NTcmd v0.11 for HScan v1.20=======================" fullword ascii
        $s6 = "NTcmd>" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 80KB and 2 of them
}

rule mysql_pwd_crack {
    meta:
        id = "1sZnmdjtVnUOa6aqNHJYYY"
        fingerprint = "v1_sha256_d272b98a6cf2749482ee501734d0043564ba528770161cb0ed4f032409305f22"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file mysql_pwd_crack.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "57d1cb4d404688804a8c3755b464a6e6248d1c73"

    strings:
        $s1 = "mysql_pwd_crack 127.0.0.1 -x 3306 -p root -d userdict.txt" fullword ascii
        $s2 = "Successfully --> username %s password %s " fullword ascii
        $s3 = "zhouzhen@gmail.com http://zhouzhen.eviloctal.org" fullword ascii
        $s4 = "-a automode  automatic crack the mysql password " fullword ascii
        $s5 = "mysql_pwd_crack 127.0.0.1 -x 3306 -a" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule CmdShell64 {
    meta:
        id = "4SRNnaqgIfJLdis2bZh6sW"
        fingerprint = "v1_sha256_fd8010ab2ab51feed62475f840ffaeef92cf1266c139b8f669b7fa5ff646fdab"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file CmdShell64.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "5b92510475d95ae5e7cd6ec4c89852e8af34acf1"

    strings:
        $s1 = "C:\\Windows\\System32\\JAVASYS.EXE" fullword wide
        $s2 = "ServiceCmdShell" fullword ascii
        $s3 = "<!-- If your application is designed to work with Windows 8.1, uncomment the fol" ascii
        $s4 = "ServiceSystemShell" fullword wide
        $s5 = "[Root@CmdShell ~]#" fullword wide
        $s6 = "Hello Man 2015 !" fullword wide
        $s7 = "CmdShell" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 30KB and 4 of them
}

rule Ms_Viru_v {
    meta:
        id = "5L9FjWtdleHAFcVk9wyjJb"
        fingerprint = "v1_sha256_028b589c11eeacb2edfeeaeaebf2da370e540cba964c9ebbb19e4c734afe190f"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file v.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "ecf4ba6d1344f2f3114d52859addee8b0770ed0d"

    strings:
        $s1 = "c:\\windows\\system32\\command.com /c " fullword ascii
        $s2 = "Easy Usage Version -- Edited By: racle@tian6.com" fullword ascii
        $s3 = "OH,Sry.Too long command." fullword ascii
        $s4 = "Success! Commander." fullword ascii
        $s5 = "Hey,how can racle work without ur command ?" fullword ascii
        $s6 = "The exploit thread was unable to map the virtual 8086 address space" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule CN_Tools_Vscan {
    meta:
        id = "5s7sLNoYzYlsotjRLfwSWf"
        fingerprint = "v1_sha256_2bbf0a3fb2b3fc9b646c6f8fc021f65a38e1b64edd74301481051541f8938902"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Vscan.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "0365fe05e2de0f327dfaa8cd0d988dbb7b379612"

    strings:
        $s1 = "[+] Usage: VNC_bypauth <target> <scantype> <option>" fullword ascii
        $s2 = "========RealVNC <= 4.1.1 Bypass Authentication Scanner=======" fullword ascii
        $s3 = "[+] Type VNC_bypauth <target>,<scantype> or <option> for more informations" fullword ascii
        $s4 = "VNC_bypauth -i 192.168.0.1,192.168.0.2,192.168.0.3,..." fullword ascii
        $s5 = "-vn:%-15s:%-7d  connection closed" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 60KB and 2 of them
}

rule Dos_iis {
    meta:
        id = "3ndaA8ZwU8xYxyg3b2bddQ"
        fingerprint = "v1_sha256_d6852af79eac659f4dfa3019793290e0498739f02a06c5540cd7d2c65b46b960"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file iis.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "61ffd2cbec5462766c6f1c44bd44eeaed4f3d2c7"

    strings:
        $s1 = "comspec" fullword ascii
        $s2 = "program terming" fullword ascii
        $s3 = "WinSta0\\Defau" fullword ascii
        $s4 = "* FROM IIsWebInfo" ascii
        $s5 = "www.icehack." ascii
        $s6 = "wmiprvse.exe" fullword ascii
        $s7 = "Pid: %d" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule IISPutScannesr {
    meta:
        id = "57xSWqxL8n1NsIotK0Frgl"
        fingerprint = "v1_sha256_27c190050aabcdff3713b388adb0113ad2334c107a2a7b3d682c209b102cf642"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file IISPutScannesr.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "2dd8fee20df47fd4eed5a354817ce837752f6ae9"

    strings:
        $s1 = "yoda & M.o.D." ascii
        $s2 = "-> come.to/f2f **************" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Generate {
    meta:
        id = "SO9QKmeMKtAWOHuC0kF9K"
        fingerprint = "v1_sha256_02a13785d01fba39be4e713cc9013fe366f0d8d99f510fa13856d7d1ee3475d2"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Generate.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "2cb4c3916271868c30c7b4598da697f59e9c7a12"

    strings:
        $s1 = "C:\\TEMP\\" fullword ascii
        $s2 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
        $s3 = "$530 Please login with USER and PASS." fullword ascii
        $s4 = "_Shell.exe" fullword ascii
        $s5 = "ftpcWaitingPassword" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}

rule Pc_rejoice {
    meta:
        id = "2MMtH2k6LIbd0UVCQlBWde"
        fingerprint = "v1_sha256_9e22a98b5065a95a7f169fda8d6d4112101bffa11a1407e03ec152db41857206"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file rejoice.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"

    strings:
        $s1 = "@members.3322.net/dyndns/update?system=dyndns&hostname=" fullword ascii
        $s2 = "http://www.xxx.com/xxx.exe" fullword ascii
        $s3 = "@ddns.oray.com/ph/update?hostname=" fullword ascii
        $s4 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
        $s5 = "ListViewProcessListColumnClick!" fullword ascii
        $s6 = "http://iframe.ip138.com/ic.asp" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them
}

rule ms11080_withcmd {
    meta:
        id = "4j8lucn6wCW7FZbIsk4B5E"
        fingerprint = "v1_sha256_557fab4a08ba8cce21b80df3abfc52d2fa00ac8163610d7ca6ebf061d8d46718"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file ms11080_withcmd.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "745e5058acff27b09cfd6169caf6e45097881a49"

    strings:
        $s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
        $s2 = "\\ms11080\\ms11080\\Debug\\ms11080.pdb" fullword ascii
        $s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
        $s4 = "[>] create porcess error" fullword ascii
        $s5 = "[>] ms11-080 Exploit" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and 1 of them
}

rule OtherTools_xiaoa {
    meta:
        id = "1FBFTFtICeKZX3rUQHRkYE"
        fingerprint = "v1_sha256_451ed602bd1e9dd7e4020108ea133b60c546965bd77be349d07be42150f80fee"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file xiaoa.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "6988acb738e78d582e3614f83993628cf92ae26d"

    strings:
        $s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
        $s2 = "The shell \"cmd\" success!" fullword ascii
        $s3 = "Not Windows NT family OS." fullword ascii /* PEStudio Blacklist: os */
        $s4 = "Unable to get kernel base address." fullword ascii
        $s5 = "run \"%s\" failed,code: %d" fullword ascii
        $s6 = "Windows Kernel Local Privilege Exploit " fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule unknown2 {
    meta:
        id = "kSIxdJdUDIR10nHEpOVR4"
        fingerprint = "v1_sha256_47eb9d74b0a5172561620ffb43b47b2adce47ecddaf52eead750826723c4ca0d"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file unknown2.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "32508d75c3d95e045ddc82cb829281a288bd5aa3"

    strings:
        $s1 = "http://md5.com.cn/index.php/md5reverse/index/md/" fullword wide
        $s2 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
        $s3 = "http://www.md5.com.cn" fullword wide
        $s4 = "1.5.exe" fullword wide
        $s5 = "\\Set.ini" fullword wide
        $s6 = "OpenFileDialog1" fullword wide
        $s7 = " (*.txt)|*.txt" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and 4 of them
}

rule mswin_auth {
    meta:
        id = "7iec6yJrhwy1V8D6th2EUm"
        fingerprint = "v1_sha256_5f8b815927cba73ee400ad54d1a1e588dd7a05fb4224a09075cf2b8b3cf0d355"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file mswin_auth.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "512cbd02f6fe69482e005a067db4eb07ce62d5a0"

    strings:
        $s1 = "No such user or wrong password" fullword ascii
        $s2 = "%s [-A|D UserGroup][-O DefaultDomain][-d]" fullword ascii
        $s3 = "mswin_auth[%d]: " fullword ascii
        $s4 = "Unknown option: -%c. Exiting" fullword ascii
        $s5 = "-D can specify a Windows Local Group name not allowed to authenticate" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule hydra_7_3_hydra {
    meta:
        id = "2XK2yei9ScCKqD7HApj7Dw"
        fingerprint = "v1_sha256_23194c2df0b8bdedc4fc66c423b0aebb10217de328a194b26560d4cc9a5531e3"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file hydra.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "2f82b8bf1159e43427880d70bcd116dc9e8026ad"

    strings:
        $s1 = "[ATTEMPT-ERROR] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii
        $s2 = "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=))(COMMAND=reload)(PASSWORD=%s)(SERVICE" ascii
        $s3 = "cn=^USER^,cn=users,dc=foo,dc=bar,dc=com for domain foo.bar.com" fullword ascii
        $s4 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
        $s5 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 700KB and 1 of them
}

rule OracleScan {
    meta:
        id = "4TYIIWrgcIe7VjZSGWP209"
        fingerprint = "v1_sha256_84d2e5273b273bd9c03d6e8adb3af3199900d59273dc5a955f9ac447fe405f3b"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file OracleScan.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "10ff7faf72fe6da8f05526367b3522a2408999ec"

    strings:
        $s1 = "MYBLOG:HTTP://HI.BAIDU.COM/0X24Q" fullword ascii
        $s2 = "\\Borland\\Delphi\\RTL" fullword ascii
        $s3 = "USER_NAME" ascii
        $s4 = "FROMWWHERE" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule SQLTools {
    meta:
        id = "3b4WcxZ0uUf0esYWBreqIC"
        fingerprint = "v1_sha256_35b84c3445e92d61ca5e638a2eb19128dca2174327c6325436287d8d3f0bb976"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file SQLTools.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "38a9caa2079afa2c8d7327e7762f7ed9a69056f7"

    strings:
        $s1 = "DBN_POST" fullword wide
        $s2 = "LOADER ERROR" fullword ascii
        $s3 = "www.1285.net" fullword wide
        $s4 = "TUPFILEFORM" fullword wide
        $s5 = "DBN_DELETE" fullword wide
        $s6 = "DBINSERT" fullword wide
        $s7 = "Copyright (C) Kibosoft Corp. 2001-2006" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 2350KB and all of them
}

rule portscanner {
    meta:
        id = "21cApXolUwvnJomnYlEj5N"
        fingerprint = "v1_sha256_446cbc1b8046bfd182e0b1c98fe37c8b8ef98f600f5d80d9de83b45aeaf2b386"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file portscanner.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "1de367d503fdaaeee30e8ad7c100dd1e320858a4"

    strings:
        $s0 = "PortListfNo" fullword ascii
        $s1 = ".533.net" fullword ascii
        $s2 = "CRTDLL.DLL" fullword ascii
        $s3 = "exitfc" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule kappfree {
    meta:
        id = "2AnI4FWKaVpE5NSrRFFjBT"
        fingerprint = "v1_sha256_b1b644f9b033ac8372369e81628ee3f6fe094f80d11b8f4f6c192a5e81d2e543"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file kappfree.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "e57e79f190f8a24ca911e6c7e008743480c08553"

    strings:
        $s1 = "Bienvenue dans un processus distant" fullword wide
        $s2 = "kappfree.dll" fullword ascii
        $s3 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule Smartniff {
    meta:
        id = "7dy3NP5Gf1ZuhfH9szzbR8"
        fingerprint = "v1_sha256_bac770ae3c8e7f619da0b0ff4243716ff8212dce0f36c08c127af892548fe0b6"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Smartniff.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "67609f21d54a57955d8fe6d48bc471f328748d0a"

    strings:
        $s1 = "smsniff.exe" fullword wide
        $s2 = "support@nirsoft.net0" fullword ascii
        $s3 = "</requestedPrivileges></security></trustInfo></assembly>" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule ChinaChopper_caidao {
    meta:
        id = "33zKccumooyZVOxNyKLmg7"
        fingerprint = "v1_sha256_c348a828e390d26e649359d4ed92115758c974f7781da86efc1238d55f7e4634"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file caidao.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "056a60ec1f6a8959bfc43254d97527b003ae5edb"

    strings:
        $s1 = "Pass,Config,n{)" fullword ascii
        $s2 = "phMYSQLZ" fullword ascii
        $s3 = "\\DHLP\\." fullword ascii
        $s4 = "\\dhlp\\." fullword ascii
        $s5 = "SHAutoComple" fullword ascii
        $s6 = "MainFrame" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1077KB and all of them
}

rule KiwiTaskmgr_2 {
    meta:
        id = "3GFPAh07j3zZYkob9afbJt"
        fingerprint = "v1_sha256_6d197e9b7bb9bbd759d6c8c882f7d7412512ba10208cb52a08fcde5e32fd1733"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file KiwiTaskmgr.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"

    strings:
        $s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
        $s2 = "Kiwi Taskmgr no-gpo" fullword wide
        $s3 = "KiwiAndTaskMgr" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule kappfree_2 {
    meta:
        id = "4E2ouLKHJZlrxHJrB4oZzb"
        fingerprint = "v1_sha256_1862f1283e8a268f523b3922b3630ebbca9a81cc5aed19e5068315e6346d25c2"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file kappfree.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "5d578df9a71670aa832d1cd63379e6162564fb6b"

    strings:
        $s1 = "kappfree.dll" fullword ascii
        $s2 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
        $s3 = "' introuvable !" fullword wide
        $s4 = "kiwi\\mimikatz" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule x_way2_5_sqlcmd {
    meta:
        id = "6CXeTvWoHeXXgzroygWSkL"
        fingerprint = "v1_sha256_59fd25a786d56885e456fca154800a8313cd04a23fd9374361cc37b86be109a1"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file sqlcmd.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "5152a57e3638418b0d97a42db1c0fc2f893a2794"

    strings:
        $s1 = "LOADER ERROR" fullword ascii
        $s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
        $s3 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
        $s4 = "kernel32.dll" fullword ascii
        $s5 = "VirtualAlloc" fullword ascii
        $s6 = "VirtualFree" fullword ascii
        $s7 = "VirtualProtect" fullword ascii
        $s8 = "ExitProcess" fullword ascii
        $s9 = "user32.dll" fullword ascii
        $s16 = "MessageBoxA" fullword ascii
        $s10 = "wsprintfA" fullword ascii
        $s11 = "kernel32.dll" fullword ascii
        $s12 = "GetProcAddress" fullword ascii
        $s13 = "GetModuleHandleA" fullword ascii
        $s14 = "LoadLibraryA" fullword ascii
        $s15 = "odbc32.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 23KB and filesize > 20KB and all of them
}

rule Win32_klock {
    meta:
        id = "P6GfypyyPpx9KiHdjtkCj"
        fingerprint = "v1_sha256_e9f1d38de15ce06d55cf276e0f2becd9f9dbf5bd22f9061de03761d7ccdd3e60"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file klock.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "7addce4434670927c4efaa560524680ba2871d17"

    strings:
        $s1 = "klock.dll" fullword ascii
        $s2 = "Erreur : impossible de basculer le bureau ; SwitchDesktop : " fullword wide
        $s3 = "klock de mimikatz pour Windows" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule ipsearcher {
    meta:
        id = "2Risx77n5RNutxIyBohg7"
        fingerprint = "v1_sha256_703d08a9c0aaa5f85e064ff2444fed1ae1063c110af776c56debc9a186ad61ec"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file ipsearcher.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"

    strings:
        $s0 = "http://www.wzpg.com" fullword ascii
        $s1 = "ipsearcher\\ipsearcher\\Release\\ipsearcher.pdb" fullword ascii
        $s3 = "_GetAddress" fullword ascii
        $s5 = "ipsearcher.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule ms10048_x64 {
    meta:
        id = "5m1Nzl7Mk95SlBhL7iVA7e"
        fingerprint = "v1_sha256_f6e353a9e4f751632ca5fda1663f0ba66b16b60df90570ccdaf836eaaa6a78ca"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file ms10048-x64.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"

    strings:
        $s1 = "The target is most likely patched." fullword ascii
        $s2 = "Dojibiron by Ronald Huizer, (c) master#h4cker.us  " fullword ascii
        $s3 = "[ ] Creating evil window" fullword ascii
        $s4 = "[+] Set to %d exploit half succeeded" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 40KB and 1 of them
}

rule hscangui {
    meta:
        id = "47WTCpmbLmaQssn13Wpdnx"
        fingerprint = "v1_sha256_9c0eb87dcf8aa107b5289d196650aebcf49c24f57a317de0afdadd61fb5bb5b7"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file hscangui.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "af8aced0a78e1181f4c307c78402481a589f8d07"

    strings:
        $s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
        $s2 = "http://www.cnhonker.com" fullword ascii
        $s3 = "%s@ftpscan#Cracked account:  %s/%s" fullword ascii
        $s4 = "[%s]: Found \"FTP account: %s/%s\" !!!" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule GoodToolset_ms11080 {
    meta:
        id = "3EuvFvwJwg9qBqeqsbeM9I"
        fingerprint = "v1_sha256_d9e7989727c95252ac77e32c21e8677a45658db7eb4c0be6c4e2bee564fd55b1"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file ms11080.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"

    strings:
        $s1 = "[*] command add user 90sec 90sec" fullword ascii
        $s2 = "\\ms11080\\Debug\\ms11080.pdb" fullword ascii
        $s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
        $s4 = "[*] Add to Administrators success" fullword ascii
        $s5 = "[*] User has been successfully added" fullword ascii
        $s6 = "[>] ms11-08 Exploit" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}

rule epathobj_exp64 {
    meta:
        id = "1U0qTvJa2OYQMxCtsOB4DM"
        fingerprint = "v1_sha256_57303b602891fc02d2b6b4f3819c2eac6e770c87889a8d98672b792beebdb8f7"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file epathobj_exp64.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "09195ba4e25ccce35c188657957c0f2c6a61d083"

    strings:
        $s1 = "Watchdog thread %d waiting on Mutex" fullword ascii
        $s2 = "Exploit ok run command" fullword ascii
        $s3 = "\\epathobj_exp\\x64\\Release\\epathobj_exp.pdb" fullword ascii
        $s4 = "Alllocated userspace PATHRECORD () %p" fullword ascii
        $s5 = "Mutex object did not timeout, list not patched" fullword ascii
        $s6 = "- inconsistent onexit begin-end variables" fullword wide  /* Goodware String - occured 96 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}

rule kelloworld_2 {
    meta:
        id = "1yR5ETioUipXk2cw2RQNxu"
        fingerprint = "v1_sha256_a575c30c06bd84196cbf01a9b5ef3a042cf29553610421b019227d30a2c7ad1c"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file kelloworld.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"

    strings:
        $s1 = "Hello World!" fullword wide
        $s2 = "kelloworld.dll" fullword ascii
        $s3 = "kelloworld de mimikatz pour Windows" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule HScan_v1_20_hscan {
    meta:
        id = "6zsnw0xsb17P6TUqQrYgWZ"
        fingerprint = "v1_sha256_8e30c366c5d5c34a7b50ba4dec17a46c173196b773fff6965891802bcebeb112"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file hscan.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "568b06696ea0270ee1a744a5ac16418c8dacde1c"

    strings:
        $s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
        $s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,100" fullword ascii
        $s3 = ".\\report\\%s-%s.html" fullword ascii
        $s4 = ".\\log\\Hscan.log" fullword ascii
        $s5 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule _Project1_Generate_rejoice {
    meta:
        id = "7WoA0YAE62SDJsMyaFUzVT"
        fingerprint = "v1_sha256_b66bb4d392881468b33a8ee4458f33bfe7a82d34cc3927eedccd54ad94ff6a04"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - from files Project1.exe, Generate.exe, rejoice.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        super_rule = 1
        hash0 = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
        hash1 = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
        hash2 = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"

    strings:
        $s1 = "sfUserAppDataRoaming" fullword ascii
        $s2 = "$TRzFrameControllerPropertyConnection" fullword ascii
        $s3 = "delphi32.exe" fullword ascii
        $s4 = "hkeyCurrentUser" fullword ascii
        $s5 = "%s is not a valid IP address." fullword wide
        $s6 = "Citadel hooking error" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule _hscan_hscan_hscangui {
    meta:
        id = "vqQU1TR9DLw3b3ypxhRE7"
        fingerprint = "v1_sha256_5466c3dd8b2b777186bfab9d0948905eb3692ce05cf4748fb5b7b896dc3cb251"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - from files hscan.exe, hscan.exe, hscangui.exe"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        super_rule = 1
        hash0 = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
        hash1 = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
        hash2 = "af8aced0a78e1181f4c307c78402481a589f8d07"

    strings:
        $s1 = ".\\log\\Hscan.log" fullword ascii
        $s2 = ".\\report\\%s-%s.html" fullword ascii
        $s3 = "[%s]: checking \"FTP account: ftp/ftp@ftp.net\" ..." fullword ascii
        $s4 = "[%s]: IPC NULL session connection success !!!" fullword ascii
        $s5 = "Scan %d targets,use %4.1f minutes" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 240KB and all of them
}

rule kiwi_tools {
    meta:
        id = "1EstHtWHfSMIMFU8feaSHe"
        fingerprint = "v1_sha256_ce7b3c7d57740257013d9d589444a3b53e81254619bd3f09ece917c70bba03ce"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, mimikatz.sys, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, mimikatz.sys, sekurlsa.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        super_rule = 1
        hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
        hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
        hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
        hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
        hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
        hash5 = "7addce4434670927c4efaa560524680ba2871d17"
        hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
        hash7 = "b5c93489a1b62181594d0fb08cc510d947353bc8"
        hash8 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
        hash9 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
        hash10 = "febadc01a64a071816eac61a85418711debaf233"
        hash11 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
        hash12 = "56a61c808b311e2225849d195bbeb69733efe49a"
        hash13 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
        hash14 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
        hash15 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
        hash16 = "20facf1fa2d87cccf177403ca1a7852128a9a0ab"
        hash17 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"

    strings:
        $s1 = "http://blog.gentilkiwi.com/mimikatz" ascii
        $s2 = "Benjamin Delpy" fullword ascii
        $s3 = "GlobalSign" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule kiwi_tools_gentil_kiwi {
    meta:
        id = "6bRVTZlJS3hEdR0oGfaALg"
        fingerprint = "v1_sha256_1a88bb31e985ae2119b578494ce9130204b41eece5929865c0822cdc82eaba75"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        super_rule = 1
        hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
        hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
        hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
        hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
        hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
        hash5 = "7addce4434670927c4efaa560524680ba2871d17"
        hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
        hash7 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
        hash8 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
        hash9 = "febadc01a64a071816eac61a85418711debaf233"
        hash10 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
        hash11 = "56a61c808b311e2225849d195bbeb69733efe49a"
        hash12 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
        hash13 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
        hash14 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
        hash15 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"

    strings:
        $s1 = "mimikatz" fullword wide
        $s2 = "Copyright (C) 2012 Gentil Kiwi" fullword wide
        $s3 = "Gentil Kiwi" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}
