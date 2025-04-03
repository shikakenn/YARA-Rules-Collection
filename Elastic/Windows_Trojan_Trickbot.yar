rule Windows_Trojan_Trickbot_01365e46 {
    meta:
        id = "16yCfh0VH400w9ddzLyRlm"
        fingerprint = "v1_sha256_4d61de2cb37e12f62326c1717f6ed44554f5d2aa7ede6033d0c988e5e64df54d"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "5c450d4be39caef1d9ec943f5dfeb6517047175fec166a52970c08cd1558e172"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 8B 43 28 4C 8B 53 18 4C 8B 5B 10 4C 8B 03 4C 8B 4B 08 89 44 24 38 48 89 4C 24 30 4C }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_06fd4ac4 {
    meta:
        id = "2FGAEdeXWsdJwqxYIon1q1"
        fingerprint = "v1_sha256_bde387f1e22d1399fb99f6d41732a37635d8e90f29626f2995914a073a7cac89"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Trickbot unpacker"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 5F 33 C0 68 ?? ?? 00 00 59 50 E2 FD 8B C7 57 8B EC 05 ?? ?? ?? 00 89 45 04 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_ce4305d1 {
    meta:
        id = "3vshCrnpXpH8waxsK4TKhe"
        fingerprint = "v1_sha256_c547114475383e5d84f6b8cb72585ddd5778ae3afa491deddeef8a5ec56be1b5"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { F9 8B 45 F4 89 5D E4 85 D2 74 39 83 C0 02 03 C6 89 45 F4 8B }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_1e56fad7 {
    meta:
        id = "CbmFV7sJGvbD19VAaFT0c"
        fingerprint = "v1_sha256_815b37804f79fb4607e6b84294882d818233c3df13aececb3d341244900a2e44"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 5B C9 C2 18 00 43 C1 02 10 7C C2 02 10 54 C1 02 10 67 C1 02 10 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_93c9a2a4 {
    meta:
        id = "67eN1zVqBXmd5Wj6tWX2sy"
        fingerprint = "v1_sha256_dadeeba6147b118b80e014ab067eac7a2c3c2990958a6c7016562d8b64fef53c"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 6A 01 8B CF FF 50 5C 8B 4F 58 49 89 4F 64 8B 4D F4 8B 45 E4 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_5340afa3 {
    meta:
        id = "18MaIRvVCHhlFrTjQUvN2s"
        fingerprint = "v1_sha256_8b9d3c978f0c4a04ee5b3446b990172206b17496036bc1cc04180ea7e9b99734"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { E8 0C 89 5D F4 0F B7 DB 03 5D 08 66 83 F8 03 75 0A 8B 45 14 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_e7932501 {
    meta:
        id = "78Z9NNAPIu20ovfXq1pFkQ"
        fingerprint = "v1_sha256_f82704a408a0cf1def2a5926dc4c02fa56afea1422c88ba41af50d44c60edb07"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 24 0C 01 00 00 00 85 C0 7C 2F 3B 46 24 7D 2A 8B 4E 20 8D 04 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_cd0868d5 {
    meta:
        id = "4YwCMhyoirw02EFLKWvFzG"
        fingerprint = "v1_sha256_053a99e5e722fd2aa1cae96266cc344954f9c3a12d0851fa9d5e95a6420651f4"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 8D 1C 01 89 54 24 10 8B 54 24 1C 33 C9 66 8B 0B 8D 3C 8A 8B 4C }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_515504e2 {
    meta:
        id = "2WIxAoVew3d52NNOWvWuFo"
        fingerprint = "v1_sha256_5410068e09de4a1283f98f6364ddf243373e228ba060b00699db6323f1167684"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 6A 00 6A 00 8D 4D E0 51 FF D6 85 C0 74 29 83 F8 FF 74 0C 8D }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_a0fc8f35 {
    meta:
        id = "4hKcP0HXMTiksEwmL4Byvw"
        fingerprint = "v1_sha256_7ab2b45ddfc1d7fa409a6ea3dfd8d4940e1bdf3fc0cb6c7e8d49c60e7bda5b1b"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 18 33 DB 53 6A 01 53 53 8D 4C 24 34 51 8B F0 89 5C 24 38 FF D7 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_cb95dc06 {
    meta:
        id = "3yW9zfQyFj7KqewW7zDDS5"
        fingerprint = "v1_sha256_563b2311d37ace2d09601a70325352db3fcbf135e7ce518965f5410081b5d626"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 08 5F 5E 33 C0 5B 5D C3 8B 55 14 89 02 8B 45 18 5F 89 30 B9 01 00 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_9d4d3fa4 {
    meta:
        id = "7XREI1wIzpb15sOCcfHjdL"
        fingerprint = "v1_sha256_7c3c9917a95248fd990b6947a0304ded473bf1bcceec8f4498a7955e879d348b"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 89 44 24 18 33 C9 89 44 24 1C 8D 54 24 38 89 44 24 20 33 F6 89 44 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_34f00046 {
    meta:
        id = "1B2WvmBanvBxA0M7vFcrGK"
        fingerprint = "v1_sha256_f9d646645d6726e3aac5cc3eaea9edf1c89c7e743aff7cfa73998a72f3446711"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 30 FF FF FF 03 08 8B 95 30 FF FF FF 2B D1 89 95 30 FF FF FF }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_f2a18b09 {
    meta:
        id = "71gjCHlO3VN9IqEz9MZdVt"
        fingerprint = "v1_sha256_c4c4b0b1df1e8fde87284fb27d46e917c47b479a675fec60faeca6185511907d"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 04 39 45 08 75 08 8B 4D F8 8B 41 18 EB 0F 8B 55 F8 8B 02 89 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_d916ae65 {
    meta:
        id = "41rStHFHkRzRzUtkBc2UMT"
        fingerprint = "v1_sha256_e0aafe498cd9f0e8addfef78027943a754ca797aafae0cb40f1c6425de501339"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 5F 24 01 10 CF 22 01 10 EC 22 01 10 38 23 01 10 79 23 01 10 82 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_52722678 {
    meta:
        id = "3GRPACVTEUoA01khVt4gWy"
        fingerprint = "v1_sha256_6340171fdde68b32de480f1f410aa4c491a8fffa7c1f699bf5fa72a12ecb77b8"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 2B 5D 0C 89 5D EC EB 03 8B 5D EC 8A 1C 3B 84 DB 74 0D 38 1F }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_28a60148 {
    meta:
        id = "7g6iO6p5aFRg7oLEAwhN1S"
        fingerprint = "v1_sha256_20a26ed3f0da3a77867597494bf0069a2093ec19b1c5e179c0e7934c1b69d4b9"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { C0 31 E8 83 7D 0C 00 89 44 24 38 0F 29 44 24 20 0F 29 44 24 10 0F 29 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_997b25a0 {
    meta:
        id = "26rSEvstAYtbDGFKWNFSLl"
        fingerprint = "v1_sha256_ca688086c4628c64c32a99083d620bcb5373e3100d154331451a3e9f86081aca"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 85 D2 74 F0 C6 45 E1 20 8D 4D E1 C6 45 E2 4A C6 45 E3 4A C6 45 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_b17b33a1 {
    meta:
        id = "7LFhEbpLAjy6GRKwLRftLB"
        fingerprint = "v1_sha256_7fa69674d1e985bafe310597f23ae80113136768141f0a1931baf88b2509e6ef"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 08 53 55 56 57 64 A1 30 00 00 00 89 44 24 10 8B 44 24 10 8B }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_23d77ae5 {
    meta:
        id = "51xcuoXFSEKmNgtyUQhPAN"
        fingerprint = "v1_sha256_e5f5cf854ebd0e25fffbd6796217f22223a06937e1cacb33baa105ac41731256"
        version = "1.0"
        date = "2021-03-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets importDll64 containing Browser data stealer module"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "844974A2D3266E1F9BA275520C0E8A5D176DF69A0CCD5135B99FACF798A5D209"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "/system32/cmd.exe /c \"start microsoft-edge:{URL}\"" ascii fullword
        $a2 = "SELECT name, value, host_key, path, expires_utc, creation_utc, encrypted_value FROM cookies" ascii fullword
        $a3 = "attempt %d. Cookies not found" ascii fullword
        $a4 = "attempt %d. History not found" ascii fullword
        $a5 = "Cookies version is %d (%d)" ascii fullword
        $a6 = "attempt %d. Local Storage not found" ascii fullword
        $a7 = "str+='xie.com.'+p+'.guid='+'{'+components[i]+'}\\n';" ascii fullword
        $a8 = "Browser exec is: %s" ascii fullword
        $a9 = "found mozilla key: %s" ascii fullword
        $a10 = "Version %d is not supported" ascii fullword
        $a11 = "id %d - %s" ascii fullword
        $a12 = "prot: %s, scope: %s, port: %d" ascii fullword
        $a13 = "***** Send %d bytes to callback from %s *****" ascii fullword
        $a14 = "/chrome.exe {URL}" ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_5574be7d {
    meta:
        id = "30Kaspb1qmieUQGd1QhQKG"
        fingerprint = "v1_sha256_ed0fc98c5d628ce38b923e1410eaf7a4a65ecffea42bed35314e30c99a52219b"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets injectDll64 containing injection functionality to steal banking credentials"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "8c5c0d27153f60ef8aec57def2f88e3d5f9a7385b5e8b8177bab55fa7fac7b18"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "webinject64.dll" ascii fullword
        $a2 = "Mozilla Firefox version: %s" ascii fullword
        $a3 = "socks=127.0.0.1:" ascii fullword
        $a4 = "<conf ctl=\"dpost\" file=\"dpost\" period=\"60\"/>" ascii fullword
        $a5 = "<moduleconfig>" ascii fullword
        $a6 = "https://%.*s%.*s" ascii fullword
        $a7 = "http://%.*s%.*s" ascii fullword
        $a8 = "Chrome version: %s" ascii fullword
        $a9 = "IE version real: %s" ascii fullword
        $a10 = "IE version old: %s" ascii fullword
        $a11 = "Build date: %s %s" ascii fullword
        $a12 = "EnumDpostServer" ascii fullword
        $a13 = "ESTR_PASS_" ascii fullword
        $a14 = "<conf ctl=\"dinj\" file=\"dinj\" period=\"20\"/>" ascii fullword
        $a15 = "<conf ctl=\"sinj\" file=\"sinj\" period=\"20\"/>" ascii fullword
        $a16 = "<autoconf>" ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_1473f0b4 {
    meta:
        id = "3RODchAxyFFke174Pas3CL"
        fingerprint = "v1_sha256_dc13625e58c029c60b8670f8e63cd7786bf3e9705c462f3cbbf5b39e7c02f9a1"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets mailsearcher64.dll module"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "9cfb441eb5c60ab1c90b58d4878543ee554ada2cceee98d6b867e73490d30fec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "mailsearcher.dll" ascii fullword
        $a2 = "%s/%s/%s/send/" wide fullword
        $a3 = "Content-Disposition: form-data; name=\"list\"" ascii fullword
        $a4 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autostart>no</autostart><autoconf><conf ctl=\"SetConf\" file=\"mail"
        $a5 = "eriod=\"60\"/></autoconf></moduleconfig>" ascii fullword
        $a6 = "=Waitu H" ascii fullword
        $a7 = "Content-Length: %d" ascii fullword
    condition:
        2 of ($a*)
}

rule Windows_Trojan_Trickbot_dcf25dde {
    meta:
        id = "4Ycax1pmEC6N6TgLvhQap2"
        fingerprint = "v1_sha256_64d15d92faf0919a8fa1ce6772750cde47eaa24b09cf4243393777334bad9712"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets networkDll64.dll module containing functionality to gather network and system information"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "BA2A255671D33677CAB8D93531EB25C0B1F1AC3E3085B95365A017463662D787"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Host Name - %s" wide fullword
        $a2 = "Last Boot Up Time - %02u/%02u/%04u %02d.%02d.%02d" wide fullword
        $a3 = "Install Date - %02u/%02u/%04u %02d.%02d.%02d" wide fullword
        $a4 = "System Directory - %s" wide fullword
        $a5 = "OS Version - %s" wide fullword
        $a6 = "***PROCESS LIST***" wide fullword
        $a7 = "Product Type - Domain Controller" wide fullword
        $a8 = "Registered Organization - %s" wide fullword
        $a9 = "Product Type - Domain Controller" wide fullword
        $a10 = "Build Type - %s" wide fullword
        $a11 = "Boot Device - %s" wide fullword
        $a12 = "Serial Number - %s" wide fullword
        $a13 = "OS Architecture - %s" wide fullword
        $a14 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"SetConf\" file=\"dpost\" period=\"1440\"/></au"
        $a15 = "oduleconfig>" ascii fullword
        $a16 = "Computer name: %s" wide fullword
        $a17 = "/c net view /all /domain" ascii fullword
        $a18 = "/c nltest /domain_trusts" ascii fullword
        $a19 = "***SYSTEMINFO***" wide fullword
        $a20 = "***LOCAL MACHINE DATA***" wide fullword
        $a21 = "Admin Name: %s" wide fullword
        $a22 = "Domain controller: %s" wide fullword
        $a23 = "Admin E-mail: %s" wide fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_46dc12dd {
    meta:
        id = "Xb2VCwFORE6m9OBQh90GN"
        fingerprint = "v1_sha256_e01209a83f4743cbad7dda01595c053277868bd47208e48214b557ae339b5b3c"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets newBCtestDll64 module containing reverse shell functionality"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "BF38A787AEE5AFDCAB00B95CCDF036BC7F91F07151B4444B54165BB70D649CE5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "setconf" ascii fullword
        $a2 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name = \"id\"/><needinfo name = \"ip\"/><autoconf><conf ctl = \""
        $a3 = "nf\" file = \"bcconfig\" period = \"90\"/></autoconf></moduleconfig>" ascii fullword
        $a4 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name = \"id\"/><needinfo name = \"ip\"/><autoconf><conf ctl = \""
        $a5 = "<addr>" ascii fullword
        $a6 = "</addr>" ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_78a26074 {
    meta:
        id = "54fNrDxDPpQoiBk94egX1d"
        fingerprint = "v1_sha256_3837c22f7f9d55f03cb0bc1336798f0e2a91549c187b9f5136491cbafd26ce6e"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets psfin64.dll module containing point-of-sale recon functionality"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "8CD75FA8650EBCF0A6200283E474A081CC0BE57307E54909EE15F4D04621DDE0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"SetConf\" file=\"dpost\" period=\"14400\"/></a"
        $a2 = "Dpost servers unavailable" ascii fullword
        $a3 = "moduleconfig>" ascii fullword
        $a4 = "ALOHA found: %d" wide fullword
        $a5 = "BOH found: %d" wide fullword
        $a6 = "MICROS found: %d" wide fullword
        $a7 = "LANE found: %d" wide fullword
        $a8 = "RETAIL found: %d" wide fullword
        $a9 = "REG found: %d" wide fullword
        $a10 = "STORE found: %d" wide fullword
        $a11 = "POS found: %d" wide fullword
        $a12 = "DOMAIN %s" wide fullword
        $a13 = "/%s/%s/90" wide fullword
        $a14 = "CASH found: %d" wide fullword
        $a15 = "COMPUTERS:" wide fullword
        $a16 = "TERM found: %d" wide fullword
    condition:
        3 of ($a*)
}

rule Windows_Trojan_Trickbot_217b9c97 {
    meta:
        id = "5XMIIZwK3LZWnfwA9XJsev"
        fingerprint = "v1_sha256_9b2b8a8154d4aba06029fd35d896331449f7baa961f183fb0cb47e890610ff99"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets pwgrab64.dll module containing functionality use to retrieve local passwords"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "1E90A73793017720C9A020069ED1C87879174C19C3B619E5B78DB8220A63E9B7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "pwgrab.dll" ascii fullword
        $a2 = "\\\\.\\pipe\\pidplacesomepipe" ascii fullword
        $a3 = "\\Google\\Chrome\\User Data\\Default\\Login Data.bak" ascii fullword
        $a4 = "select origin_url, username_value, password_value, length(password_value) from logins where blacklisted_by_user = 0" ascii fullword
        $a5 = "<moduleconfig><autostart>yes</autostart><all>yes</all><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"dpost"
        $a6 = "Grab_Passwords_Chrome(0)" ascii fullword
        $a7 = "Grab_Passwords_Chrome(1)" ascii fullword
        $a8 = "=\"dpost\" period=\"60\"/></autoconf></moduleconfig>" ascii fullword
        $a9 = "Grab_Passwords_Chrome(): Can't open database" ascii fullword
        $a10 = "UPDATE %Q.%s SET sql = CASE WHEN type = 'trigger' THEN sqlite_rename_trigger(sql, %Q)ELSE sqlite_rename_table(sql, %Q) END, tbl_"
        $a11 = "Chrome login db copied" ascii fullword
        $a12 = "Skip Chrome login db copy" ascii fullword
        $a13 = "Mozilla\\Firefox\\Profiles\\" ascii fullword
        $a14 = "Grab_Passwords_Chrome() success" ascii fullword
        $a15 = "No password provided by user" ascii fullword
        $a16 = "Chrome login db should be copied (copy absent)" ascii fullword
        $a17 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" wide fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_d2110921 {
    meta:
        id = "1qKaWEqgRIM4pASzpod1kb"
        fingerprint = "v1_sha256_39ef17836f29c358f596e0047d582b5f1d1af523c8f6354ac8a783eda9969554"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets shareDll64.dll module containing functionality use to spread Trickbot across local networks"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "05EF40F7745DB836DE735AC73D6101406E1D9E58C6B5F5322254EB75B98D236A"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "module64.dll" ascii fullword
        $a2 = "Size - %d kB" ascii fullword
        $a3 = "%s - FAIL" wide fullword
        $a4 = "%s - SUCCESS" wide fullword
        $a5 = "ControlSystemInfoService" ascii fullword
        $a6 = "<moduleconfig><autostart>yes</autostart></moduleconfig>" ascii fullword
        $a7 = "Copy: %d" wide fullword
        $a8 = "Start sc 0x%x" wide fullword
        $a9 = "Create sc 0x%x" wide fullword
        $a10 = "Open sc %d" wide fullword
        $a11 = "ServiceInfoControl" ascii fullword
    condition:
        3 of ($a*)
}

rule Windows_Trojan_Trickbot_0114d469 {
    meta:
        id = "1zYDvlT1N3qaW26hOooICU"
        fingerprint = "v1_sha256_6ca8e73f758d3fa956fe53cc83abb43806359f93df05c42a58e2f394a1a3c117"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets systeminfo64.dll module containing functionality use to retrieve system information"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "083CB35A7064AA5589EFC544AC1ED1B04EC0F89F0E60383FCB1B02B63F4117E9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "<user>%s</user>" wide fullword
        $a2 = "<service>%s</service>" wide fullword
        $a3 = "<users>" wide fullword
        $a4 = "</users>" wide fullword
        $a5 = "%s%s%s</general>" wide fullword
        $a6 = "<program>%s</program>" wide fullword
        $a7 = "<moduleconfig><autostart>no</autostart><limit>2</limit></moduleconfig>" ascii fullword
        $a8 = "<cpu>%s</cpu>" wide fullword
        $a9 = "<ram>%s</ram>" wide fullword
        $a10 = "</installed>" wide fullword
        $a11 = "<installed>" wide fullword
        $a12 = "<general>" wide fullword
        $a13 = "SELECT * FROM Win32_Processor" wide fullword
        $a14 = "SELECT * FROM Win32_OperatingSystem" wide fullword
        $a15 = "SELECT * FROM Win32_ComputerSystem" wide fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_Trickbot_07239dad {
    meta:
        id = "3IwwHevoERaVkzgjlyhGQt"
        fingerprint = "v1_sha256_231592d1a45798de6d22c922626ca28ef4019bae95d552a0f2822823d8dec384"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets vncDll64.dll module containing remote control VNC functionality"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "DBD534F2B5739F89E99782563062169289F23AA335639A9552173BEDC98BB834"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "C:\\Users\\MaxMikhaylov\\Documents\\Visual Studio 2010\\MMVNC.PROXY\\VNCSRV\\x64\\Release\\VNCSRV.pdb" ascii fullword
        $a2 = "vncsrv.dll" ascii fullword
        $a3 = "-new -noframemerging http://www.google.com" ascii fullword
        $a4 = "IE.HTTP\\shell\\open\\command" ascii fullword
        $a5 = "EDGE\\shell\\open\\command" ascii fullword
        $a6 = "/K schtasks.exe |more" ascii fullword
        $a7 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/></moduleconfig> " ascii fullword
        $a8 = "\\Microsoft Office\\Office16\\outlook.exe" ascii fullword
        $a9 = "\\Microsoft Office\\Office11\\outlook.exe" ascii fullword
        $a10 = "\\Microsoft Office\\Office15\\outlook.exe" ascii fullword
        $a11 = "\\Microsoft Office\\Office12\\outlook.exe" ascii fullword
        $a12 = "\\Microsoft Office\\Office14\\outlook.exe" ascii fullword
        $a13 = "TEST.TEMP:" ascii fullword
        $a14 = "Chrome_WidgetWin" wide fullword
        $a15 = "o --disable-gpu --disable-d3d11 --disable-accelerated-2d-canvas" ascii fullword
        $a16 = "NetServerStart" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_Trickbot_fd7a39af {
    meta:
        id = "1IjnXLkbQ1NQosICE6zC8e"
        fingerprint = "v1_sha256_15cb286504e6167c78e194488555f565965a03e7714fe16692a115df26985a01"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets wormDll64.dll module containing spreading functionality"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "D5BB8D94B71D475B5EB9BB4235A428563F4104EA49F11EF02C8A08D2E859FD68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "module64.dll" ascii fullword
        $a2 = "worming.png" wide
        $a3 = "Size - %d kB" ascii fullword
        $a4 = "[+] %s -" wide fullword
        $a5 = "%s\\system32" ascii fullword
        $a6 = "[-] %s" wide fullword
        $a7 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/></moduleconfig>" ascii fullword
        $a8 = "*****MACHINE IN WORKGROUP*****" wide fullword
        $a9 = "*****MACHINE IN DOMAIN*****" wide fullword
        $a10 = "\\\\%s\\IPC$" ascii fullword
        $a11 = "Windows 5" ascii fullword
        $a12 = "InfMach" ascii fullword
        $a13 = "%s x64" wide fullword
        $a14 = "%s x86" wide fullword
        $a15 = "s(&(objectCategory=computer)(userAccountControl:" wide fullword
        $a16 = "------MACHINE IN D-N------" wide fullword
    condition:
        5 of ($a*)
}

rule Windows_Trojan_Trickbot_2d89e9cd {
    meta:
        id = "6q8vuzsoZGxPrebNgYlo00"
        fingerprint = "v1_sha256_c15833687c2aed55aae0bb5de83c088cb66edeb4ad1964543522f5477c1f1942"
        version = "1.0"
        date = "2021-03-29"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets tabDll64.dll module containing functionality using SMB for lateral movement"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "3963649ebfabe8f6277190be4300ecdb68d4b497ac5f81f38231d3e6c862a0a8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64( pX64function, ctx ) failed" ascii fullword
        $a2 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pExecuteX64 failed" ascii fullword
        $a3 = "%SystemRoot%\\system32\\stsvc.exe" ascii fullword
        $a4 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64=0x%08p, pX64function=0x%08p, ctx=0x%08p" ascii fullword
        $a5 = "DLL and target process must be same architecture" ascii fullword
        $a6 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pX64function failed" ascii fullword
        $a7 = "%SystemDrive%\\stsvc.exe" ascii fullword
        $a8 = "Wrote shellcode to 0x%x" ascii fullword
        $a9 = "ERROR: %d, line - %d" wide fullword
        $a10 = "[INJECT] inject_via_remotethread_wow64: Success, hThread=0x%08p" ascii fullword
        $a11 = "GetProcessPEB:EXCEPT" wide fullword
        $a12 = "Checked count - %i, connected count %i" wide fullword
        $a13 = "C:\\%s\\%s C:\\%s\\%s" ascii fullword
        $a14 = "C:\\%s\\%s" ascii fullword
        $a15 = "%s\\ADMIN$\\stsvc.exe" wide fullword
        $a16 = "%s\\C$\\stsvc.exe" wide fullword
        $a17 = "Size - %d kB" ascii fullword
        $a18 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"dpost"
        $a19 = "%s - FAIL" wide fullword
        $a20 = "%s - SUCCESS" wide fullword
        $a21 = "CmainSpreader::init() CreateEvent, error code %i" wide fullword
        $a22 = "Incorrect ModuleHandle %i, expect %i" wide fullword
        $a23 = "My interface is \"%i.%i.%i.%i\", mask \"%i.%i.%i.%i\"" wide fullword
        $a24 = "WormShare" ascii fullword
        $a25 = "ModuleHandle 0x%08X, call Control: error create thread %i" wide fullword
        $a26 = "Enter to Control: moduleHandle 0x%08X, unknown Ctl = \"%S\"" wide fullword
    condition:
        3 of ($a*)
}

rule Windows_Trojan_Trickbot_32930807 {
    meta:
        id = "2iYot90X46jxHZ1NGZap6L"
        fingerprint = "v1_sha256_e98503696bd72cab4d0d1633991bdb87c0537fd1e2d95507ccd474125328f318"
        version = "1.0"
        date = "2021-03-30"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets cookiesdll.dll module containing functionality used to retrieve browser cookie data"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "e999b83629355ec7ff3b6fda465ef53ce6992c9327344fbf124f7eb37808389d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "select name, encrypted_value, host_key, path, length(encrypted_value), creation_utc, expires_utc from cookies where datetime(exp"
        $a2 = "Cookies send failure: servers unavailable" ascii fullword
        $a3 = "<moduleconfig>"
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_618b27d2 {
    meta:
        id = "4AK6OBsUH3q1IxDI9o1YI6"
        fingerprint = "v1_sha256_e66a9dd7efdbff8b9e30119d0e99187e3dfa4ca1c1bc1ade0f8f1003d10e2620"
        version = "1.0"
        date = "2021-03-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets Outlook.dll module containing functionality used to retrieve Outlook data"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "d3ec8f4a46b21fb189fc3d58f3d87bf9897653ecdf90b7952dcc71f3b4023b4e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "OutlookX32.dll" ascii fullword
        $a2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" wide fullword
        $a3 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook" wide fullword
        $a4 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook" wide fullword
        $a5 = "OutlookX32" ascii fullword
        $a6 = " Port:" wide fullword
        $a7 = " User:" wide fullword
        $a8 = " Pass:" wide fullword
        $a9 = "String$" ascii fullword
        $a10 = "outlookDecrU" ascii fullword
        $a11 = "Cannot Decrypt" ascii fullword
        $a12 = " Mail:" wide fullword
        $a13 = " Serv:" wide fullword
        $a14 = ",outlookDecr" ascii fullword
        $a15 = "CryptApi" ascii fullword
    condition:
        5 of ($a*)
}

rule Windows_Trojan_Trickbot_6eb31e7b {
    meta:
        id = "3OhOgr81r1rybiYFafC226"
        fingerprint = "v1_sha256_5b6902c8644c79bd183725f0e41bf2f7ae425bf0eb1dddea6fd1a38b77f176ba"
        version = "1.0"
        date = "2021-03-30"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets DomainDll module containing functionality using LDAP to retrieve credentials and configuration information"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "3e3d82ea4764b117b71119e7c2eecf46b7c2126617eafccdfc6e96e13da973b1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "module32.dll" ascii fullword
        $a2 = "Size - %d kB" ascii fullword
        $a3 = "</moduleconfig> " ascii fullword
        $a4 = "<moduleconfig>" ascii fullword
        $a5 = "\\\\%ls\\SYSVOL\\%ls" wide fullword
        $a6 = "DomainGrabber"
        $a7 = "<autostart>yes</autostart>" ascii fullword
        $a8 = "<needinfo name=\"id\"/>" ascii fullword
        $a9 = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" wide fullword
    condition:
        5 of ($a*)
}

rule Windows_Trojan_Trickbot_91516cf4 {
    meta:
        id = "6FA0RtiAkukMcbBV25wuzH"
        fingerprint = "v1_sha256_6c0bdd6827bebb337c0012cdb6e931cd96ce2ad61f3764f288b96ff049b2d007"
        version = "1.0"
        date = "2021-03-30"
        modified = "2021-08-31"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Generic signature used to identify Trickbot module usage"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "6cd0d4666553fd7184895502d48c960294307d57be722ebb2188b004fc1a8066"
        severity = 80
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "<moduleconfig>" ascii wide
        $a2 = "<autostart>" ascii wide
        $a3 = "</autostart>" ascii wide
        $a4 = "</moduleconfig>" ascii wide
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_be718af9 {
    meta:
        id = "3gcpD5fzlWiSfwnsbmIIIU"
        fingerprint = "v1_sha256_d020f7d1637fc4ee3246e97c9acae0be1782e688154bd109f53f807211beebd7"
        version = "1.0"
        date = "2021-03-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets permadll module used to fingerprint BIOS/firmaware data"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "c1f1bc58456cff7413d7234e348d47a8acfdc9d019ae7a4aba1afc1b3ed55ffa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "user_platform_check.dll" ascii fullword
        $a2 = "<moduleconfig><nohead>yes</nohead></moduleconfig>" ascii fullword
        $a3 = "DDEADFDEEEEE"
        $a4 = "\\`Ruuuuu_Exs|_" ascii fullword
        $a5 = "\"%pueuu%" ascii fullword
    condition:
        3 of ($a*)
}

rule Windows_Trojan_Trickbot_f8dac4bc {
    meta:
        id = "6CRhDoWWYWNCIP6gqnmKDX"
        fingerprint = "v1_sha256_d4536aac0ee402abcb87826e45c892d6f39562bc1e39b72ae8880dc077f230d9"
        version = "1.0"
        date = "2021-03-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets rdpscan module used to bruteforce RDP"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "13d102d546b9384f944f2a520ba32fb5606182bed45a8bba681e4374d7e5e322"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "rdpscan.dll" ascii fullword
        $a2 = "F:\\rdpscan\\Bin\\Release_nologs\\"
        $a3 = "Cookie: %s %s" wide fullword
        $a4 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"srv\" file=\"srv\" period=\"60\"/></autoconf><"
        $a5 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"srv\" file=\"srv\" period=\"60\"/></autoconf><"
        $a6 = "X^Failed to create a list of contr" ascii fullword
        $a7 = "rdp/domains" wide fullword
        $a8 = "Your product name" wide fullword
        $a9 = "rdp/over" wide fullword
        $a10 = "rdp/freq" wide fullword
        $a11 = "rdp/names" wide fullword
        $a12 = "rdp/dict" wide fullword
        $a13 = "rdp/mode" wide fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_9c0fa8fe {
    meta:
        id = "3YBmJWr7ulrt6fxesKINHW"
        fingerprint = "v1_sha256_23aebc3139c34ecd609db7920fa0d5e194173409e1862555e4c468dad6c46299"
        version = "1.0"
        date = "2021-07-13"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "f528c3ea7138df7c661d88fafe56d118b6ee1d639868212378232ca09dc9bfad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 74 19 48 85 FF 74 60 8B 46 08 39 47 08 76 6A 33 ED B1 01 B0 01 }
    condition:
        all of them
}

