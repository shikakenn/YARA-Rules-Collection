rule MacOS_Trojan_Metasploit_6cab0ec0 {
    meta:
        id = "1PfYR2a5I27hJnCGKdmXwW"
        fingerprint = "v1_sha256_c19fe812b74b034bfb42c0e2ee552d879ed038e054c5870b85e7e610d3184198"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = "mettlesploit! " ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_293bfea9 {
    meta:
        id = "5zjmhMasbzgVSAhGZduIrW"
        fingerprint = "v1_sha256_b8bd0d034a6306f99333723d77724ae53c1a189dad3fad7417f2d2fde214c24a"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = "_webcam_get_frame" ascii fullword
        $a2 = "_get_process_info" ascii fullword
        $a3 = "process_new: got %zd byte executable to run in memory" ascii fullword
        $a4 = "Dumping cert info:" ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_448fa81d {
    meta:
        id = "78RTQCQyd7Ack05FPJorDw"
        fingerprint = "v1_sha256_ab0608920b9f632bad99e1358f21a88bc6048f46fca21a488a1a10b7ef1e42ae"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = "/Users/vagrant/mettle/mettle/src/process.c" ascii fullword
        $a2 = "/Users/vagrant/mettle/mettle/src/c2_http.c" ascii fullword
        $a3 = "/Users/vagrant/mettle/mettle/src/mettle.c" ascii fullword
    condition:
        any of them
}

rule MacOS_Trojan_Metasploit_768df39d {
    meta:
        id = "6iGgFnVO1fwpwvg9kQz2BL"
        fingerprint = "v1_sha256_140ba93d57b27325f66b36132ecaab205663e3e582818baf377e050802c8d152"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Byte sequence based on Metasploit shell_reverse_tcp.rb"
        category = "INFO"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_reverse_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = { FF 4F E8 79 F6 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_7ce0b709 {
    meta:
        id = "47gKdAtk6BWbvOSPlhSVQL"
        fingerprint = "v1_sha256_56fc05ece464d562ff6e56247756454c940c07b03c4a4c783b2bae4d5807247a"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Byte sequence based on Metasploit shell_bind_tcp.rb"
        category = "INFO"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = { FF 4F E4 79 F6 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_f11ccdac {
    meta:
        id = "29PvHesChspEBs0dn8cEY4"
        fingerprint = "v1_sha256_fcf578d3e98b591b33cb6f4bec1b9e92a7e1a88f0b56f3c501f9089d2094289c"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Byte sequence based on Metasploit shell_find_port.rb"
        category = "INFO"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_find_port.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = { 50 6A 1F 58 CD 80 66 81 7F 02 04 D2 75 EE 50 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_d9b16f4c {
    meta:
        id = "556uYjRCwJRyBmJaacnBXf"
        fingerprint = "v1_sha256_8e082878fb52f6314ec8c725dd279447ee8a0fc403c47ffd997712adb496e7c3"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Byte sequence based on Metasploit vforkshell_bind_tcp.rb"
        category = "INFO"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7E 00 00 00 89 C6 52 52 52 68 00 02 34 12 89 E3 6A }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_2992b917 {
    meta:
        id = "3KdiFZvioxshjrowx0kPUm"
        fingerprint = "v1_sha256_10056ffb719092f83ad236a63ef6fa1f40568e500c042bd737575997bb67a8ec"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Byte sequence based on Metasploit vforkshell_reverse_tcp.rb"
        category = "INFO"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_reverse_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 6D 89 C7 52 52 68 7F 00 00 01 68 00 02 34 12 89 E3 6A }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_27d409f1 {
    meta:
        id = "11CrKjTK8GEJrcjNHNdo9L"
        fingerprint = "v1_sha256_b757e0ab6665a3e4846c6bbe4386e9d9a730ece00a2453933ce771aec2dd716e"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Byte sequence based on Metasploit x64 shell_bind_tcp.rb"
        category = "INFO"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x64/shell_bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = { B8 61 00 00 02 6A 02 5F 6A 01 5E 48 31 D2 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_65a2394b {
    meta:
        id = "2ZD05Vvkj9wmYV8gIm6JqK"
        fingerprint = "v1_sha256_f01f671b0bf9fa53aa3383c88ba871742f0e55dbdae4278f440ed29f35eb1ca1"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Byte sequence based on Metasploit stages vforkshell.rb"
        category = "INFO"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stages/osx/x86/vforkshell.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = { 31 DB 83 EB 01 43 53 57 53 B0 5A CD 80 72 43 83 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_c7b7a90b {
    meta:
        id = "2rhtDHNPvZivDnIkNrjqLR"
        fingerprint = "v1_sha256_d4b1f01bf8434dd69188d2ad0b376fad3a4d9c94ebe74d40f05019baf95b5496"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Byte sequence based on Metasploit stager reverse_tcp.rb"
        category = "INFO"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/reverse_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_4bd6aaca {
    meta:
        id = "5zWRm6AxXk968AnInUjcsq"
        fingerprint = "v1_sha256_a3de610ced90679f6fa0dcdf7890a64369c774839ea30018a7ef6fe9289d3d17"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Byte sequence based on Metasploit stager x86 bind_tcp.rb"
        category = "INFO"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7D }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_5e5b685f {
    meta:
        id = "61KpS5yOloZQonlrZuW6gg"
        fingerprint = "v1_sha256_003fb4f079b125f37899a2b3cb62d80edd5b3e5ccbed5bc1ea514a4a173d329d"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "cdf0a3c07ef1479b53d49b8f22a9f93adcedeea3b869ef954cc043e54f65c3d0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = { 00 00 F4 90 90 90 90 55 48 89 E5 48 81 EC 60 20 00 00 89 F8 48 8B 0D 74 23 00 }
    condition:
        all of them
}

