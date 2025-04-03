rule MacOS_Trojan_Bundlore_28b13e67 {
    meta:
        id = "3rbPCNfEPd7RYvTrQCpif0"
        fingerprint = "v1_sha256_586ae19e570c51805afd3727b2e570cdb1c48344aa699e54774a708f02bc3a6f"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "0b50a38749ea8faf571169ebcfce3dfd668eaefeb9a91d25a96e6b3881e4a3e8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 05 A5 A3 A9 37 D2 05 13 E9 3E D6 EA 6A EC 9B DC 36 E5 76 A7 53 B3 0F 06 46 D1 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_75c8cb4e {
    meta:
        id = "1kjKD7S5clhfR885cRpAEg"
        fingerprint = "v1_sha256_527fecb8460c0325c009beddd6992e0abbf8c5a05843e4cedf3b17deb4b19a1c"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "3d69912e19758958e1ebdef5e12c70c705d7911c3b9df03348c5d02dd06ebe4e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 EE 19 00 00 EA 80 35 E8 19 00 00 3B 80 35 E2 19 00 00 A4 80 35 DC 19 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_17b564b4 {
    meta:
        id = "NjtILqvoClHcaAfcwZ0oD"
        fingerprint = "v1_sha256_40cd2a793c8ed51a8191ecb9b358f50dc2035d997d0f773f6049f9c272291607"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "94f6e5ee6eb3a191faaf332ea948301bbb919f4ec6725b258e4f8e07b6a7881d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 D9 11 00 00 05 80 35 D3 11 00 00 2B 80 35 CD 11 00 00 F6 80 35 C7 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_c90c088a {
    meta:
        id = "2YV700Um1pm5yy56z7Z6nu"
        fingerprint = "v1_sha256_c82c5c8d1e38e0d2631c5611e384eb49b58c64daeafe0cc642682e5c64686b60"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "875513f4ebeb63b9e4d82fb5bff2b2dc75b69c0bfa5dd8d2895f22eaa783f372"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 E1 11 00 00 92 80 35 DB 11 00 00 2A 80 35 D5 11 00 00 7F 80 35 CF 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_3965578d {
    meta:
        id = "2QtqQ13SDnZp1ei0cIxt8"
        fingerprint = "v1_sha256_6bd24640e0a3aa152fcd90b6975ee4fb7e99ab5f2d48d3a861bc804c526c90b6"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "d72543505e36db40e0ccbf14f4ce3853b1022a8aeadd96d173d84e068b4f68fa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 33 2A 00 00 60 80 35 2D 2A 00 00 D0 80 35 27 2A 00 00 54 80 35 21 2A 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_00d9d0e9 {
    meta:
        id = "625s4scdbW8tZemED60Nb2"
        fingerprint = "v1_sha256_535831872408caa27984190d1b1b1a5954e502265925d50457e934219598dbfd"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "73069b34e513ff1b742b03fed427dc947c22681f30cf46288a08ca545fc7d7dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 8E 11 00 00 55 80 35 88 11 00 00 BC 80 35 82 11 00 00 72 80 35 7C 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_650b8ff4 {
    meta:
        id = "5ISOxVJl5MVX46IfSzvs8n"
        fingerprint = "v1_sha256_e8a706db010e9c3d9714d5e7a376e9b2189af382a7b01db9a9e7ee947e9637bb"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "78fd2c4afd7e810d93d91811888172c4788a0a2af0b88008573ce8b6b819ae5a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 8B 11 00 00 60 80 35 85 11 00 00 12 80 35 7F 11 00 00 8C 80 35 79 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_c8ad7edd {
    meta:
        id = "4qfh91XOQlTItqDHBShC6x"
        fingerprint = "v1_sha256_be09b4bd612bb499044fe91ca4e1ab62405cf1e4d75b8e1da90e326d1c66e04f"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "d4915473e1096a82afdaee405189a0d0ae961bd11a9e5e9adc420dd64cb48c24"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 74 11 00 00 D5 80 35 6E 11 00 00 57 80 35 68 11 00 00 4C 80 35 62 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_cb7344eb {
    meta:
        id = "5g5o1o4nR44WSAVGp8N2e0"
        fingerprint = "v1_sha256_6b5e868dfd14e9b1cdf3caeb1216764361b28c1dd38849526baf5dbdb1020d8d"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "53373668d8c5dc17f58768bf59fb5ab6d261a62d0950037f0605f289102e3e56"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 ED 09 00 00 92 80 35 E7 09 00 00 93 80 35 E1 09 00 00 16 80 35 DB 09 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_753e5738 {
    meta:
        id = "6uwbjpHbGBqIYr0pYw34Ko"
        fingerprint = "v1_sha256_7a6907b51c793e4182c1606eab6f2bcb71f0350a34aef93fa3f3a9f1a49961ba"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "42aeea232b28724d1fa6e30b1aeb8f8b8c22e1bc8afd1bbb4f90e445e31bdfe9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 9A 11 00 00 96 80 35 94 11 00 00 68 80 35 8E 11 00 00 38 80 35 88 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_7b9f0c28 {
    meta:
        id = "2oYJaVIzyqU8p3RhQsKQAZ"
        fingerprint = "v1_sha256_32abbb76c866e3a555ee6a9c39f62a0712f641959b66068abfb4379baa9a9da9"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "fc4da125fed359d3e1740dafaa06f4db1ffc91dbf22fd5e7993acf8597c4c283"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 B6 15 00 00 81 80 35 B0 15 00 00 14 80 35 AA 15 00 00 BC 80 35 A4 15 00 00 }
    condition:
        all of them
}

