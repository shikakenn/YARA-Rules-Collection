rule MacOS_Virus_Maxofferdeal_53df500f {
    meta:
        id = "OniFMdmIIGxbAa3L1EXJI"
        fingerprint = "v1_sha256_ed63c14e31c200f906b525c7ef1cd671511a89c8833cfa1a605fc9870fe91043"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }
    condition:
        all of them
}

rule MacOS_Virus_Maxofferdeal_f4681eba {
    meta:
        id = "6VrVQl1NbR6DsTv2Z9p1qt"
        fingerprint = "v1_sha256_cf478ec5313b40d74d110e4d6e97da5f671d5af331adc3ab059a69616e78c76c"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { BA A4 C8 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }
    condition:
        all of them
}

rule MacOS_Virus_Maxofferdeal_4091e373 {
    meta:
        id = "1sX0yZvnV82jchrIg2I71D"
        fingerprint = "v1_sha256_ce82f6d3a2e4b7ffe7010629bf91a9144a94e50513682a6c0622603d28248d51"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "c38c4bdd3c1fa16fd32db06d44d0db1b25bb099462f8d2936dbdd42af325b37c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { B8 F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 8B 8E 8A BD A6 AC A4 }
    condition:
        all of them
}

rule MacOS_Virus_Maxofferdeal_20a0091e {
    meta:
        id = "7eURLhPgNoVV01TCNasgfp"
        fingerprint = "v1_sha256_bb90b7e1637fd86e91763b4801a0b3bb8a1b956f328d07e96cf1b26e42b1931b"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "b00a61c908cd06dbc26bee059ba290e7ce2ad6b66c453ea272c7287ffa29c5ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 A0 BC BC B8 F2 E7 E7 BF }
    condition:
        all of them
}

