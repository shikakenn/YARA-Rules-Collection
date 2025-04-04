rule Linux_Trojan_Sckit_a244328f {
    meta:
        id = "1j4Ko9SbXDzWKUs2eoNgJ"
        fingerprint = "v1_sha256_8001c9fcf9f8b70c3e27554156b0b26ddcd6cab36bf97cf3b89a4c43c9ad883c"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sckit"
        reference_sample = "685da66303a007322d235b7808190c3ea78a828679277e8e03e6d8d511df0a30"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 34 D0 04 08 BB 24 C3 04 08 CD 80 C7 05 A0 EE 04 }
    condition:
        all of them
}

