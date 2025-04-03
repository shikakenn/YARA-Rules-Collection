rule Linux_Trojan_Ladvix_db41f9d2 {
    meta:
        id = "6KnHoEBknmuWHFJ3kyAN6m"
        fingerprint = "v1_sha256_81642b4ff1b6488098f019c5e992fc942916bc6eb593006cf91e878ac41509d6"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ladvix"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C0 49 89 C4 74 45 45 85 ED 7E 26 48 89 C3 41 8D 45 FF 4D 8D 7C }
    condition:
        all of them
}

rule Linux_Trojan_Ladvix_77d184fd {
    meta:
        id = "7MsXz0D96szm84o61raS5N"
        fingerprint = "v1_sha256_0ae9c41d3eb7964344f71b9708278a0e83776228e4455cf0ad7c08e288305203"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ladvix"
        reference_sample = "1bb44b567b3c82f7ee0e08b16f7326d1af57efe77d608a96b2df43aab5faa9f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 40 10 48 89 45 80 8B 85 64 FF FF FF 48 89 E2 48 89 D3 48 63 D0 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ladvix_c9888edb {
    meta:
        id = "3600OAHK6alKrfQ4qPvsQw"
        fingerprint = "v1_sha256_608f2340b0ee4b843933d8137aa0908583a6de477e6c472fb4bd2e5bb62dfb80"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ladvix"
        reference_sample = "1d798e9f15645de89d73e2c9d142189d2eaf81f94ecf247876b0b865be081dca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E8 01 83 45 E4 01 8B 45 E4 83 F8 57 76 B5 83 45 EC 01 8B 45 EC 48 }
    condition:
        all of them
}

rule Linux_Trojan_Ladvix_81fccd74 {
    meta:
        id = "4QhJKTjRResn7uKonTKQ54"
        fingerprint = "v1_sha256_18f7ca953d22f02c1dbf03595a19b66ea582d2c1623f0042dcf15f86556ca41e"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "2a183f613fca5ec30dfd82c9abf72ab88a2c57d2dd6f6483375913f81aa1c5af"
        threat_name = "Linux.Trojan.Ladvix"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 EA 00 00 48 8D 45 EA 48 8B 55 F0 0F B6 12 88 10 0F B7 45 EA 0F }
    condition:
        all of them
}

