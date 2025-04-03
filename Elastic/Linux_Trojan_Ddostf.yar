rule Linux_Trojan_Ddostf_e4874cd4 {
    meta:
        id = "71tB7xuKBsxIrDnZg45TkQ"
        fingerprint = "v1_sha256_1523fe8f7bbbc7e42f8c2efe5b28dd381007846a1ba7078a6f1a30aedace884b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E4 01 8B 45 F0 2B 45 F4 89 C2 8B 45 E4 39 C2 73 82 8B 45 EC }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_32c35334 {
    meta:
        id = "6OrI7Tiy0sDbku0L2AOoS2"
        fingerprint = "v1_sha256_d62d450d48756c09f8788b27301de889c864e597924a0526a325fa602f91f376"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ddostf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0E 18 41 0E 1C 41 0E 20 48 0E 10 00 4C 00 00 00 64 4B 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_6dc1caab {
    meta:
        id = "251TWE2cVqQXxgpzipNa1S"
        fingerprint = "v1_sha256_fd70960ed6e06f4d152bbd211fbe491dad596010da12cd53c93b577b551b8053"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "f4587bd45e57d4106ebe502d2eaa1d97fd68613095234038d67490e74c62ba70"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FC 01 83 45 F8 01 83 7D F8 5A 7E E6 C7 45 F8 61 00 00 00 EB 14 8B }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_dc47a873 {
    meta:
        id = "3Qsh95XtiU5v6cptIU1xmK"
        fingerprint = "v1_sha256_2f5bd9e012fd778388074cf29b56c7cd59391840f994835d087b7b661445d316"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 05 88 10 8B 45 08 0F B6 10 83 E2 0F 83 CA 40 88 10 8B 45 08 C6 40 }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_cb0358a0 {
    meta:
        id = "7SfOowTDuXECnWYX7GJYkN"
        fingerprint = "v1_sha256_1f152b69bf0b2bfa539fdd42c432e456b9efb3766a450333a987313bb12c1826"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 66 C7 45 F2 00 00 8D 45 F2 8B 55 E4 0F B6 12 88 10 0F B7 45 F2 0F }
    condition:
        all of them
}

