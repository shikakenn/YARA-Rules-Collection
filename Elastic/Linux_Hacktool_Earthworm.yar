rule Linux_Hacktool_Earthworm_4de7b584 {
    meta:
        id = "3lDrdrDPXzzMxtR33HyYDT"
        fingerprint = "v1_sha256_019b2504df192e673f96a86464bb5e8ba5e89190e51bfe7d702753f76c00b979"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Earthworm"
        reference_sample = "9d61aabcf935121b4f7fc6b0d082d7d6c31cb43bf253a8603dd46435e66b7955"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 73 6F 63 6B 73 64 20 2C 20 72 63 73 6F 63 6B 73 20 2C 20 72 73 }
    condition:
        all of them
}

rule Linux_Hacktool_Earthworm_82d5c4cf {
    meta:
        id = "5UsaQLNCLscubfLycKDtmn"
        fingerprint = "v1_sha256_81f35293bd3dd0cfbbf67f036773e16625bb74e06320fa1fff5bc428ef2f3a43"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Earthworm"
        reference_sample = "dc412d4f2b0e9ca92063a47adfb0657507d3f2a54a415619db5a7ccb59afb204"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E5 48 83 EC 20 31 C0 89 C1 48 8D 55 F0 48 89 7D F8 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Earthworm_4ec2ec63 {
    meta:
        id = "2LVuuuqVN4YCEwC65jU4bj"
        fingerprint = "v1_sha256_25f616c5440a48aef0f824cb6859e88787db4f42c1ec904a3d3bd72f3a64116e"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Earthworm"
        reference_sample = "dc412d4f2b0e9ca92063a47adfb0657507d3f2a54a415619db5a7ccb59afb204"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E5 48 83 EC 20 BA 04 00 00 00 48 8D 45 F0 48 89 7D F8 89 }
    condition:
        all of them
}

