rule Linux_Trojan_Sfloost_69a5343a {
    meta:
        id = "6CdBJNelJfhJhcXeTgUlIt"
        fingerprint = "v1_sha256_bd3cd33d02c7ca1d3a0364e5e3e2f968f32da8f087f744232f3cb786da6c7875"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sfloost"
        reference_sample = "c0cd73db5165671c7bbd9493c34d693d25b845a9a21706081e1bf44bf0312ef9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F 83 C8 50 88 43 0C 0F B6 45 F0 66 C7 43 10 00 00 66 C7 43 12 }
    condition:
        all of them
}

