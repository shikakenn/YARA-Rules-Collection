rule Linux_Trojan_Asacub_d3c4aa41 {
    meta:
        id = "2YuZWeRq9PUZXtIe6N3AER"
        fingerprint = "v1_sha256_3645e10e5ef8c50e5e82d749da07f5669c5162cb95aa5958ce45a414b870f619"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Asacub"
        reference_sample = "15044273a506f825859e287689a57c6249b01bb0a848f113c946056163b7e5f1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 8B 0F 83 EC 08 50 57 FF 51 54 83 C4 10 8B 8B DC FF FF FF 89 4C }
    condition:
        all of them
}

