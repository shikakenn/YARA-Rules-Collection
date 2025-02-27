rule Windows_Trojan_ArkeiStealer_84c7086a {
    meta:
        id = "3ZyghUsmMAaLlLsDGxHtr3"
        fingerprint = "v1_sha256_b7129094389f789f0b43f0da54645c24a6d1149f53d6536c14714e3ff44f935b"
        version = "1.0"
        date = "2022-02-17"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.ArkeiStealer"
        reference_sample = "708d9fb40f49192d4bf6eff62e0140c920a7eca01b9f78aeaf558bef0115dbe2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 01 89 55 F4 8B 45 F4 3B 45 10 73 31 8B 4D 08 03 4D F4 0F BE 19 8B }
    condition:
        all of them
}

