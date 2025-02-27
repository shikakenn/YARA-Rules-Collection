rule Windows_Ransomware_Doppelpaymer_6660d29f : beta {
    meta:
        id = "76vENfnFll8827ke5HhAeI"
        fingerprint = "v1_sha256_4c12eaa44f82c6f729e51242c9c1836eb1856959c682e2d2e21b975104c197b6"
        version = "1.0"
        date = "2020-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies DOPPELPAYMER ransomware"
        category = "INFO"
        reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
        threat_name = "Windows.Ransomware.Doppelpaymer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Setup run" wide fullword
        $a2 = "RtlComputeCrc32" ascii fullword
    condition:
        2 of ($a*)
}

rule Windows_Ransomware_Doppelpaymer_6ab188da : beta {
    meta:
        id = "11l6edruAr8ALRlEMfeGGC"
        fingerprint = "v1_sha256_429c87d293b7f517a594e8be020cbe7f8302a8b6eb8337f090ca18973aafbde4"
        version = "1.0"
        date = "2020-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies DOPPELPAYMER ransomware"
        category = "INFO"
        reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
        threat_name = "Windows.Ransomware.Doppelpaymer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $d1 = { 56 55 55 55 F7 EF B8 56 55 55 55 8B EA F7 E9 8B C2 8B D1 C1 FA 1F 2B C2 C1 FF 1F 2B EF 8D 14 40 B8 F3 1A CA 6B 2B CA 03 E9 F7 ED 8B CD C1 FA 05 C1 F9 1F 2B D1 6B CA B4 03 CD 74 1C 81 E1 03 00 00 80 7D 07 83 E9 01 83 C9 FC 41 8B C1 F7 D8 85 C9 8D 7C 05 04 0F 45 EF 8D 44 55 02 5D 5F C3 }
    condition:
        1 of ($d*)
}

rule Windows_Ransomware_Doppelpaymer_4fb1a155 : beta {
    meta:
        id = "2HoRmasZca8ohNvRC6mUt9"
        fingerprint = "v1_sha256_eb041a836b2bc73312a2f87523d817d5274f3d43d3e5fe6aacfad1399c61a9de"
        version = "1.0"
        date = "2020-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies DOPPELPAYMER ransomware"
        category = "INFO"
        reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
        threat_name = "Windows.Ransomware.Doppelpaymer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $c1 = { 83 EC 64 8B E9 8B 44 24 ?? 8B 00 0F B7 10 83 FA 5C 75 }
    condition:
        1 of ($c*)
}

