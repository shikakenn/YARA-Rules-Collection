rule Windows_Ransomware_Haron_a1c12e7e {
    meta:
        id = "UCpzIs3z40Ym3eJEf2STR"
        fingerprint = "v1_sha256_84df5a13495acee5dc2007cf1d6e1828a832d46fcbad2ca8676643fd47756248"
        version = "1.0"
        date = "2021-08-03"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Direct overlap with Thanos/Avaddon"
        category = "INFO"
        threat_name = "Windows.Ransomware.Haron"
        reference_sample = "6e6b78a1df17d6718daa857827a2a364b7627d9bfd6672406ad72b276014209c"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 00 04 28 0E 00 00 0A 06 FE 06 2A 00 00 06 73 0F 00 00 0A 28 }
    condition:
        any of them
}

rule Windows_Ransomware_Haron_23b76cb7 {
    meta:
        id = "1ki3pZZuSHWrg3YNCWlvUQ"
        fingerprint = "v1_sha256_e53c92be617444da0057680ee1ac45cbc1f707194281644bececa44e4ebe3580"
        version = "1.0"
        date = "2021-08-03"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Direct overlap with Thanos/Avaddon"
        category = "INFO"
        threat_name = "Windows.Ransomware.Haron"
        reference_sample = "6e6b78a1df17d6718daa857827a2a364b7627d9bfd6672406ad72b276014209c"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 0A 28 06 00 00 06 26 DE 0A 08 2C 06 08 6F 48 00 00 0A DC DE }
    condition:
        any of them
}

