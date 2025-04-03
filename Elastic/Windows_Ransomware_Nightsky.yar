rule Windows_Ransomware_Nightsky_a7f19411 {
    meta:
        id = "2CYYEBheN4evKPkWn1oahf"
        fingerprint = "v1_sha256_defc7ab43035c663302edfda60a4b57cb301b3d61662afe3ce1de2ac93cfc3e2"
        version = "1.0"
        date = "2022-01-11"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Nightsky"
        reference_sample = "1fca1cd04992e0fcaa714d9dfa97323d81d7e3d43a024ec37d1c7a2767a17577"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "\\NightSkyReadMe.hta" wide fullword
        $a2 = ".nightsky" wide fullword
        $a3 = "<h1 id=\"nightsky\"><center><span style=\"color: black; font-size: 48pt\">NIGHT SKY</span></center>" ascii fullword
        $a4 = "URL:https://contact.nightsky.cyou" ascii fullword
    condition:
        2 of them
}

rule Windows_Ransomware_Nightsky_253c4d0d {
    meta:
        id = "37Y3O2ZKcJK8HetJbGNxBd"
        fingerprint = "v1_sha256_ba9e6dab664e464e0fdc65bd8bdccc661846d85e7fd8fbf089e72e9e5b71fb17"
        version = "1.0"
        date = "2022-03-14"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Nightsky"
        reference_sample = "2c940a35025dd3847f7c954a282f65e9c2312d2ada28686f9d1dc73d1c500224"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 43 B8 48 2B D9 49 89 43 C0 4C 8B E2 49 89 43 C8 4C 8B F1 49 89 }
    condition:
        all of them
}

