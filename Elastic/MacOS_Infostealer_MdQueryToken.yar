rule MacOS_Infostealer_MdQueryToken_1c52d574 {
    meta:
        id = "21ApRbDmjqXFGzIiml4jUS"
        fingerprint = "v1_sha256_ede29154aae99bb67075e21acb694b089f9a1b366a4e2505cb761142393994a8"
        version = "1.0"
        date = "2023-04-11"
        modified = "2024-08-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Infostealer.MdQueryToken"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $string1 = /kMDItemTextContent\s{1,50}==\s{1,50}\S{1,50}token/ ascii wide nocase
        $string2 = /kMDItemDisplayName\s{1,50}==\s{1,50}\S{1,50}token\S{1,50}/ ascii wide nocase
    condition:
        any of ($string1, $string2)
}

