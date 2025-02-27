rule MacOS_Infostealer_MdQuerySecret_5535ab96 {
    meta:
        id = "1El9Wdriw548aP9oL0vkE7"
        fingerprint = "v1_sha256_c755e617b9dd41505bb225ea836ecdde8f3f6f9ab7ae79697e6d85190e206c41"
        version = "1.0"
        date = "2023-04-11"
        modified = "2024-08-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Infostealer.MdQuerySecret"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $string1 = /kMDItemTextContent\s{1,50}==\s{1,50}\S{1,50}secret/ ascii wide nocase
        $string2 = /kMDItemDisplayName\s{1,50}==\s{1,50}\S{1,50}secret\S{1,50}/ ascii wide nocase
    condition:
        any of ($string1, $string2)
}

