rule MacOS_Infostealer_MdQueryPassw_6125f987 {
    meta:
        id = "7IKIWSsNpYqUxEopEEwpRQ"
        fingerprint = "v1_sha256_72e0c1a7507733157f93e2bff82e6ec10d50986020eeeb27a02aba5cd8c78a81"
        version = "1.0"
        date = "2023-04-11"
        modified = "2024-08-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Infostealer.MdQueryPassw"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $string1 = /kMDItemTextContent\s{1,50}==\s{1,50}\S{1,50}passw/ ascii wide nocase
        $string2 = /kMDItemDisplayName\s{1,50}==\s{1,50}\S{1,50}passw\S{1,50}/ ascii wide nocase
    condition:
        any of ($string1, $string2)
}

