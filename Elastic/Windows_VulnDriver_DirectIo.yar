rule Windows_VulnDriver_DirectIo_7bea6c8f {
    meta:
        id = "6PPifIv3TjSjDq4e705z9s"
        fingerprint = "v1_sha256_3b148fed9c52af1d2d1eb18b6c4b191fb80e547f2da1beccdaf3d3e0237ecc1b"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.DirectIo"
        reference_sample = "1dadd707c55413a16320dc70d2ca7784b94c6658331a753b3424ae696c5d93ea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\DirectIo.pdb"
        $str2 = { 9B 49 18 FC CD 5C EA D2 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1 and not $str2
}

rule Windows_VulnDriver_DirectIo_abe8bfa6 {
    meta:
        id = "3riNRsaHYDM8oaZT8iBcg3"
        fingerprint = "v1_sha256_5224938b0381943a171b1db00249e71c43ce2c179ef4bbe14b46cc0787e35cb2"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.DirectIo"
        reference_sample = "d84e3e250a86227c64a96f6d5ac2b447674ba93d399160850acb2339da43eae5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\DirectIo64.pdb"
        $str2 = { 9B 49 18 FC CD 5C EA D2 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1 and not $str2
}

