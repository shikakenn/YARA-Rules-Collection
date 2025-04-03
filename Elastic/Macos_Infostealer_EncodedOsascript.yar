rule Macos_Infostealer_EncodedOsascript_eeb54a7e {
    meta:
        id = "2gydqbX2sqRMyThGbBxVIU"
        fingerprint = "v1_sha256_dcc10a407465d4f7ceb52570de48f438c08eef798bffb644725d337574263cfd"
        version = "1.0"
        date = "2024-08-19"
        modified = "2024-08-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Macos.Infostealer.EncodedOsascript"
        reference_sample = "c1693ee747e31541919f84dfa89e36ca5b74074044b181656d95d7f40af34a05"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $xor_encoded_osascript = "osascript" xor(64)
        $base32_encoded_osascript = { 4E 35 5A 57 43 34 33 44 4F 4A 55 58 41 35 }
        $hex_encoded_osascript = "6f7361736372697074" ascii wide nocase
    condition:
        any of them
}

