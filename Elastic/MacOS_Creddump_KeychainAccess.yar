rule MacOS_Creddump_KeychainAccess_535c1511 {
    meta:
        id = "1lhVq5apICEA8OdL5BDsEH"
        fingerprint = "v1_sha256_c2995263622d62b11db93f7d163a7595e316ec24b51099f434bc5dbd0afefbfe"
        version = "1.0"
        date = "2023-04-11"
        modified = "2024-08-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Macos.Creddump.KeychainAccess"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $strings1 = "uploadkeychain" ascii wide nocase
        $strings2 = "decryptkeychain" ascii wide nocase
        $strings3 = "dump-generic-password" ascii wide nocase
        $strings4 = "keychain_extract" ascii wide nocase
        $strings5 = "chainbreaker" ascii wide nocase
        $strings6 = "SecKeychainItemCopyContent" ascii wide nocase
        $strings7 = "SecKeychainItemCopyAccess" ascii wide nocase
        $strings8 = "Failed to get password" ascii wide nocase
    condition:
        all of ($strings1, $strings2) or $strings4 or all of ($strings3, $strings5) or all of ($strings6, $strings7, $strings8)
}

