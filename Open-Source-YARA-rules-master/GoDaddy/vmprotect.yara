
rule vmprotect {
    meta:
        id = "2pvA9HTi6SUekOz3swSrrF"
        fingerprint = "v1_sha256_6d89a33ea18b13191fa49b232ba8277fabda0e896667f972ed75be0e4d4be3f1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "VMProtect packed file"
        category = "INFO"
        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $vmp0 = {2E766D7030000000}
        $vmp1 = {2E766D7031000000}

    condition:
        $mz at 0 and $vmp0 in (0x100..0x300) and $vmp1 in (0x100..0x300)
}

