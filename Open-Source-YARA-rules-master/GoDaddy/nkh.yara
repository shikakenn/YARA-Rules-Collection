
rule nkh_packer {
    meta:
        id = "gf75ThUIBO4EXBfDg7mq7"
        fingerprint = "v1_sha256_1a34b60e43807587d1a1d97c90569e16658969e2468c9acde5f6d0f4e1827eea"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        block = false
        quarantine = false

    strings:
        // payload is xor compressed in the overlay with a 4-byte xor key
        $nkh_section = ".nkh_\x00\x00\x00\x00\x10\x00\x00"

    condition:
        IsPeFile and $nkh_section in (0..0x400)
}

