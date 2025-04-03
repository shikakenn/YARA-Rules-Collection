rule Mole
{
    meta:
        id = "2rGhorBHhnv987RWE0X1wP"
        fingerprint = "v1_sha256_8be4d190d554a610360c0e04b33da59eb00319395e5b2000d580546ce6503786"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Mole Payload"
        category = "INFO"
        cape_type = "Mole Payload"

    strings:
        $a1 = ".mole0" wide
        $a2 = "_HELP_INSTRUCTION.TXT" wide
        $a3 = "-----BEGIN PUBLIC KEY----- MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
