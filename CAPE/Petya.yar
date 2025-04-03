rule Petya
{
    meta:
        id = "2ptZlT0uc1FILMw75FYl68"
        fingerprint = "v1_sha256_f819261bb34f3b2eb7dc2f843b56be25105570fe902a77940a632a54fbe0d014"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Petya Payload"
        category = "INFO"
        cape_type = "Petya Payload"

    strings:
        $a1 = "CHKDSK is repairing sector"
        $a2 = "wowsmith123456@posteo.net"
        $a3 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" wide
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
