rule NanoLocker
{
    meta:
        id = "3Lr2YWknD8UljGjD2O2eVW"
        fingerprint = "v1_sha256_fe6c8a4e259c3c526f8f50771251f6762b2b92a4df2e8bfc705f282489f757db"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "NanoLocker Payload"
        category = "INFO"
        cape_type = "NanoLocker Payload"

    strings:
        $a1 = "NanoLocker"
        $a2 = "$humanDeadline"
        $a3 = "Decryptor.lnk"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
