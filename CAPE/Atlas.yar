rule Atlas
{
    meta:
        id = "2bKaJvsva7C6G0BaMsIcQd"
        fingerprint = "v1_sha256_c3f73b29df5caf804dbfe3e6ac07a9e2c772bd2a126f0487e4a65e72bd501e6e"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Atlas Payload"
        category = "INFO"
        cape_type = "Atlas Payload"

    strings:
        $a1 = "bye.bat"
        $a2 = "task=knock&id=%s&ver=%s x%s&disks=%s&other=%s&ip=%s&pub="
        $a3 = "process call create \"cmd /c start vssadmin delete shadows /all /q"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
