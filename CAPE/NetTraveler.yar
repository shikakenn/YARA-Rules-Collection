rule NetTraveler
{
    meta:
        id = "tjt0cAFK1FFQRnX2OJ0nC"
        fingerprint = "v1_sha256_bf5026f1a1cb3d6986a29d22657a9f1904b362391a6715d7468f8f8aca351233"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "NetTraveler Payload"
        category = "INFO"
        cape_type = "NetTraveler Payload"

    strings:
        $string1 = {4E 61 6D 65 3A 09 25 73 0D 0A 54 79 70 65 3A 09 25 73 0D 0A 53 65 72 76 65 72 3A 09 25 73 0D 0A} // "Name: %s  Type: %s  Server: %s "
        $string2 = "Password Expiried Time:"
        $string3 = "Memory: Total:%dMB,Left:%dMB (for %.2f%s)"

    condition:
        uint16(0) == 0x5A4D and all of them
}
