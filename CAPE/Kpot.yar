rule Kpot
{
    meta:
        id = "5mScx52O8FbslFpWRJQ2YN"
        fingerprint = "v1_sha256_75abaab9a10e8ac8808425c389238285ab9bd9cb76f0cd03cc1e35b3ea0a1b0f"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Kpot Stealer"
        category = "INFO"
        cape_type = "Kpot Payload"

    strings:
        $format   = "%s | %s | %s | %s | %s | %s | %s | %d | %s"
        $username = "username:s:"
        $os       = "OS: %S x%d"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
