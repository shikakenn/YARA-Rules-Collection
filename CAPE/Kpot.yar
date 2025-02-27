rule Kpot
{
    meta:
        id = "6631oDAMdLz2kYfL4nawac"
        fingerprint = "v1_sha256_75abaab9a10e8ac8808425c389238285ab9bd9cb76f0cd03cc1e35b3ea0a1b0f"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
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
