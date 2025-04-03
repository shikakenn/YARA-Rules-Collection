rule COATHANGER_beacon
{
    meta:
        id = "rzvNa3AKt0G3CKleMXWrz"
        fingerprint = "v1_sha256_e44496e62de8c885d5bd941819a97f4c0dd90ce2d0cfe9d042ab9590cc354ddb"
        version = "1.0"
        date = "20240206"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NLD MIVD - JSCU"
        description = "Detects COATHANGER beaconing code (GET / HTTP/2\nHost: www.google.com\n\n)"
        category = "INFO"
        report = "HTTPS://WWW.NCSC.NL/DOCUMENTEN/PUBLICATIES/2024/FEBRUARI/6/MIVD-AIVD-ADVISORY-COATHANGER-TLP-CLEAR"
        malware = "COATHANGER"

    strings:
        $chunk_1 = {
            48 B8 47 45 54 20 2F 20 48 54
            48 89 45 B0
            48 B8 54 50 2F 32 0A 48 6F 73
            48 89 45 B8
            48 B8 74 3A 20 77 77 77 2E 67
            48 89 45 C0
            48 B8 6F 6F 67 6C 65 2E 63 6F
        }

    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and
        any of them
}
