rule Wabot : Worm
{
    meta:
        id = "pzIOK4UnUofcAMVepZGWJ"
        fingerprint = "v1_sha256_5374d73e6c255ce7cbb751e5cf811806f14aa45bdc4560fdb2a0715df91dddab"
        version = "1.0"
        date = "14/08/2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Wabot Trojan Worm"
        category = "INFO"

    strings:
        $signature1={43 3A 5C 6D 61 72 69 6A 75 61 6E 61 2E 74 78 74}
        $signature2={73 49 52 43 34}

    condition:
        $signature1 and $signature2
}
