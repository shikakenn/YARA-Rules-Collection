rule Zegost : Trojan
{
    meta:
        id = "57roojK0YlgPvtRPxVh4Ld"
        fingerprint = "v1_sha256_5af6561444b7663fbde82d3cbfc6f8f9da52c11a5b90a032d3b81ad4a6a352a7"
        version = "1.0"
        date = "10/06/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Zegost Trojan"
        category = "INFO"

    strings:
        $signature1={39 2F 66 33 30 4C 69 35 75 62 4F 35 44 4E 41 44 44 78 47 38 73 37 36 32 74 71 59 3D}
        $signature2={00 BA DA 22 51 42 6F 6D 65 00}
        
    condition:
        $signature1 and $signature2
}
