rule DoppelPaymer
{
    meta:
        id = "2rCuQh3pfUbBYMx9vTz4ij"
        fingerprint = "v1_sha256_73a2575671bafc31a70af3ce072d6f94ae172b12202baebba586a02524cb6f9d"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "DoppelPaymer Payload"
        category = "INFO"
        cape_type = "DoppelPaymer Payload"

    strings:
        $getproc32 = {81 FB ?? ?? ?? ?? 74 2D 8B CB E8 ?? ?? ?? ?? 85 C0 74 0C 8B C8 8B D7 E8 ?? ?? ?? ?? 5B 5F C3}
        $cmd_string = "Setup run\\n" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
