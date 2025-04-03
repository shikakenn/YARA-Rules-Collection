rule SquirrelWaffle
{
    meta:
        id = "7eTAokcLB5z1tdpfjRz18D"
        fingerprint = "v1_sha256_5f799333398421d537ec7a87ca94f6cc9cf1e53e55b353036a5132440990e500"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly & R3MRUM"
        description = "NA"
        category = "INFO"
        cape_type = "SquirrelWaffle Payload"

    strings:
        $code = {8D 45 ?? C6 45 ?? 00 0F 43 4D ?? 83 7D ?? 10 0F 43 45 ?? 8A 04 10 32 04 39 8D 4D ?? 0F B6 C0 50 6A 01 E8 [4] C6 45}
        $decode = {F7 75 ?? 83 7D ?? 10 8D 4D ?? 8D 45 ?? C6 45 ?? 00 0F 43 4D ?? 83 7D ?? 10 0F 43 45 ?? 8A 04 10 32 04 39}
    condition:
        uint16(0) == 0x5A4D and all of them
}
