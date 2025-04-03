rule WanaCry
{
    meta:
        id = "2KqGoBwkXvt7qixxwfN8Hq"
        fingerprint = "v1_sha256_16d5e39f043d27bbf22f8f21e13971b7e0709b07e44746dd157d11ee4cc51944"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "WanaCry Payload"
        category = "INFO"
        cape_type = "WanaCry Payload"

    strings:
        $exename    = "@WanaDecryptor@.exe"
        $res        = "%08X.res"
        $pky        = "%08X.pky"
        $eky        = "%08X.eky"
        $taskstart  = {8B 35 58 71 00 10 53 68 C0 D8 00 10 68 F0 DC 00 10 FF D6 83 C4 0C 53 68 B4 D8 00 10 68 24 DD 00 10 FF D6 83 C4 0C 53 68 A8 D8 00 10 68 58 DD 00 10 FF D6 53}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}
