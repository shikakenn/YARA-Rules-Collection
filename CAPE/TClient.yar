rule TClient
{
    meta:
        id = "3wqdAePxxP6xsbzCCjjL1V"
        fingerprint = "v1_sha256_6edcd01e4722b367723ed77d9596877d16ee35dc4c160885d125f83e45cee24d"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "TClient Payload"
        category = "INFO"
        cape_type = "TClient Payload"

    strings:
        $code1 = {41 0F B6 00 4D 8D 40 01 34 01 8B D7 83 E2 07 0F BE C8 FF C7 41 0F BE 04 91 0F AF C1 41 88 40 FF 81 FF 80 03 00 00 7C D8}
    condition:
        uint16(0) == 0x5A4D and any of ($code*)
}
