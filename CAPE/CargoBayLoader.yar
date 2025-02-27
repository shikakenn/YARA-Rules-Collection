rule CargoBayLoader
{
    meta:
        id = "1HkceLzclRrxCj24UJhdsH"
        fingerprint = "v1_sha256_1d5c4ca79f97e1fac358189a8c6530be12506974fc2fb42f63b0b621536a45c9"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "CargoBay Loader"
        category = "INFO"
        hash = "75e975031371741498c5ba310882258c23b39310bd258239277708382bdbee9c"
        cape_type = "CargoBay Loader"

    strings:
        $jmp1 = {40 42 0F 00 0F 82 [2] 00 00 48 8D 15 [4] BF 04 00 00 00 41 B8 04 00 00 00 4C 8D [3] 4C 89 F1 E8}
        $jmp2 = {84 DB 0F 85 [2] 00 00 48 8D 15 [4] 41 BE 03 00 00 00 41 B8 03 00 00 00 4C 8D 7C [2] 4C 89 F9 E8}
    condition:
        uint16(0) == 0x5A4D and all of them
}
