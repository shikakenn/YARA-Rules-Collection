rule Nemty
{
    meta:
        id = "162oKD3JcbivoMIbkqe7v5"
        fingerprint = "v1_sha256_a05974b561c67b4f1e0812639b74831edcf65686a06c0d380f0b45739e342419"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Nemty Ransomware Payload"
        category = "INFO"
        cape_type = "Nemty Payload"

    strings:
        $tordir = "TorDir"
        $decrypt = "DECRYPT.txt"
        $nemty = "NEMTY"
    condition:
        uint16(0) == 0x5A4D and all of them
}
