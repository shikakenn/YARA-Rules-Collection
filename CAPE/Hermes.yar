rule Hermes
{
    meta:
        id = "6tWkT7ksVHyIGdYGh28J6s"
        fingerprint = "v1_sha256_9bc974173f39a57e7adfbf8ae106a20d960557696b4c3ce16e9b4e47d3e9e95b"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Hermes Payload"
        category = "INFO"
        cape_type = "Hermes Payload"

    strings:
        $ext = ".HRM" wide
        $vss = "vssadmin Delete"
        $email = "supportdecrypt@firemail.cc" wide
    condition:
        uint16(0) == 0x5A4D and all of ($*)
}
