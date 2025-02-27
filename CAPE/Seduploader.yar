rule Seduploader
{
    meta:
        id = "38KGqcjjZ21PIHD5ptuwCw"
        fingerprint = "v1_sha256_d70c886699169d4dafc5b063c93682a34af5667df6d293b52256ddc19ab9c516"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Seduploader decrypt function"
        category = "INFO"
        cape_type = "Seduploader Payload"

    strings:
        $decrypt1 = {8D 0C 30 C7 45 FC 0A 00 00 00 33 D2 F7 75 FC 8A 82 ?? ?? ?? ?? 32 04 0F 88 01 8B 45 0C 40 89 45 0C 3B C3 7C DB}
    condition:
        uint16(0) == 0x5A4D and any of ($decrypt*)
}
