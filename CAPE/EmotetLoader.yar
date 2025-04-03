rule EmotetLoader
{
    meta:
        id = "6iyP5R4thFfvtg04H14yZm"
        fingerprint = "v1_sha256_410872d25ed3a89a2cba108f952d606cd1c3bf9ccc89ae6ab3377b83665c2773"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Emotet Loader"
        category = "INFO"
        cape_type = "EmotetLoader Payload"

    strings:
        $antihook = {8B 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 95 28 FF FF FF A1 ?? ?? ?? ?? 2D 4D 01 00 00 A3 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 3B 0D ?? ?? ?? ?? 76 26 8B 95 18 FF FF FF 8B 42 38}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and any of them
}
