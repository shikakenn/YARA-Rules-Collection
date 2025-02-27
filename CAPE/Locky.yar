rule Locky
{
    meta:
        id = "4VIRafDeZNZfLxpYuSzHQ8"
        fingerprint = "v1_sha256_9786c54a2644d9581fefe64be11b26e22806398e54e961fa4f19d26eae039cd7"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Locky Payload"
        category = "INFO"
        cape_type = "Locky Payload"

    strings:
        $string1 = "wallet.dat" wide
        $string2 = "Locky_recover" wide
        $string3 = "opt321" wide
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}
