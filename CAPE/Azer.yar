rule Azer
{
    meta:
        id = "8HqyZ73yuWQTHxadalxBC"
        fingerprint = "v1_sha256_48bd4a4e071f10d1911c4173a0cd39c69fed7a3b29eb92beffe709899f4cefa5"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Azer Payload"
        category = "INFO"
        cape_type = "Azer Payload"

    strings:
        $a1 = "webmafia@asia.com" wide
        $a2 = "INTERESTING_INFORMACION_FOR_DECRYPT.TXT" wide
        $a3 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"  //-----BEGIN PUBLIC KEY-----
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
