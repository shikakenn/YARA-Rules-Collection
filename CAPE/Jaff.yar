rule Jaff
{
    meta:
        id = "2ZshA6blX25Vqu5FSgMGRs"
        fingerprint = "v1_sha256_6806a5eeee04b7436ff694addc334bfc0f1ee611116904d57be9506acfd47418"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Jaff Payload"
        category = "INFO"
        cape_type = "Jaff Payload"

    strings:
        $a1 = "CryptGenKey"
        $a2 = "353260540318613681395633061841341670181307185694827316660016508"
        $b1 = "jaff"
        $b2 = "2~1c0q4t7"
    condition:
        uint16(0) == 0x5A4D and (any of ($a*) ) and (1 of ($b*))
}
