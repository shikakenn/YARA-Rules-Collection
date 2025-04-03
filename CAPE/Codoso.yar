rule Codoso
{
    meta:
        id = "7h4IBF1Ez251N6PYNWcf2T"
        fingerprint = "v1_sha256_32c9ed2ac29e8905266977a9ee573a252442d96fb9ec97d88642180deceec3f8"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Codoso Payload"
        category = "INFO"
        cape_type = "Codoso Payload"

    strings:
        $a1 = "WHO_A_R_E_YOU?"
        $a2 = "DUDE_AM_I_SHARP-3.14159265358979"
        $a3 = "USERMODECMD"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
