rule Kronos
{
    meta:
        id = "5wM2lOoXzgv8uJrBwUzzM2"
        fingerprint = "v1_sha256_52ce9caf3627efe8ae86df6ca59e51e9f738e13ac0265f797e8d70123dbcaeb3"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Kronos Payload"
        category = "INFO"
        cape_type = "Kronos Payload"

    strings:
        $a1 = "user_pref(\"network.cookie.cookieBehavior\""
        $a2 = "T0E0H4U0X3A3D4D8"
        $a3 = "wow64cpu.dll" wide
        $a4 = "Kronos" fullword ascii wide
    condition:
        uint16(0) == 0x5A4D and (2 of ($a*))
}
