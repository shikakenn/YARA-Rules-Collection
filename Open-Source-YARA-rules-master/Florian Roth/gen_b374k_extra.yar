/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-08-18
    Identifier: b374k - Back Connect Payload UPX
*/

rule b374k_back_connect {
    meta:
        id = "63lFY0evopi56cIKQKf3Ke"
        fingerprint = "v1_sha256_dd89aefb6c1add44bfe2a706cd161a16f36a649f910ace16b641a7836525aa73"
        version = "1.0"
        score = 80
        date = "2016-08-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects privilege escalation tool"
        category = "INFO"
        reference = "Internal Analysis"
        hash1 = "c8e16f71f90bbaaef27ccaabb226b43762ca6f7e34d7d5585ae0eb2d36a4bae5"

    strings:
        $s1 = "AddAtomACreatePro" fullword ascii
        $s2 = "shutdow" fullword ascii
        $s3 = "/config/i386" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 10KB and all of them )
}
