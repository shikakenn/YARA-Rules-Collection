/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-06-10
    Identifier: SharpCat
*/

rule SharpCat {
    meta:
        id = "jJjuKV0ixu8VBGWacV8Jp"
        fingerprint = "v1_sha256_4a38812b07b40bdde03049dbff1f9de38cadaf9941ab8b40b84016b1d5cbfd51"
        version = "1.0"
        date = "2016-06-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects command shell SharpCat - file SharpCat.exe"
        category = "INFO"
        reference = "https://github.com/Cn33liz/SharpCat"
        hash1 = "96dcdf68b06c3609f486f9d560661f4fec9fe329e78bd300ad3e2a9f07e332e9"

    strings:
        $x1 = "ShellZz" fullword ascii
        $s2 = "C:\\Windows\\System32\\cmd.exe" fullword wide
        $s3 = "currentDirectory" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 20KB and all of them
}
