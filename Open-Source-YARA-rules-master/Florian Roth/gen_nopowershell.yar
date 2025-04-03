/*
    Yara Rule Set
    Author: YarGen Rule Generator
    Date: 2016-05-21
    Identifier: No PowerShell
*/

rule No_PowerShell {
    meta:
        id = "3xKYSUDvlPNTXRKUIdbdEU"
        fingerprint = "v1_sha256_9fba467cfbf8cad0c8e6cf1e1c7eacd8b0be869ebe6c5180f50f5cdefa8b5bb5"
        version = "1.0"
        score = 80
        date = "2016-05-21"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects an C# executable used to circumvent PowerShell detection - file nps.exe"
        category = "INFO"
        reference = "https://github.com/Ben0xA/nps"
        hash1 = "64f811b99eb4ae038c88c67ee0dc9b150445e68a2eb35ff1a0296533ae2edd71"

    strings:
        $s1 = "nps.exe -encodedcommand {base64_encoded_command}" fullword wide
        $s2 = "c:\\Development\\ghps\\nps\\nps\\obj\\x86\\Release\\nps.pdb" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 40KB and ( 1 of ($s*) ) ) or ( all of them )
}
