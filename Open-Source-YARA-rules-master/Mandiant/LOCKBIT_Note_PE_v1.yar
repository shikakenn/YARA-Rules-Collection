rule LOCKBIT_Note_PE_v1

{
    meta:
        id = "7ENN9fh4784Q3VghG4aM4B"
        fingerprint = "v1_sha256_0e7a5d2754e08b19408a04cea54fcb61b0d4488b7ec78ae35b73c6fc7d33a138"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://www.mandiant.com/resources/unc2165-shifts-to-evade-sanctions"

    strings:

 

        $onion = /http:\/\/lockbit[a-z0-9]{9,49}.onion/ ascii wide

        $note1 = "restore-my-files.txt" nocase ascii wide

        $note2 = /lockbit[_-](ransomware|note)\.hta/ nocase ascii wide

        $v2 = "LockBit_2_0_Ransom" nocase wide

 

    condition:

 

        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)

        and $onion

        and (all of ($note*)) and not $v2
}


