rule LOCKBIT_Note_PE_v2

{
    meta:
        id = "1GHS1Zf1G87Gfj6GZRoEGi"
        fingerprint = "v1_sha256_cce0d3539c8c6e73004f81727f37cf76e0453cdef0ed13c00e67aac8a6c87881"
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

 

        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them

}


