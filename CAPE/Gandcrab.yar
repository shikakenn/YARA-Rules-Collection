rule Gandcrab
{
    meta:
        id = "1Dhu14gy66j5lOrnfp8OYd"
        fingerprint = "v1_sha256_354ed566dbafbe8e9531bb771d9846952eb8c0e70ee94c26d09368159ce4142c"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Gandcrab Payload"
        category = "INFO"
        cape_type = "Gandcrab Payload"

    strings:
        $string1 = "GDCB-DECRYPT.txt" wide
        $string2 = "GandCrabGandCrabnomoreransom.coinomoreransom.bit"
        $string3 = "action=result&e_files=%d&e_size=%I64u&e_time=%d&" wide
        $string4 = "KRAB-DECRYPT.txt" wide
    condition:
        uint16(0) == 0x5A4D and any of ($string*)
}
