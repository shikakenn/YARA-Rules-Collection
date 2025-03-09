/* Disabled due to Benjamin Delphys sig overlap
rule LSASS_memory_dump_file {
    meta:
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-Rules-Collection"
        category = "INFO"
        description = "Detects a LSASS memory dump file"
        author = "Florian Roth"
        date = "2015/03/31"
        memory = 0
        score = 50
    strings:
        $s1 = "lsass.exe" ascii fullword
        $s2 = "wdigest.DLL" wide nocase
    condition:
        uint32(0) == 0x504D444D and all of them
} */

rule NTLM_Dump_Output {
    meta:
        id = "6oxK7hZDkmerDsnl9oI4m2"
        fingerprint = "v1_sha256_154de926d27d38b38a4ed2c14b9122213fd1deb4115ef3bb77366db0818c7572"
        version = "1.0"
        score = 75
        date = "2015-10-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "NTML Hash Dump output file - John/LC format"
        category = "INFO"

    strings:
        $s0 = "500:AAD3B435B51404EEAAD3B435B51404EE:" ascii
        $s1 = "500:aad3b435b51404eeaad3b435b51404ee:" ascii
    condition:
        1 of them
}
