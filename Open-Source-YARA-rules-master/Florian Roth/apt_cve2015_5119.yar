
rule Flash_CVE_2015_5119_APT3 {
    meta:
        id = "1Dyfo56NBBNo7mK3hcIjkn"
        fingerprint = "v1_sha256_238c6033baa17bfb74866d478629d89ccd810945fab66650f2e00543a765c566"
        version = "1.0"
        score = 70
        date = "2015-08-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Exploit Sample CVE-2015-5119"
        category = "INFO"
        yaraexchange = "No distribution without author's consent"

    strings:
        $s0 = "HT_exploit" fullword ascii
        $s1 = "HT_Exploit" fullword ascii
        $s2 = "flash_exploit_" ascii
        $s3 = "exp1_fla/MainTimeline" ascii fullword
        $s4 = "exp2_fla/MainTimeline" ascii fullword
        $s5 = "_shellcode_32" fullword ascii
        $s6 = "todo: unknown 32-bit target" fullword ascii 
    condition:
        uint16(0) == 0x5746 and 1 of them
}
