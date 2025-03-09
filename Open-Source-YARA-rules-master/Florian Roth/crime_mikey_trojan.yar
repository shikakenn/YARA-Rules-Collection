
rule Gen_Trojan_Mikey {
    meta:
        id = "QKY4KXUB44vpRR8Ku5xL9"
        fingerprint = "v1_sha256_5454953bba09d6fc866bcb23ef81a0b6763d8f82b8b606597548cbb5cf6053ed"
        version = "1.0"
        score = 70
        date = "2015-05-07"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Trojan Mikey - file sample_mikey.exe"
        category = "INFO"
        hash = "a8e6c3ca056b3ff2495d7728654b780735b3a4cb"

    strings:
        $s0 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" fullword ascii 
                        /* reversed string 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' */
        $x1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
        $x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.00; Windows NT 5.0; MyIE 3.01)" fullword ascii
        $x3 = "%d*%u%s" fullword ascii
        $x4 = "%s %s:%d" fullword ascii
        $x5 = "Mnopqrst Vwxyabcde Ghijklm Opqrstuv Xya" fullword ascii
    condition:
        uint16(0) == 0x5a4d and $s0 and 2 of ($x*)
}

