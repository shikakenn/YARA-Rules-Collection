/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-08-04
    Identifier: Terracotta APT
    Comment: Reduced Rule Set
*/

/* Rule Set ----------------------------------------------------------------- */

rule Apolmy_Privesc_Trojan {
    meta:
        id = "Z3UhLheJs7gtfk4w7ErTV"
        fingerprint = "v1_sha256_8cce828806d5829735d6ac8d28a48c9b016b96b4370b2f3ac139799a9fe13c4a"
        version = "1.0"
        score = 80
        date = "2015-08-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Apolmy Privilege Escalation Trojan used in APT Terracotta"
        category = "INFO"
        reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
        hash = "d7bd289e6cee228eb46a1be1fcdc3a2bd5251bc1eafb59f8111756777d8f373d"

    strings:
        $s1 = "[%d] Failed, %08X" fullword ascii
        $s2 = "[%d] Offset can not fetched." fullword ascii
        $s3 = "PowerShadow2011" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Mithozhan_Trojan {
    meta:
        id = "3Mevqf284gpTQO5jNS47qE"
        fingerprint = "v1_sha256_a7beb030368cc6e1119617991b68e6fa1bf2d1f6eee28e83fef7862313f19d30"
        version = "1.0"
        score = 70
        date = "2015-08-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Mitozhan Trojan used in APT Terracotta"
        category = "INFO"
        reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
        hash = "8553b945e2d4b9f45c438797d6b5e73cfe2899af1f9fd87593af4fd7fb51794a"

    strings:
        $s1 = "adbrowser" fullword wide 
        $s2 = "IJKLlGdmaWhram0vn36BgIOChYR3L45xcHNydXQvhmloa2ptbH8voYCDTw==" fullword ascii
        $s3 = "EFGHlGdmaWhrL41sf36BgIOCL6R3dk8=" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule RemoteExec_Tool {
    meta:
        id = "1kLmFvmbDqtFIeRdEURxn3"
        fingerprint = "v1_sha256_951cc65e14c2ff035ccc06d080730b1c25208caa1d30129074a6150557a5cebe"
        version = "1.0"
        date = "2015-08-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Remote Access Tool used in APT Terracotta"
        category = "INFO"
        reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
        hash = "a550131e106ff3c703666f15d55d9bc8c816d1cb9ac1b73c2e29f8aa01e53b78"

    strings:
        $s0 = "cmd.exe /q /c \"%s\"" fullword ascii 
        $s1 = "\\\\.\\pipe\\%s%s%d" fullword ascii 
        $s2 = "This is a service executable! Couldn't start directly." fullword ascii 
        $s3 = "\\\\.\\pipe\\TermHlp_communicaton" fullword ascii 
        $s4 = "TermHlp_stdout" fullword ascii 
        $s5 = "TermHlp_stdin" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 75KB and 4 of ($s*)
}

/* Super Rules ------------------------------------------------------------- */

rule LiuDoor_Malware_1 {
    meta:
        id = "2bZKf1JlbkMUugpqzbnTqa"
        fingerprint = "v1_sha256_96562c3c8f9fe9ed09b59539ccb831374c4550b88ca2e17838dbf0776845d11e"
        version = "1.0"
        score = 70
        date = "2015-08-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Liudoor Trojan used in Terracotta APT"
        category = "INFO"
        reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
        super_rule = 1
        hash1 = "deed6e2a31349253143d4069613905e1dfc3ad4589f6987388de13e33ac187fc"
        hash2 = "4575e7fc8f156d1d499aab5064a4832953cd43795574b4c7b9165cdc92993ce5"
        hash3 = "ad1a507709c75fe93708ce9ca1227c5fefa812997ed9104ff9adfec62a3ec2bb"

    strings:
        $s1 = "svchostdllserver.dll" fullword ascii 
        $s2 = "SvcHostDLL: RegisterServiceCtrlHandler %S failed" fullword ascii 
        $s3 = "\\nbtstat.exe" fullword ascii
        $s4 = "DataVersionEx" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule LiuDoor_Malware_2 {
    meta:
        id = "7bqzcyU669lTj9DNuzELtm"
        fingerprint = "v1_sha256_12cc72fb147f2d580f9f9e2a9bdfbec3f7b0e977871a27ccc941cd0b1aaa634c"
        version = "1.0"
        score = 70
        date = "2015-08-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Liudoor Trojan used in Terracotta APT"
        category = "INFO"
        reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
        super_rule = 1
        hash1 = "f3fb68b21490ded2ae7327271d3412fbbf9d705c8003a195a705c47c98b43800"
        hash2 = "e42b8385e1aecd89a94a740a2c7cd5ef157b091fabd52cd6f86e47534ca2863e"

    strings:
        $s0 = "svchostdllserver.dll" fullword ascii 
        $s1 = "Lpykh~mzCCRv|mplpykCCHvq{phlCC\\jmmzqkIzmlvpqCC" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and all of them
}
