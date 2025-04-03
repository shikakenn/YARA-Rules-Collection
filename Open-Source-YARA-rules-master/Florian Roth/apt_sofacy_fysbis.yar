
/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-02-13
    Identifier: Sofacy Fysbis
*/

rule Sofacy_Fybis_ELF_Backdoor_Gen1 {
    meta:
        id = "PjrcdVF1C7fdb4Q0ukpeL"
        fingerprint = "v1_sha256_7f9f0bc49944f11f7b4b54c829c583ca5904a41f4b414ad062e708e2363c566b"
        version = "1.0"
        score = 80
        date = "2016-02-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Sofacy Fysbis Linux Backdoor_Naikon_APT_Sample1"
        category = "INFO"
        reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
        hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
        hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"

    strings:
        $x1 = "Your command not writed to pipe" fullword ascii
        $x2 = "Terminal don`t started for executing command" fullword ascii
        $x3 = "Command will have end with \\n" fullword ascii

        $s1 = "WantedBy=multi-user.target' >> /usr/lib/systemd/system/" fullword ascii
        $s2 = "Success execute command or long for waiting executing your command" fullword ascii
        $s3 = "ls /etc | egrep -e\"fedora*|debian*|gentoo*|mandriva*|mandrake*|meego*|redhat*|lsb-*|sun-*|SUSE*|release\"" fullword ascii
        $s4 = "rm -f /usr/lib/systemd/system/" fullword ascii
        $s5 = "ExecStart=" fullword ascii
        $s6 = "<table><caption><font size=4 color=red>TABLE EXECUTE FILES</font></caption>" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 500KB and 1 of ($x*) ) or
        ( 1 of ($x*) and 3 of ($s*) )
}

rule Sofacy_Fysbis_ELF_Backdoor_Gen2 {
    meta:
        id = "4EQMpvzKK7Dd7pKNSxP5Hq"
        fingerprint = "v1_sha256_1d50a789e9c43fce27f3ad390cbdd9533c61e4f263cec1aa1abfba6545e55c57"
        version = "1.0"
        score = 80
        date = "2016-02-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Sofacy Fysbis Linux Backdoor"
        category = "INFO"
        reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
        hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
        hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
        hash3 = "fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61"

    strings:
        $s1 = "RemoteShell" ascii
        $s2 = "basic_string::_M_replace_dispatch" fullword ascii
        $s3 = "HttpChannel" ascii
    condition:
        uint16(0) == 0x457f and filesize < 500KB and all of them
}
