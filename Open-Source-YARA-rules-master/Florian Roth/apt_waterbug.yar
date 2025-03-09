/* WATERBUG ----------------------------------------------------------------- */

rule WaterBug_wipbot_2013_core_PDF {
    meta:
        id = "6OCPPULOn7KaZSDtlEvvuk"
        fingerprint = "v1_sha256_83aa8cbf5ebee56dea7a6816f112c3a91826d86ce2287adcbceb60f60a87bd35"
        version = "1.0"
        date = "22.01.2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Symantec Security Response"
        description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 core PDF"
        category = "INFO"
        reference = "http://t.co/rF35OaAXrl"

    strings:
        $PDF = "%PDF-"
        $a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/ 
        $b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/
    condition:
        ($PDF at 0) and #a > 150 and #b > 200
}

rule WaterBug_wipbot_2013_dll {
    meta:
        id = "5IoSBuAC5Tiq1ApZLBSjuC"
        fingerprint = "v1_sha256_f29ff81d62bd6bea776aeddc0725b034624f836c234441f63a8b697e959d3f8d"
        version = "1.0"
        date = "22.01.2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Symantec Security Response"
        description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 Down.dll component"
        category = "INFO"
        reference = "http://t.co/rF35OaAXrl"

    strings:
        $string1 = "/%s?rank=%s"
        $string2 = "ModuleStart\x00ModuleStop\x00start"
        $string3 = "1156fd22-3443-4344-c4ffff"
        //read file... error..
        $string4 = "read\x20file\x2E\x2E\x2E\x20error\x00\x00"
    condition:
        2 of them
}

rule WaterBug_wipbot_2013_core {
    meta:
        id = "7m0SIheNbduF5SLJCtrPu3"
        fingerprint = "v1_sha256_f8197bd4bb7aee105ff7a2108b7c17186660369a6ae6e5ea0dd7397e816826ed"
        version = "1.0"
        date = "22.01.2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Symantec Security Response"
        description = "Symantec Waterbug Attack - Trojan.Wipbot core + core; garbage appended data (PDF Exploit leftovers) + wipbot dropper; fake AdobeRd32 Error"
        category = "INFO"
        reference = "http://t.co/rF35OaAXrl"

    strings:
        $mz = "MZ"
        $code1 = { 89 47 0C C7 47 10 90 C2 04 00 C7 47 14 90 C2 10 00 C7 47 18 90 90 60 68 89 4F 1C C7 47 20 90 90 90 B8 89 4F 24 C7 47 28 90 FF D0 61 C7 47 2C 90 C2 04 00}
        $code2 = { 85 C0 75 25 8B 0B BF ?? ?? ?? ?? EB 17 69 D7 0D 66 19 00 8D BA 5F F3 6E 3C 89 FE C1 EE 10 89 F2 30 14 01 40 3B 43 04 72 E4}
        $code3 = {90 90 90 ?? B9 00 4D 5A 90 00 03 00 00 00 82 04} $code4 = {55 89 E5 5D C3 55 89 E5 83 EC 18 8B 45 08 85 C0}
    condition:
        $mz at 0 and (($code1 or $code2) or ($code3 and $code4))
}

rule WaterBug_turla_dropper {
    meta:
        id = "5OltIsAkuoHlIJo7O790U4"
        fingerprint = "v1_sha256_6836b8d28fb41d9459f24d22e3c428b022b26885b7dce1caa5b0d5a7a1b7f82b"
        version = "1.0"
        date = "22.01.2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Symantec Security Response"
        description = "Symantec Waterbug Attack - Trojan Turla Dropper"
        category = "INFO"
        reference = "http://t.co/rF35OaAXrl"

    strings: 
        $a = {0F 31 14 31 20 31 3C 31 85 31 8C 31 A8 31 B1 31 D1 31 8B 32 91 32 B6 32 C4 32 6C 33 AC 33 10 34}
        $b = {48 41 4C 2E 64 6C 6C 00 6E 74 64 6C 6C 00 00 00 57 8B F9 8B 0D ?? ?? ?? ?? ?? C9 75 26 56 0F 20 C6 8B C6 25 FF FF FE FF 0F 22 C0 E8}
    condition: 
        all of them
}

rule WaterBug_fa_malware { 
    meta:
        id = "6OJ2LJYUctOmmu1fyffiPp"
        fingerprint = "v1_sha256_9fc53718179af865128048bef0f33244de2fd77eeeeacf4bf64e91f23f4e03c1"
        version = "1.0"
        date = "22.01.2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Symantec Security Response"
        description = "Symantec Waterbug Attack - FA malware variant"
        category = "INFO"
        reference = "http://t.co/rF35OaAXrl"

    strings:
        $mz = "MZ"
        $string1 = "C:\\proj\\drivers\\fa _ 2009\\objfre\\i386\\atmarpd.pdb"
        $string2 = "d:\\proj\\cn\\fa64\\"
        $string3 = "sengoku_Win32.sys\x00"
        $string4 = "rk_ntsystem.c"
        $string5 = "\\uroboros\\"
        $string6 = "shell.{F21EDC09-85D3-4eb9-915F-1AFA2FF28153}"
    condition:
        ($mz at 0) and (any of ($string*))
}

/* pe module memory leak problem


rule WaterBug_turla_dll {
    meta: 
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-Rules-Collection"
        category = "INFO"
        description = "Symantec Waterbug Attack - Trojan Turla DLL"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl"	
    strings:
        $a = /([A-Za-z0-9]{2,10}_){,2}Win32\.dll\x00/
    condition:
        pe.exports("ee") and $a
}

rule WaterBug_sav_dropper {
    meta: 
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-Rules-Collection"
        category = "INFO"
        description = "Symantec Waterbug Attack - SAV Dropper"
        author = "Symantec Security Response"
        date = "22.01.2015"
        reference = "http://t.co/rF35OaAXrl" 
    strings:
        $mz = "MZ"
        $a = /[a-z]{,10}_x64.sys\x00hMZ\x00/
    condition:
        ($mz at 0) and uint32(0x400) == 0x000000c3 and pe.number_of_sections == 6 and $a 
}

*/ 

rule WaterBug_sav {
    meta:
        id = "C6pakieUJmhbPMOEYHWMf"
        fingerprint = "v1_sha256_829d3f1563d65d4801b1290f6d972cf3d322789e166c8f6fc4a11e562b774d88"
        version = "1.0"
        date = "22.01.2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Symantec Security Response"
        description = "Symantec Waterbug Attack - SAV Malware"
        category = "INFO"
        reference = "http://t.co/rF35OaAXrl"

    strings:
        $mz = "MZ"
        $code1a = { 8B 75 18 31 34 81 40 3B C2 72 F5 33 F6 39 7D 14 76 1B 8A 04 0E 88 04 0F 6A 0F 33 D2 8B C7 5B F7 F3 85 D2 75 01 }
        $code1b = { 8B 45 F8 40 89 45 F8 8B 45 10 C1 E8 02 39 45 F8 73 17 8B 45 F8 8B 4D F4 8B 04 81 33 45 20 8B 4D F8 8B 55 F4 89 04 8A EB D7 83 65 F8 00 83 65 EC 00 EB 0E 8B 45 F8 40 89 45 F8 8B 45 EC 40 89 45 EC 8B 45 EC	3B 45 10 73 27 8B 45 F4 03 45 F8 8B 4D F4 03 4D EC 8A 09 88 08 8B 45 F8 33 D2 6A 0F 59 F7 F1 85 D2 75 07 }
        $code1c = { 8A 04 0F 88 04 0E 6A 0F 33 D2 8B C6 5B F7 F3 85 D2 75 01 47 8B 45 14 46 47 3B F8 72 E3 EB 04 C6 04 08 00 48 3B C6 73 F7 33 C0 C1 EE 02 74 0B 8B 55 18 31 14 81 40 3B C6 72 F5 }
        $code2 =  { 29 5D 0C 8B D1 C1 EA 05 2B CA 8B 55 F4 2B C3 3D 00 00 00 01 89 0F 8B 4D 10 8D 94 91 00 03 00 00 73 17 8B 7D F8 8B 4D 0C 0F B6 3F C1 E1 08 0B CF C1 E0 08 FF 45 F8 89 4D 0C 8B 0A 8B F8 C1 EF 0B}
    condition:
        ($mz at 0) and (($code1a or $code1b or $code1c) and $code2) 
}
