rule APT_Project_Sauron_Scripts {
    meta:
        id = "3KpjhR1aWCcBWxEDAObkis"
        fingerprint = "v1_sha256_5d22f0d52a0bbf2bb0bf4ea0c6fb4b5d50fbd5ee32090e93d448c3a400952007"
        version = "1.0"
        date = "2016-08-08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects scripts (mostly LUA) from Project Sauron report by Kaspersky"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"

    strings:
        $x1 = "local t = w.exec2str(\"regedit "
        $x2 = "local r = w.exec2str(\"cat"
        $x3 = "ap*.txt link*.txt node*.tun VirtualEncryptedNetwork.licence"
        $x4 = "move O FakeVirtualEncryptedNetwork.dll"
        $x5 = "sinfo | basex b 32url | dext l 30"
        $x6 = "w.exec2str(execStr)"
        $x7 = "netnfo irc | basex b 32url"
        $x8 = "w.exec(\"wfw status\")"
        $x9 = "exec(\"samdump\")"
        $x10 = "cat VirtualEncryptedNetwork.ini|grep"
        $x11 = "if string.lower(k) == \"securityproviders\" then"
        $x12 = "exec2str(\"plist b | grep netsvcs\")"
        $x13 = ".*account.*|.*acct.*|.*domain.*|.*login.*|.*member.*"
        $x14 = "SAURON_KBLOG_KEY ="
    condition:
        1 of them
}

rule APT_Project_Sauron_arping_module {
    meta:
        id = "g94zS5ej1hkK9pA5siEgz"
        fingerprint = "v1_sha256_d87e91441994c4ed863596d79c108c9f72adfb708f885cb63a881eb25aa089b7"
        version = "1.0"
        date = "2016-08-08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects strings from arping module - Project Sauron report by Kaspersky"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"

    strings:
        $s1 = "Resolve hosts that answer"
        $s2 = "Print only replying Ips"
        $s3 = "Do not display MAC addresses"
    condition:
        all of them
}

rule APT_Project_Sauron_kblogi_module {
    meta:
        id = "26WxkFQ5YOFEWzzvYiBibe"
        fingerprint = "v1_sha256_bba87b17a62fc968e89d4f6d10de06875c6b7f47c8bb7ae3f7932804b23a8e87"
        version = "1.0"
        date = "2016-08-08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects strings from kblogi module - Project Sauron report by Kaspersky"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"

    strings:
        $x1 = "Inject using process name or pid. Default"
        $s2 = "Convert mode: Read log from file and convert to text"
        $s3 = "Maximum running time in seconds"
    condition:
        $x1 or 2 of them
}

rule APT_Project_Sauron_basex_module {
    meta:
        id = "50pbEmST1vl49z5Rqutpui"
        fingerprint = "v1_sha256_90cfb58017d62312c56908aca1a48bb7425f5cd51540298ecf65305b46ffb2c8"
        version = "1.0"
        date = "2016-08-08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects strings from basex module - Project Sauron report by Kaspersky"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"

    strings:
        $x1 = "64, 64url, 32, 32url or 16."
        $s2 = "Force decoding when input is invalid/corrupt"
        $s3 = "This cruft"
    condition:
        $x1 or 2 of them
}

rule APT_Project_Sauron_dext_module {
    meta:
        id = "peAinfopIsF9G69T8ik8O"
        fingerprint = "v1_sha256_7dbfb3ddfffa6fa65800e07fdcc527650474740afa658567efe46830587cedae"
        version = "1.0"
        date = "2016-08-08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects strings from dext module - Project Sauron report by Kaspersky"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"

    strings:
        $x1 = "Assemble rows of DNS names back to a single string of data"
        $x2 = "removes checks of DNS names and lengths (during split)"
        $x3 = "Randomize data lengths (length/2 to length)"
        $x4 = "This cruft"
    condition:
        2 of them
}

rule Hacktool_This_Cruft {
    meta:
        id = "3a9HQHTX8qpJIiofPONqv2"
        fingerprint = "v1_sha256_875c34e8048c3f98afc97683d0b3086c3396753cd9fb14bc68681c63ed77fd51"
        version = "1.0"
        score = 60
        date = "2016-08-08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects string 'This cruft' often used in hack tools like netcat or cryptcat and also mentioned in Project Sauron report"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"

    strings:
        $x1 = "This cruft" fullword
    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and $x1 )
}

/*
    Yara Rule Set
    Author: FLorian Roth
    Date: 2016-08-09
    Identifier: Project Sauron - my own ruleset
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT_Project_Sauron_Custom_M1 {
    meta:
        id = "5ewDJuFDTPGMfnPxf6EYLM"
        fingerprint = "v1_sha256_c81c996e487bdd840111513724ccf1220ee3bd8280d776aa4c128ef5263ee136"
        version = "1.0"
        date = "2016-08-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FLorian Roth"
        description = "Detects malware from Project Sauron APT"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"
        hash1 = "9572624b6026311a0e122835bcd7200eca396802000d0777dba118afaaf9f2a9"

    strings:
        $s1 = "ncnfloc.dll" fullword wide
        $s4 = "Network Configuration Locator" fullword wide

        $op0 = { 80 75 6e 85 c0 79 6a 66 41 83 38 0a 75 63 0f b7 } /* Opcode */
        $op1 = { 80 75 29 85 c9 79 25 b9 01 } /* Opcode */
        $op2 = { 2b d8 48 89 7c 24 38 44 89 6c 24 40 83 c3 08 89 } /* Opcode */
    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( all of ($s*) ) and 1 of ($op*) ) or ( all of them )
}

rule APT_Project_Sauron_Custom_M2 {
    meta:
        id = "5NkDPzCC3c4rW7aKDKZ6Wd"
        fingerprint = "v1_sha256_25955c9265291cd740bb4fcc18b17542ac7957bb0742cb994f1dec30708dd0c9"
        version = "1.0"
        date = "2016-08-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FLorian Roth"
        description = "Detects malware from Project Sauron APT"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"
        hash1 = "30a824155603c2e9d8bfd3adab8660e826d7e0681e28e46d102706a03e23e3a8"

    strings:
        $s2 = "\\*\\3vpn" fullword ascii

        $op0 = { 55 8b ec 83 ec 0c 53 56 33 f6 39 75 08 57 89 75 } /* Opcode */
        $op1 = { 59 59 c3 8b 65 e8 ff 75 88 ff 15 50 20 40 00 ff } /* Opcode */
        $op2 = { 8b 4f 06 85 c9 74 14 83 f9 12 0f 82 a7 } /* Opcode */
    condition:
        ( uint16(0) == 0x5a4d and filesize < 400KB and ( all of ($s*) ) and all of ($op*) )
}

rule APT_Project_Sauron_Custom_M3 {
    meta:
        id = "70pi3PChWcOiJZLenuu2gt"
        fingerprint = "v1_sha256_739414990d112dd16e01831408ba745b04fae7621eb9074f73babbc40b69e1ad"
        version = "1.0"
        date = "2016-08-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FLorian Roth"
        description = "Detects malware from Project Sauron APT"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"
        hash1 = "a4736de88e9208eb81b52f29bab9e7f328b90a86512bd0baadf4c519e948e5ec"

    strings:
        $s1 = "ExampleProject.dll" fullword ascii

        $op0 = { 8b 4f 06 85 c9 74 14 83 f9 13 0f 82 ba } /* Opcode */
        $op1 = { ff 15 34 20 00 10 85 c0 59 a3 60 30 00 10 75 04 } /* Opcode */
        $op2 = { 55 8b ec ff 4d 0c 75 09 ff 75 08 ff 15 00 20 00 } /* Opcode */
    condition:
        ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of ($s*) ) and all of ($op*) )
}

rule APT_Project_Sauron_Custom_M4 {
    meta:
        id = "1Mgy1jb0lxxjdrYmo11NYZ"
        fingerprint = "v1_sha256_0735ba9591a9cf06cd13ba480b4559ef83105ab08ffcec21ebbbfdf3766edb93"
        version = "1.0"
        date = "2016-08-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FLorian Roth"
        description = "Detects malware from Project Sauron APT"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"
        hash1 = "e12e66a6127cfd2cbb42e6f0d57c9dd019b02768d6f1fb44d91f12d90a611a57"

    strings:
        $s1 = "xpsmngr.dll" fullword wide
        $s2 = "XPS Manager" fullword wide

        $op0 = { 89 4d e8 89 4d ec 89 4d f0 ff d2 3d 08 00 00 c6 } /* Opcode */
        $op1 = { 55 8b ec ff 4d 0c 75 09 ff 75 08 ff 15 04 20 5b } /* Opcode */
        $op2 = { 8b 4f 06 85 c9 74 14 83 f9 13 0f 82 b6 } /* Opcode */
    condition:
        ( uint16(0) == 0x5a4d and filesize < 90KB and ( all of ($s*) ) and 1 of ($op*) ) or ( all of them )
}

rule APT_Project_Sauron_Custom_M6 {
    meta:
        id = "5sxerDAlJu8ewgndX7Cf20"
        fingerprint = "v1_sha256_95ca9a0b2e71e7152d20a01d238e7362024c6dac6fc95ed2ebfa96dcbc8dbd40"
        version = "1.0"
        date = "2016-08-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FLorian Roth"
        description = "Detects malware from Project Sauron APT"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"
        hash1 = "3782b63d7f6f688a5ccb1b72be89a6a98bb722218c9f22402709af97a41973c8"

    strings:
        $s1 = "rseceng.dll" fullword wide
        $s2 = "Remote Security Engine" fullword wide

        $op0 = { 8b 0d d5 1d 00 00 85 c9 0f 8e a2 } /* Opcode */
        $op1 = { 80 75 6e 85 c0 79 6a 66 41 83 38 0a 75 63 0f b7 } /* Opcode */
        $op2 = { 80 75 29 85 c9 79 25 b9 01 } /* Opcode */
    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( all of ($s*) ) and 1 of ($op*) ) or ( all of them )
}

rule APT_Project_Sauron_Custom_M7 {
    meta:
        id = "58EfMWEoEbSB0zHpQ0aVwG"
        fingerprint = "v1_sha256_d132ddeb1d26b035565d3707b73d401fb413315febe26ac291cb05bfeca7c41d"
        version = "1.0"
        date = "2016-08-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FLorian Roth"
        description = "Detects malware from Project Sauron APT"
        category = "INFO"
        reference = "https://goo.gl/eFoP4A"
        hash1 = "6c8c93069831a1b60279d2b316fd36bffa0d4c407068dbef81b8e2fe8fd8e8cd"
        hash2 = "7cc0bf547e78c8aaf408495ceef58fa706e6b5d44441fefdce09d9f06398c0ca"

    strings:
        $sx1 = "Default user" fullword wide
        $sx2 = "Hincorrect header check" fullword ascii /* Typo */

        $sa1 = "MSAOSSPC.dll" fullword ascii
        $sa2 = "MSAOSSPC.DLL" fullword wide
        $sa3 = "MSAOSSPC" fullword wide
        $sa4 = "AOL Security Package" fullword wide
        $sa5 = "AOL Security Package" fullword wide
        $sa6 = "AOL Client for 32 bit platforms" fullword wide

        $op0 = { 8b ce 5b e9 4b ff ff ff 55 8b ec 51 53 8b 5d 08 } /* Opcode */
        $op1 = { e8 0a fe ff ff 8b 4d 14 89 46 04 89 41 04 8b 45 } /* Opcode */
        $op2 = { e9 29 ff ff ff 83 7d fc 00 0f 84 cf 0a 00 00 8b } /* Opcode */
        $op3 = { 83 f8 0c 0f 85 3a 01 00 00 44 2b 41 6c 41 8b c9 } /* Opcode */
        $op4 = { 44 39 57 0c 0f 84 d6 0c 00 00 44 89 6f 18 45 89 } /* Opcode */
        $op5 = { c1 ed 02 83 c6 fe e9 68 fe ff ff 44 39 57 08 75 } /* Opcode */
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and
        (
            ( 3 of ($s*) and 3 of ($op*) ) or
            ( 1 of ($sx*) and 1 of ($sa*) )
        )
}
