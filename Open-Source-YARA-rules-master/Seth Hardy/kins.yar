rule KINS_dropper {
    meta:
        id = "2IOAwdaD1C3t6GA6uyB7RC"
        fingerprint = "v1_sha256_cdab93f823e13e0c3104de8e05cb1572f83fb5294f359698092d73fc7983955b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs aortega@alienvault.com"
        description = "Match protocol, process injects and windows exploit present in KINS dropper"
        category = "INFO"

    strings:
        // Network protocol
        $n1 = "tid=%d&ta=%s-%x" fullword
        $n2 = "fid=%d" fullword
        $n3 = "%[^.].%[^(](%[^)])" fullword
        // Injects
        $i0 = "%s [%s %d] 77 %s"
        $i01 = "Global\\%s%x"
        $i1 = "Inject::InjectProcessByName()"
        $i2 = "Inject::CopyImageToProcess()"
        $i3 = "Inject::InjectProcess()"
        $i4 = "Inject::InjectImageToProcess()"
        $i5 = "Drop::InjectStartThread()"
        // UAC bypass
        $uac1 = "ExploitMS10_092"
        $uac2 = "\\globalroot\\systemroot\\system32\\tasks\\" ascii wide
        $uac3 = "<RunLevel>HighestAvailable</RunLevel>" ascii wide
    condition:
        2 of ($n*) and 2 of ($i*) and 2 of ($uac*)
}

rule KINS_DLL_zeus {
    meta:
        id = "6yBLrf8NXW1mZgqDpy77cy"
        fingerprint = "v1_sha256_bd1ebe7976d1f93856b4f8d1d62d8fff68ce6234204da9fbdc233ddbef56864d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs aortega@alienvault.com"
        description = "Match default bot in KINS leaked dropper, Zeus"
        category = "INFO"

    strings:
        // Network protocol
        $n1 = "%BOTID%" fullword
        $n2 = "%opensocks%" fullword
        $n3 = "%openvnc%" fullword
        $n4 = /Global\\(s|v)_ev/ fullword
        // Crypted strings
        $s1 = "\x72\x6E\x6D\x2C\x36\x7D\x76\x77"
        $s2 = "\x18\x04\x0F\x12\x16\x0A\x1E\x08\x5B\x11\x0F\x13"
        $s3 = "\x39\x1F\x01\x07\x15\x19\x1A\x33\x19\x0D\x1F"
        $s4 = "\x62\x6F\x71\x78\x63\x61\x7F\x69\x2D\x67\x79\x65"
        $s5 = "\x6F\x69\x7F\x6B\x61\x53\x6A\x7C\x73\x6F\x71"
    condition:
        all of ($n*) and 1 of ($s*)
}
