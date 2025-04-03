
rule apt_sofacy_xtunnel {
    meta:
        id = "69hjIDEJBorKwoATj9PuL1"
        fingerprint = "v1_sha256_2478d9d8996bf4a142e39eac0e2d6af718d364be080a89530812615595777efd"
        version = "1.0"
        score = 75
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Claudio Guarnieri"
        description = "Sofacy Malware - German Bundestag"
        category = "INFO"

    strings:
        $xaps = ":\\PROJECT\\XAPS_"
        $variant11 = "XAPS_OBJECTIVE.dll" $variant12 = "start"
        $variant21 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0"
        $variant22 = "is you live?"
        $mix1 = "176.31.112.10"
        $mix2 = "error in select, errno %d" $mix3 = "no msg"
        $mix4 = "is you live?"
        $mix5 = "127.0.0.1"
        $mix6 = "err %d"
        $mix7 = "i`m wait"
        $mix8 = "hello"
        $mix9 = "OpenSSL 1.0.1e 11 Feb 2013" $mix10 = "Xtunnel.exe"
    condition:
        ((uint16(0) == 0x5A4D) or (uint16(0) == 0xCFD0)) and (($xaps) or (all of ($variant1*)) or (all of ($variant2*)) or (6 of ($mix*)))
}

rule Winexe_RemoteExecution {
    meta:
        id = "DevuJpMm2i7eMkpYTV9VA"
        fingerprint = "v1_sha256_a57c7e494440535f6270432215fbc9af728df390c349cfa24d1a4e006ffec79f"
        version = "1.0"
        score = 70
        date = "2015-06-19"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Winexe tool used by Sofacy group several APT cases"
        category = "INFO"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        hash = "5130f600cd9a9cdc82d4bad938b20cbd2f699aadb76e7f3f1a93602330d9997d"

    strings:
        $s1 = "\\\\.\\pipe\\ahexec" fullword ascii
        $s2 = "implevel" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 115KB and all of them
}

rule Sofacy_Mal2 {
    meta:
        id = "13CDr6vbCTwyDqxgw46QAs"
        fingerprint = "v1_sha256_c325ed815b7de3338363d064f4097edf0596644d4ef8d642fda3664a2a16c2eb"
        version = "1.0"
        score = 70
        date = "2015-06-19"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Sofacy Group Malware Sample 2"
        category = "INFO"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        hash = "566ab945f61be016bfd9e83cc1b64f783b9b8deb891e6d504d3442bc8281b092"

    strings:
        $x1 = "PROJECT\\XAPS_OBJECTIVE_DLL\\" ascii
        $x2 = "XAPS_OBJECTIVE.dll" fullword ascii

        $s1 = "i`m wait" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ( 1 of ($x*) ) and $s1
}

rule Sofacy_Mal3 {
    meta:
        id = "3hueA5CR57ZceaK7YpYrcd"
        fingerprint = "v1_sha256_af34a68f8c83cae06a77af09aeba9583d310e28ecc2aed3c5e6ae08c4870e3d9"
        version = "1.0"
        score = 70
        date = "2015-06-19"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Sofacy Group Malware Sample 3"
        category = "INFO"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        hash = "5f6b2a0d1d966fc4f1ed292b46240767f4acb06c13512b0061b434ae2a692fa1"

    strings:
        $s1 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" fullword ascii
        $s2 = ".?AVAgentModuleRemoteKeyLogger@@" fullword ascii
        $s3 = "<font size=4 color=red>process isn't exist</font>" fullword ascii
        $s4 = "<font size=4 color=red>process is exist</font>" fullword ascii
        $s5 = ".winnt.check-fix.com" fullword ascii
        $s6 = ".update.adobeincorp.com" fullword ascii
        $s7 = ".microsoft.checkwinframe.com" fullword ascii
        $s8 = "adobeincorp.com" fullword wide
        $s9 = "# EXC: HttpSender - Cannot create Get Channel!" fullword ascii

        $x1 = "User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:20.0) Gecko/20100101 Firefox/" wide
        $x2 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/2" wide
        $x3 = "C:\\Windows\\System32\\cmd.exe" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and (
            2 of ($s*) or
            ( 1 of ($s*) and all of ($x*) )
        )
}

rule Sofacy_Bundestag_Batch {
    meta:
        id = "2KWs5EXqzJ1qIKgSq6ePDm"
        fingerprint = "v1_sha256_05d6df161042a65f9eeec4be4046001a03fa61747a9ea123f13e6e75d6664ac7"
        version = "1.0"
        score = 70
        date = "2015-06-19"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Sofacy Bundestags APT Batch Script"
        category = "INFO"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"

    strings:
        $s1 = "for %%G in (.pdf, .xls, .xlsx, .doc, .docx)" ascii
        $s2 = "cmd /c copy"
        $s3 = "forfiles"
    condition:
        filesize < 10KB and 2 of them
}
