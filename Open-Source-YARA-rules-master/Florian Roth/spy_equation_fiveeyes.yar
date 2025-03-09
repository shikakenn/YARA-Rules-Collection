/* Equation APT ------------------------------------------------------------ */

rule apt_equation_exploitlib_mutexes {
    meta:
        id = "70y3mPXvjAPka8PPzFojAK"
        fingerprint = "v1_sha256_6c4855ddb149a507655ed0da9e03d60fa3e1b87a2c810ceae3605d4d1a02ee2c"
        version = "1.0"
        modified = "2015-02-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
        category = "INFO"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
        copyright = "Kaspersky Lab"

    strings:
        $mz="MZ"
        $a1="prkMtx" wide
        $a2="cnFormSyncExFBC" wide
        $a3="cnFormVoidFBC" wide
        $a4="cnFormSyncExFBC"
        $a5="cnFormVoidFBC"
    condition:
        (($mz at 0) and any of ($a*))
}

rule apt_equation_doublefantasy_genericresource {
    meta:
        id = "7AaVtRZbSlhjtXPlGqTr8o"
        fingerprint = "v1_sha256_766bd245f274cedd1253e9d960d50d37cde8465f27eabacb3f843c8bf9a4ae9e"
        version = "1.0"
        modified = "2015-02-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect DoubleFantasy encoded config http://goo.gl/ivt8EW"
        category = "INFO"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
        copyright = "Kaspersky Lab"

    strings:
        $mz="MZ"
        $a1={06 00 42 00 49 00 4E 00 52 00 45 00 53 00}
        $a2="yyyyyyyyyyyyyyyy"
        $a3="002"
    condition:
        (($mz at 0) and all of ($a*)) and filesize < 500000
}

rule apt_equation_equationlaser_runtimeclasses {
    meta:
        id = "qbxJOV21HbEVKUvo7RxKR"
        fingerprint = "v1_sha256_663ea56f869f7099a92658df5bddd76d4e5ba8ac5dfc693733579682b9eee860"
        version = "1.0"
        modified = "2015-02-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect the EquationLaser malware"
        category = "INFO"
        reference = "https://securelist.com/blog/"
        copyright = "Kaspersky Lab"

    strings:
        $a1="?a73957838_2@@YAXXZ"
        $a2="?a84884@@YAXXZ"
        $a3="?b823838_9839@@YAXXZ"
        $a4="?e747383_94@@YAXXZ"
        $a5="?e83834@@YAXXZ"
        $a6="?e929348_827@@YAXXZ"
    condition:
        any of them
}

rule apt_equation_cryptotable {
    meta:
        id = "2NLOMBJY7FXUiL0auzw2Fa"
        fingerprint = "v1_sha256_e660fe423330334a1e3167d6a45e5ce2469fec276838618a7cb0340ec8172275"
        version = "1.0"
        modified = "2015-02-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect the crypto library used in Equation group malware"
        category = "INFO"
        reference = "https://securelist.com/blog/"
        copyright = "Kaspersky Lab"

    strings:
        $a={37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85 5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05 17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7 78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB A6 30 C5 5F BE 0C 50 C1}
    condition:
        $a
}

/* Equation Group - Kaspersky ---------------------------------------------- */

rule Equation_Kaspersky_TripleFantasy_1 {
    meta:
        id = "31ZTq8GDjIfIcNGNyIYeK1"
        fingerprint = "v1_sha256_827981f8eff19b9270ace7c45dcec0fcbdaa57398d4f9b7afa197fadd32fb7d1"
        version = "1.0"
        date = "2015/02/16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - TripleFantasy http://goo.gl/ivt8EW"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"
        hash = "b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9"

    strings:
        $mz = { 4d 5a }

        $s0 = "%SystemRoot%\\system32\\hnetcfg.dll" fullword wide
        $s1 = "%WINDIR%\\System32\\ahlhcib.dll" fullword wide
        $s2 = "%WINDIR%\\sjyntmv.dat" fullword wide
        $s3 = "Global\\{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" fullword wide
        $s4 = "%WINDIR%\\System32\\owrwbsdi" fullword wide
        $s5 = "Chrome" fullword wide
        $s6 = "StringIndex" fullword ascii

        $x1 = "itemagic.net@443" fullword wide
        $x2 = "team4heat.net@443" fullword wide
        $x5 = "62.216.152.69@443" fullword wide
        $x6 = "84.233.205.37@443" fullword wide

        $z1 = "www.microsoft.com@80" fullword wide
        $z2 = "www.google.com@80" fullword wide
        $z3 = "127.0.0.1:3128" fullword wide
    condition:
        ( $mz at 0 ) and filesize < 300000 and
        (
            ( all of ($s*) and all of ($z*) ) or
            ( all of ($s*) and 1 of ($x*) )
        )
}

rule Equation_Kaspersky_DoubleFantasy_1 {
    meta:
        id = "2DN0dRjcBmwbpBjYmt9LPT"
        fingerprint = "v1_sha256_a682f5a2d5244ac2d5f2465d9ba43dc50085131c8f6caa24966f6df0f069c5d3"
        version = "1.0"
        date = "2015/02/16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - DoubleFantasy"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"
        hash = "d09b4b6d3244ac382049736ca98d7de0c6787fa2"

    strings:
        $mz = { 4d 5a }

        $z1 = "msvcp5%d.dll" fullword ascii

        $s0 = "actxprxy.GetProxyDllInfo" fullword ascii
        $s3 = "actxprxy.DllGetClassObject" fullword ascii
        $s5 = "actxprxy.DllRegisterServer" fullword ascii
        $s6 = "actxprxy.DllUnregisterServer" fullword ascii

        $x1 = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" ascii
        $x2 = "191H1a1" fullword ascii
        $x3 = "November " fullword ascii
        $x4 = "abababababab" fullword ascii
        $x5 = "January " fullword ascii
        $x6 = "October " fullword ascii
        $x7 = "September " fullword ascii
    condition:
        ( $mz at 0 ) and filesize < 350000 and
        (
            ( $z1 ) or
            ( all of ($s*) and 6 of ($x*) )
        )
}

rule Equation_Kaspersky_GROK_Keylogger {
    meta:
        id = "6TPygYy69xVS05nOPKABbN"
        fingerprint = "v1_sha256_32962cfaeb37bae5a173affc98655c952c4616730df3f32e27e9fe81ad461f66"
        version = "1.0"
        date = "2015/02/16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - GROK keylogger"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"
        hash = "50b8f125ed33233a545a1aac3c9d4bb6aa34b48f"

    strings:
        $mz = { 4d 5a }
        $s0 = "c:\\users\\rmgree5\\" ascii
        $s1 = "msrtdv.sys" fullword wide

        $x1 = "svrg.pdb" fullword ascii
        $x2 = "W32pServiceTable" fullword ascii
        $x3 = "In forma" fullword ascii
        $x4 = "ReleaseF" fullword ascii
        $x5 = "criptor" fullword ascii
        $x6 = "astMutex" fullword ascii
        $x7 = "ARASATAU" fullword ascii
        $x8 = "R0omp4ar" fullword ascii

        $z1 = "H.text" fullword ascii
        $z2 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $z4 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment" wide fullword
    condition:
        ( $mz at 0 ) and filesize < 250000 and
        (
            $s0 or
            ( $s1 and 6 of ($x*) ) or
            ( 6 of ($x*) and all of ($z*) )
        )
}

rule Equation_Kaspersky_GreyFishInstaller {
    meta:
        id = "43jtyjVlhV3FFoyHabltx2"
        fingerprint = "v1_sha256_dae6963f3210503c6c86c818a9cd6f309ba7876f14ca42966097023d474a2366"
        version = "1.0"
        date = "2015/02/16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - Grey Fish"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"
        hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"

    strings:
        $s0 = "DOGROUND.exe" fullword wide
        $s1 = "Windows Configuration Services" fullword wide
        $s2 = "GetMappedFilenameW" fullword ascii
    condition:
        all of them
}

rule Equation_Kaspersky_EquationDrugInstaller {
    meta:
        id = "2d4y0hm5vJ9gUsIaIN7Pe0"
        fingerprint = "v1_sha256_4afc0c713dbe0e0a273e7572b234f118cfff94c07120494888f28bbd5a38971d"
        version = "1.0"
        date = "2015/02/16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"
        hash = "61fab1b8451275c7fd580895d9c68e152ff46417"

    strings:
        $mz = { 4d 5a }

        $s0 = "\\system32\\win32k.sys" fullword wide
        $s1 = "ALL_FIREWALLS" fullword ascii

        $x1 = "@prkMtx" fullword wide
        $x2 = "STATIC" fullword wide
        $x3 = "windir" fullword wide
        $x4 = "cnFormVoidFBC" fullword wide
        $x5 = "CcnFormSyncExFBC" fullword wide
        $x6 = "WinStaObj" fullword wide
        $x7 = "BINRES" fullword wide
    condition:
        ( $mz at 0 ) and filesize < 500000 and all of ($s*) and 5 of ($x*)
}

rule Equation_Kaspersky_EquationLaserInstaller {
    meta:
        id = "Q4T3vZCNUQ6S3k8ahmJmm"
        fingerprint = "v1_sha256_15a93403a966bb9e5b8c5396a4e78115fdb3d6f8fefac959d4ad68c62e1748d2"
        version = "1.0"
        date = "2015/02/16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - EquationLaser Installer"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"
        hash = "5e1f56c1e57fbff96d4999db1fd6dd0f7d8221df"

    strings:
        $mz = { 4d 5a }
        $s0 = "Failed to get Windows version" fullword ascii
        $s1 = "lsasrv32.dll and lsass.exe" fullword wide
        $s2 = "\\\\%s\\mailslot\\%s" fullword ascii
        $s3 = "%d-%d-%d %d:%d:%d Z" fullword ascii
        $s4 = "lsasrv32.dll" fullword ascii
        $s5 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii
        $s6 = "%s %02x %s" fullword ascii
        $s7 = "VIEWERS" fullword ascii
        $s8 = "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide
    condition:
        ( $mz at 0 ) and filesize < 250000 and 6 of ($s*)
}

rule Equation_Kaspersky_FannyWorm {
    meta:
        id = "1RAoJSPjWxOz6golqsv9T1"
        fingerprint = "v1_sha256_7f94b380cc55e65ed2cbfdf69707672a8e2fd49bfa331d99580c8e1829823e55"
        version = "1.0"
        date = "2015/02/16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - Fanny Worm"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"
        hash = "1f0ae54ac3f10d533013f74f48849de4e65817a7"

    strings:
        $mz = { 4d 5a }

        $s1 = "x:\\fanny.bmp" fullword ascii
        $s2 = "32.exe" fullword ascii
        $s3 = "d:\\fanny.bmp" fullword ascii

        $x1 = "c:\\windows\\system32\\kernel32.dll" fullword ascii
        $x2 = "System\\CurrentControlSet\\Services\\USBSTOR\\Enum" fullword ascii
        $x3 = "System\\CurrentControlSet\\Services\\PartMgr\\Enum" fullword ascii
        $x4 = "\\system32\\win32k.sys" fullword wide
        $x5 = "\\AGENTCPD.DLL" fullword ascii
        $x6 = "agentcpd.dll" fullword ascii
        $x7 = "PADupdate.exe" fullword ascii
        $x8 = "dll_installer.dll" fullword ascii
        $x9 = "\\restore\\" fullword ascii
        $x10 = "Q:\\__?__.lnk" fullword ascii
        $x11 = "Software\\Microsoft\\MSNetMng" fullword ascii
        $x12 = "\\shelldoc.dll" fullword ascii
        $x13 = "file size = %d bytes" fullword ascii
        $x14 = "\\MSAgent" fullword ascii
        $x15 = "Global\\RPCMutex" fullword ascii
        $x16 = "Global\\DirectMarketing" fullword ascii
    condition:
        ( $mz at 0 ) and filesize < 300000 and
        (
            ( 2 of ($s*) ) or
            ( 1 of ($s*) and 6 of ($x*) ) or
            ( 14 of ($x*) )
        )
}

rule Equation_Kaspersky_HDD_reprogramming_module {
    meta:
        id = "35rm2LAIhoRgIMTRJcVFLT"
        fingerprint = "v1_sha256_73c87cb9a9bc8a1c9ba4bf62c58c9bb2ef1605847bb7585260c1b652bb001988"
        version = "1.0"
        date = "2015/02/16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - HDD reprogramming module"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"
        hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"

    strings:
        $mz = { 4d 5a }
        $s0 = "nls_933w.dll" fullword ascii

        $s1 = "BINARY" fullword wide
        $s2 = "KfAcquireSpinLock" fullword ascii
        $s3 = "HAL.dll" fullword ascii
        $s4 = "READ_REGISTER_UCHAR" fullword ascii
    condition:
        ( $mz at 0 ) and filesize < 300000 and all of ($s*)
}

rule Equation_Kaspersky_EOP_Package {
    meta:
        id = "17pQ9OXnNpEzr3tgNBiPKr"
        fingerprint = "v1_sha256_b2cd003f0e5c37af5593b03a6c72b30876aaa316ff54029f2465c89bf5bd502a"
        version = "1.0"
        date = "2015/02/16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - EoP package and malware launcher"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"
        hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"

    strings:
        $mz = { 4d 5a }
        $s0 = "abababababab" fullword ascii
        $s1 = "abcdefghijklmnopq" fullword ascii
        $s2 = "@STATIC" fullword wide
        $s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
        $s4 = "@prkMtx" fullword wide
        $s5 = "prkMtx" fullword wide
        $s6 = "cnFormVoidFBC" fullword wide
    condition:
        ( $mz at 0 ) and filesize < 100000 and all of ($s*)
}

rule Equation_Kaspersky_TripleFantasy_Loader {
    meta:
        id = "6WbHDsKVNtaKNJypBtMIC2"
        fingerprint = "v1_sha256_5bf38500488e32d51ae38f04b1d5b8c31098dd837bff894ff5189ed16eadfe9f"
        version = "1.0"
        date = "2015/02/16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - TripleFantasy Loader"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"
        hash = "4ce6e77a11b443cc7cbe439b71bf39a39d3d7fa3"

    strings:
        $mz = { 4d 5a }

        $x1 = "Original Innovations, LLC" fullword wide
        $x2 = "Moniter Resource Protocol" fullword wide
        $x3 = "ahlhcib.dll" fullword wide

        $s0 = "hnetcfg.HNetGetSharingServicesPage" fullword ascii
        $s1 = "hnetcfg.IcfGetOperationalMode" fullword ascii
        $s2 = "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
        $s3 = "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
        $s4 = "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
        $s5 = "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii
    condition:
        ( $mz at 0 ) and filesize < 50000 and ( all of ($x*) and all of ($s*) )
}

/* Rule generated from the mentioned keywords */

rule Equation_Kaspersky_SuspiciousString {
    meta:
        id = "1OAnMiis3iW51v3ypILCgW"
        fingerprint = "v1_sha256_a35db07be0bf335adcb42459e024dfe812378013d538d9ebf8e075db774059dc"
        version = "1.0"
        score = 60
        date = "2015/02/17"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Equation Group Malware - suspicious string found in sample"
        category = "INFO"
        reference = "http://goo.gl/ivt8EW"

    strings:
        $mz = { 4d 5a }

        $s1 = "i386\\DesertWinterDriver.pdb" fullword
        $s2 = "Performing UR-specific post-install..."
        $s3 = "Timeout waiting for the \"canInstallNow\" event from the implant-specific EXE!"
        $s4 = "STRAITSHOOTER30.exe"
        $s5 = "standalonegrok_2.1.1.1"
        $s6 = "c:\\users\\rmgree5\\"
    condition:
        ( $mz at 0 ) and filesize < 500000 and all of ($s*)
}

/* EquationDrug Update 11.03.2015 - http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ */

rule EquationDrug_NetworkSniffer1 {
    meta:
        id = "7RCS2n0dtFk3LTfHMpHF7a"
        fingerprint = "v1_sha256_d21130f9292016fcb5831eb3187e936db9e1c17013c874e61ed4779916b5a6d0"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "26e787997a338d8111d96c9a4c103cf8ff0201ce"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s3 = "sys\\mstcp32.dbg" fullword ascii
        $s7 = "mstcp32.sys" fullword wide
        $s8 = "p32.sys" fullword ascii
        $s9 = "\\Device\\%ws_%ws" fullword wide
        $s10 = "\\DosDevices\\%ws" fullword wide
        $s11 = "\\Device\\%ws" fullword wide
    condition:
        all of them
}

rule EquationDrug_CompatLayer_UnilayDLL {
    meta:
        id = "7O6KDFjjvz5pU4tBiNbfN6"
        fingerprint = "v1_sha256_889f2af2d0650fb852cf937781ddcad5e5cb865c1dac2e59b7b1d71039be2592"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Unilay.DLL"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "a3a31937956f161beba8acac35b96cb74241cd0f"

    strings:
        $mz = { 4d 5a }
        $s0 = "unilay.dll" fullword ascii
    condition:
        ( $mz at 0 ) and $s0
}

rule EquationDrug_HDDSSD_Op {
    meta:
        id = "6OA51hiHtw1sxqBWfI9plK"
        fingerprint = "v1_sha256_9b45b2016a15f22079c439ff33c20e49d3c846fb4dd83caf2880767ea513a6e3"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - HDD/SSD firmware operation - nls_933w.dll"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"

    strings:
        $s0 = "nls_933w.dll" fullword ascii
    condition:
        all of them
}

rule EquationDrug_NetworkSniffer2 {
    meta:
        id = "4NABkzmChcvUddZebDKO50"
        fingerprint = "v1_sha256_69f86fb3108d96b2addc2efaf92234ccbc7f2447a2a621732910ebfee75b52a9"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Network Sniffer - tdip.sys"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "7e3cd36875c0e5ccb076eb74855d627ae8d4627f"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "IP Transport Driver" fullword wide
        $s2 = "tdip.sys" fullword wide
        $s3 = "sys\\tdip.dbg" fullword ascii
        $s4 = "dip.sys" fullword ascii
        $s5 = "\\Device\\%ws_%ws" fullword wide
        $s6 = "\\DosDevices\\%ws" fullword wide
        $s7 = "\\Device\\%ws" fullword wide
    condition:
        all of them
}

rule EquationDrug_NetworkSniffer3 {
    meta:
        id = "6OtUheLw4UcaX0fhc4VsjW"
        fingerprint = "v1_sha256_18c516fe0cd74e7a02ee15260abf3d27bba992492e6042a148abdee3086a9a00"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Network Sniffer - tdip.sys"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "14599516381a9646cd978cf962c4f92386371040"

    strings:
        $s0 = "Corporation. All rights reserved." fullword wide
        $s1 = "IP Transport Driver" fullword wide
        $s2 = "tdip.sys" fullword wide
        $s3 = "tdip.pdb" fullword ascii
    condition:
        all of them
}

rule EquationDrug_VolRec_Driver {
    meta:
        id = "74Q8u8IX76MkfsqayWVFKU"
        fingerprint = "v1_sha256_24b8202a8590ddb1dd76e01499d02282ad40a6fd6f6b9020040381a370e91f40"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Collector plugin for Volrec - msrstd.sys"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "ee2b504ad502dc3fed62d6483d93d9b1221cdd6c"

    strings:
        $s0 = "msrstd.sys" fullword wide
        $s1 = "msrstd.pdb" fullword ascii
        $s2 = "msrstd driver" fullword wide
    condition:
        all of them
}

rule EquationDrug_KernelRootkit {
    meta:
        id = "2qgL3HSxMmcjhFaZ29FAQX"
        fingerprint = "v1_sha256_5f87b7d2cb05cd68fd3ad1e8815e578cf2232c7da7f81b06185593261cf1ec34"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Kernel mode stage 0 and rootkit (Windows 2000 and above) - msndsrv.sys"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "597715224249e9fb77dc733b2e4d507f0cc41af6"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "Parmsndsrv.dbg" fullword ascii
        $s2 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s3 = "msndsrv.sys" fullword wide
        $s5 = "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\Windows" fullword wide
        $s6 = "\\Device\\%ws_%ws" fullword wide
        $s7 = "\\DosDevices\\%ws" fullword wide
        $s9 = "\\Device\\%ws" fullword wide
    condition:
        all of them
}

rule EquationDrug_Keylogger {
    meta:
        id = "3wAAcT1LcREprI5kTwJYHd"
        fingerprint = "v1_sha256_3978b71fb63b24fbb63fb6f7380182bd3d5a2de4210cb00e93bf2bbd1c07c88d"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "b93aa17b19575a6e4962d224c5801fb78e9a7bb5"

    strings:
        $s0 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $s2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\En" wide
        $s3 = "\\DosDevices\\Gk" fullword wide
        $s5 = "\\Device\\Gk0" fullword wide
    condition:
        all of them
}

rule EquationDrug_NetworkSniffer4 {
    meta:
        id = "3QsVqJ18aRggYD4ZT3cSFN"
        fingerprint = "v1_sha256_82ca6e109d2baf2476118edc0dc65482a0d1b6439a2f056e749cf87265f4e88f"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "cace40965f8600a24a2457f7792efba3bd84d9ba"

    strings:
        $s0 = "Copyright 1999 RAVISENT Technologies Inc." fullword wide
        $s1 = "\\systemroot\\" fullword ascii
        $s2 = "RAVISENT Technologies Inc." fullword wide
        $s3 = "Created by VIONA Development" fullword wide
        $s4 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s5 = "\\device\\harddiskvolume" fullword wide
        $s7 = "ATMDKDRV.SYS" fullword wide
        $s8 = "\\Device\\%ws_%ws" fullword wide
        $s9 = "\\DosDevices\\%ws" fullword wide
        $s10 = "CineMaster C 1.1 WDM Main Driver" fullword wide
        $s11 = "\\Device\\%ws" fullword wide
        $s13 = "CineMaster C 1.1 WDM" fullword wide
    condition:
        all of them
}

rule EquationDrug_PlatformOrchestrator {
    meta:
        id = "4ogn129iXeQ3GwYiQrAxtz"
        fingerprint = "v1_sha256_d18fb48c3ea4b342ab2fb51c6005c29dd72c60dfb683c3f592510868a6a92132"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Platform orchestrator - mscfg32.dll, svchost32.dll"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "febc4f30786db7804008dc9bc1cebdc26993e240"

    strings:
        $s0 = "SERVICES.EXE" fullword wide
        $s1 = "\\command.com" fullword wide
        $s2 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s3 = "LSASS.EXE" fullword wide
        $s4 = "Windows Configuration Services" fullword wide
        $s8 = "unilay.dll" fullword ascii
    condition:
        all of them
}

rule EquationDrug_NetworkSniffer5 {
    meta:
        id = "7iTsVy2wZar1wGPWDPcIBr"
        fingerprint = "v1_sha256_04a5b6b60748aa29c179610df5a4ae07fdc04358d9f9a430c82197c82b7fe2bf"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "09399b9bd600d4516db37307a457bc55eedcbd17"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s2 = "atmdkdrv.sys" fullword wide
        $s4 = "\\Device\\%ws_%ws" fullword wide
        $s5 = "\\DosDevices\\%ws" fullword wide
        $s6 = "\\Device\\%ws" fullword wide
    condition:
        all of them
}

rule EquationDrug_FileSystem_Filter {
    meta:
        id = "1Wf47fyWypbIMAxQHEOMOo"
        fingerprint = "v1_sha256_5da0c279da1b84a41e7d15df3c19cd50af1872156f133de0a367b9140425aa11"
        version = "1.0"
        date = "2015/03/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "EquationDrug - Filesystem filter driver - volrec.sys, scsi2mgr.sys"
        category = "INFO"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        hash = "57fa4a1abbf39f4899ea76543ebd3688dcc11e13"

    strings:
        $s0 = "volrec.sys" fullword wide
        $s1 = "volrec.pdb" fullword ascii
        $s2 = "Volume recognizer driver" fullword wide
    condition:
        all of them
}

rule apt_equation_keyword {
    meta:
        id = "6oi60DgcyFSHxssd73lcW9"
        fingerprint = "v1_sha256_d9a2b31d078eabbc930e9ec06e5ead5a6cda4eebf1c0ebe8164caf75a9d3cba6"
        version = "1.0"
        modified = "2015-09-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect Equation group's keyword in executable file"
        category = "INFO"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"

    strings:
         $a1 = "Backsnarf_AB25" wide
         $a2 = "Backsnarf_AB25" ascii
    condition:
         uint16(0) == 0x5a4d and 1 of ($a*)
}
