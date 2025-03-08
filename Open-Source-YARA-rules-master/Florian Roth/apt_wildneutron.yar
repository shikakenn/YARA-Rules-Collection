/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-07-10
    Identifier: WildNeutron
*/

/* Rule Set ----------------------------------------------------------------- */

rule WildNeutron_Sample_1 {
    meta:
        id = "4ZrTYBvASkby2rIvnqO7mc"
        fingerprint = "v1_sha256_d8044761fa51f2afd16eb096aa9e896483387c47e10ce922f2ef32ebcbd1a520"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - file 2b5065a3d0e0b8252a987ef5f29d9e1935c5863f5718b83440e68dc53c21fa94"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        hash = "2b5065a3d0e0b8252a987ef5f29d9e1935c5863f5718b83440e68dc53c21fa94"

    strings:
        $s0 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
        $s1 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
        $s2 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
        $s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
        $s8 = "id-ce-keyUsage" fullword ascii /* score: '12.00' */
        $s9 = "Key Usage" fullword ascii /* score: '12.00' */
        $s32 = "UPDATE_ID" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00' */
        $s37 = "id-at-commonName" fullword ascii /* score: '8.00' */
        $s38 = "2008R2" fullword wide /* PEStudio Blacklist: os */ /* score: '8.00' */
        $s39 = "RSA-alt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00' */
        $s40 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule WildNeutron_Sample_2 {
    meta:
        id = "7Nf6zy1OvtVStFuNwWfqM1"
        fingerprint = "v1_sha256_3a796199a2e9f2711e5fbdc1050234a8f3c09f762bc645f49a705d9f112d9cdc"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - file 8d80f9ef55324212759f4b6070cb8fce18a008ae9dd8b9598553206654d13a6f"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        hash = "8d80f9ef55324212759f4b6070cb8fce18a008ae9dd8b9598553206654d13a6f"

    strings:
        $s0 = "rundll32.exe \"%s\",#1" fullword wide /* PEStudio Blacklist: strings */ /* score: '33.00' */
        $s1 = "IgfxUpt.exe" fullword wide /* score: '20.00' */
        $s2 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
        $s3 = "Intel(R) Common User Interface" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
        $s4 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
        $s11 = "Key Usage" fullword ascii /* score: '12.00' */
        $s12 = "Intel Integrated Graphics Updater" fullword wide /* PEStudio Blacklist: strings */ /* score: '12.00' */
        $s13 = "%sexpires on    : %04d-%02d-%02d %02d:%02d:%02d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00' */
    condition:
        uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule WildNeutron_Sample_3 {
    meta:
        id = "7MzFrRwJV6pwriPHKt8H44"
        fingerprint = "v1_sha256_dd989a27a0c5f04e4d87b09d27054bf34f8b3d2ab1da668979ef82c32c49d8dc"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - file c2c761cde3175f6e40ed934f2e82c76602c81e2128187bab61793ddb3bc686d0"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        hash = "c2c761cde3175f6e40ed934f2e82c76602c81e2128187bab61793ddb3bc686d0"

    strings:
        $x1 = "178.162.197.9" fullword ascii /* score: '9.00' */
        $x2 = "\"http://fw.ddosprotected.eu:80 /opts resolv=drfx.chickenkiller.com\"" fullword wide /* PEStudio Blacklist: strings */ /* score: '33.00' */
        $x3 = ".chickenkiller.com" ascii /* PEStudio Blacklist: strings */ /* score: '28.00' */
        
        $s1 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
        $s2 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
        $s3 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
        $s4 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
        $s5 = "id-at-serialNumber" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
        $s6 = "ECDSA with SHA256" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
        $s7 = "Acer LiveUpdater" fullword wide /* PEStudio Blacklist: strings */ /* score: '10.00' */
    condition:
        uint16(0) == 0x5a4d and filesize < 2020KB and 
        ( 1 of ($x*) or all of ($s*) )
}

rule WildNeutron_Sample_4 {
    meta:
        id = "kmdSie8C7Nb5E3Y8xEroK"
        fingerprint = "v1_sha256_4882b7c5f469615436490cd628ee3bb5b0dded43fb556ac6477cdadc6c8eff05"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - file b4005530193bc523d3e0193c3c53e2737ae3bf9f76d12c827c0b5cd0dcbaae45"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        hash = "b4005530193bc523d3e0193c3c53e2737ae3bf9f76d12c827c0b5cd0dcbaae45"

    strings:
        $x1 = "WinRAT-Win32-Release.exe" fullword ascii /* score: '22.00' */

        $s0 = "rundll32.exe \"%s\",#1" fullword wide /* PEStudio Blacklist: strings */ /* score: '33.00' */
        $s1 = "RtlUpd.EXE" fullword wide /* score: '20.00' */
        $s2 = "RtlUpd.exe" fullword wide /* score: '20.00' */
        $s3 = "Driver Update and remove for Windows x64 or x86_32" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
        $s4 = "Realtek HD Audio Update and remove driver Tool" fullword wide /* PEStudio Blacklist: strings */ /* score: '16.00' */
        $s5 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
        $s6 = "Key Usage" fullword ascii /* score: '12.00' */
        $s7 = "id-at-serialNumber" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
    condition:
        uint16(0) == 0x5a4d and filesize < 1240KB and all of them
}

rule WildNeutron_Sample_5 {
    meta:
        id = "4qoXWxmZ7oEufTskfU15E6"
        fingerprint = "v1_sha256_57792a54c96c59a1e9ed961715c72187936aee6f001c2ed4f95ca84e799e9c8c"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - file 1604e36ccef5fa221b101d7f043ad7f856b84bf1a80774aa33d91c2a9a226206"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        hash = "1604e36ccef5fa221b101d7f043ad7f856b84bf1a80774aa33d91c2a9a226206"

    strings:
        $s0 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
        $s1 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
        $s2 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
        $s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
        $s4 = "sha-1WithRSAEncryption" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
        $s5 = "Postal code" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.00' */
        $s6 = "id-ce-keyUsage" fullword ascii /* score: '12.00' */
        $s7 = "Key Usage" fullword ascii /* score: '12.00' */
        $s8 = "TLS-RSA-WITH-3DES-EDE-CBC-SHA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00' */
        $s9 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule WildNeutron_Sample_6 {
    meta:
        id = "4ZPA8n0aO2x6JIDLIC8lEH"
        fingerprint = "v1_sha256_7dc7f9815f2b2c934ecf93f5813bdb87364b2b9e2a5aebc04f76cfff43e46d30"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - file 4bd548fe07b19178281edb1ee81c9711525dab03dc0b6676963019c44cc75865"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        hash = "4bd548fe07b19178281edb1ee81c9711525dab03dc0b6676963019c44cc75865"

    strings:
        $s0 = "mshtaex.exe" fullword wide /* score: '20.00' */
    condition:
        uint16(0) == 0x5a4d and filesize < 310KB and all of them
}

rule WildNeutron_Sample_7 {
    meta:
        id = "5tD7oeW1aFpotL68VCD0xs"
        fingerprint = "v1_sha256_8a081932be8fd03c37a87486570a02a31756ba6bd125dbed7da9703197447ea5"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - file a14d31eb965ea8a37ebcc3b5635099f2ca08365646437c770212d534d504ff3c"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        hash = "a14d31eb965ea8a37ebcc3b5635099f2ca08365646437c770212d534d504ff3c"

    strings:
        $s0 = "checking match for '%s' user %s host %s addr %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00' */
        $s1 = "PEM_read_bio_PrivateKey failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
        $s2 = "usage: %s [-ehR] [-f log_facility] [-l log_level] [-u umask]" fullword ascii /* score: '23.00' */
        $s3 = "%s %s for %s%.100s from %.200s port %d%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
        $s4 = "clapi32.dll" fullword ascii /* score: '21.00' */
        $s5 = "Connection from %s port %d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
        $s6 = "/usr/etc/ssh_known_hosts" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.00' */
        $s7 = "Version: %s - %s %s %s %s" fullword ascii /* score: '16.00' */
        $s8 = "[-] connect()" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.00' */
        $s9 = "/bin/sh /usr/etc/sshrc" fullword ascii /* score: '12.42' */
        $s10 = "kexecdhs.c" fullword ascii /* score: '12.00' */
        $s11 = "%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s" fullword ascii /* score: '11.00' */
    condition:
        uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule WildNeutron_Sample_8 {
    meta:
        id = "RVbmzXg9lfGYWS2V8BvLx"
        fingerprint = "v1_sha256_6ccae5cf1081999d683f7f165b720cb45f3e832101f2937b6b123feab72d34db"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - file 758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        hash = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"

    strings:
        $x1 = "RunFile: couldn't load SHELL32.DLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
        $x2 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00' */
        $x3 = "Error executing CreateProcess()!!" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00' */
        $x4 = "cmdcmdline" fullword wide /* score: '11.00' */
        $x5 = "Invalid input handle!!!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */

        $s1 = "Process %d terminated" fullword wide /* PEStudio Blacklist: strings */ /* score: '24.00' */
        $s2 = "Process is not running any more" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00' */
        $s3 = "javacpl.exe" fullword wide /* score: '3.00' */ /* Goodware String - occured 2 times */
        $s4 = "Windows NT Version %lu.%lu" fullword wide /* PEStudio Blacklist: os */ /* score: '19.00' */
        $s5 = "Usage: destination [reference]" fullword wide /* PEStudio Blacklist: strings */ /* score: '16.00' */
        $s6 = ".com;.exe;.bat;.cmd" fullword wide /* score: '15.00' */
        $s7 = ") -%s-> %s (" fullword ascii /* score: '14.00' */
        $s8 = "cmdextversion" fullword wide /* score: '14.00' */
        $s9 = "Invalid pid (%s)" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00' */
        $s10 = "\"%s\" /K %s" fullword wide /* score: '11.02' */
        $s11 = "Error setting %s (%s)" fullword wide /* score: '11.00' */
        $s12 = "DEBUG: Cannot allocate memory for ptrNextNode->ptrNext!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
        $s13 = "Failed to build full directory path" fullword wide /* score: '10.00' */
        $s14 = "DEBUG: Cannot allocate memory for ptrFileArray!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00' */
        $s15 = "%-8s %-3s  %*s %s  %s" fullword wide /* score: '8.00' */
        $s16 = " %%%c in (%s) do " fullword wide /* score: '8.00' */
    condition:
        uint16(0) == 0x5a4d and filesize < 1677KB and 2 of ($x*) and 6 of ($s*)
}

rule WildNeutron_Sample_9 {
    meta:
        id = "2Gqj5y3aqpftrQRzwolP7v"
        fingerprint = "v1_sha256_7955cb1c1da17fd5b6014efb8a90eb4041b135ebf0579ba448524c8b36946ca1"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - file 781eb1e17349009fbae46aea5c59d8e5b68ae0b42335cb035742f6b0f4e4087e"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        hash = "781eb1e17349009fbae46aea5c59d8e5b68ae0b42335cb035742f6b0f4e4087e"

    strings:
        $s0 = "http://get.adobe.com/flashplayer/" fullword wide /* PEStudio Blacklist: strings */ /* score: '30.00' */
        $s1 = "xxxxxxxxxxxxxxxxxxxx" fullword wide /* reversed goodware string 'xxxxxxxxxxxxxxxxxxxx' */ /* score: '19.00' */
        $s4 = " Player Installer/Uninstaller" fullword wide /* PEStudio Blacklist: strings */ /* score: '11.42' */
        $s5 = "Adobe Flash Plugin Updater" fullword wide /* PEStudio Blacklist: strings */ /* score: '11.00' */
        $s6 = "uSOFTWARE\\Adobe" fullword wide /* PEStudio Blacklist: strings */ /* score: '10.42' */
        $s11 = "2008R2" fullword wide /* PEStudio Blacklist: os */ /* score: '8.00' */
        $s12 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
        $s13 = "%d -> %d" fullword wide /* score: '7.00' */
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule WildNeutron_Sample_10 {
    meta:
        id = "7fP8ucKYwtZ5G445RSi87u"
        fingerprint = "v1_sha256_b282b6892f9cb6769bf0e302deaa8062fd69bfd51144bc06fc9501fde9537dae"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - file 1d3bdabb350ba5a821849893dabe5d6056bf7ba1ed6042d93174ceeaa5d6dad7"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        hash = "1d3bdabb350ba5a821849893dabe5d6056bf7ba1ed6042d93174ceeaa5d6dad7"

    strings:
        $n1 = "/c for /L %%i in (1,1,2) DO ping 127.0.0.1 -n 3 & type %%windir%%\\notepad.exe > %s & del /f %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '46.00' */
        
        $s1 = "%SYSTEMROOT%\\temp\\_dbg.tmp" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00' */
        $s2 = "%SYSTEMROOT%\\SysWOW64\\mspool.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
        $s3 = "%SYSTEMROOT%\\System32\\dpcore16t.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
        $s4 = "%SYSTEMROOT%\\System32\\wdigestEx.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
        $s5 = "%SYSTEMROOT%\\System32\\mspool.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
        $s6 = "%SYSTEMROOT%\\System32\\kernel32.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
        $s7 = "%SYSTEMROOT%\\SysWOW64\\iastor32.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
        $s8 = "%SYSTEMROOT%\\System32\\msvcse.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
        $s9 = "%SYSTEMROOT%\\System32\\mshtaex.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
        $s10 = "%SYSTEMROOT%\\System32\\iastor32.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
        $s11 = "%SYSTEMROOT%\\SysWOW64\\mshtaex.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
        
        $x1 = "wdigestEx.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00' */
        $x2 = "dpcore16t.dll" fullword ascii /* score: '21.00' */
        $x3 = "mspool.dll" fullword ascii /* score: '21.00' */
        $x4 = "msvcse.exe" fullword ascii /* score: '20.00' */
        $x5 = "mshtaex.exe" fullword wide /* score: '20.00' */
        $x6 = "iastor32.exe" fullword ascii /* score: '20.00' */

        $y1 = "Installer.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00' */
        $y2 = "Info: Process %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00' */
        $y3 = "Error: GetFileTime %s 0x%x" fullword ascii /* score: '17.00' */
        $y4 = "Install succeeded" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
        $y5 = "Error: RegSetValueExA 0x%x" fullword ascii /* score: '9.00' */
    condition:
        uint16(0) == 0x5a4d and filesize < 400KB and 
        (
            $n1 or ( 1 of ($s*) and 1 of ($x*) and 3 of ($y*) ) 
        )
}

/* Super Rules ------------------------------------------------------------- */

rule WildNeutron_javacpl {
    meta:
        id = "1YFj5EJFQni7ZbrMq9KqqN"
        fingerprint = "v1_sha256_890c6dd0515c6db6433ac0619b206c75f0f2cdb3babd310e0e0e1b462e5cf7ac"
        version = "1.0"
        score = 60
        date = "2015-07-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Wild Neutron APT Sample Rule - from files 683f5b476f8ffe87ec22b8bab57f74da4a13ecc3a5c2cbf951999953c2064fc9, 758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92, 8ca7ed720babb32a6f381769ea00e16082a563704f8b672cb21cf11843f4da7a"
        category = "INFO"
        reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        super_rule = 1
        hash1 = "683f5b476f8ffe87ec22b8bab57f74da4a13ecc3a5c2cbf951999953c2064fc9"
        hash2 = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
        hash3 = "8ca7ed720babb32a6f381769ea00e16082a563704f8b672cb21cf11843f4da7a"

    strings:
        $x1 = "javacpl.exe" fullword wide /* score: '3.00' */ /* Goodware String - occured 2 times */

        $s0 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00' */
        $s1 = "Error executing CreateProcess()!!" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00' */
        $s2 = "http://www.java.com/en/download/installed.jsp?detect=jre" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00' */
        $s3 = "RunFile: couldn't load SHELL32.DLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
        $s4 = "Process is not running any more" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00' */
        $s6 = "Windows NT Version %lu.%lu" fullword wide /* PEStudio Blacklist: os */ /* score: '19.00' */
        $s7 = "Usage: destination [reference]" fullword wide /* PEStudio Blacklist: strings */ /* score: '16.00' */
        $s8 = "Invalid input handle!!!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
        $s9 = ".com;.exe;.bat;.cmd" fullword wide /* score: '15.00' */
        $s10 = ") -%s-> %s (" fullword ascii /* score: '14.00' */
        $s11 = "cmdextversion" fullword wide /* score: '14.00' */
        $s12 = "Invalid pid (%s)" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00' */
        $s13 = "\"%s\" /K %s" fullword wide /* score: '11.02' */
        $s14 = "Error setting %s (%s)" fullword wide /* score: '11.00' */
        $s16 = "cmdcmdline" fullword wide /* score: '11.00' */
        $s39 = "2008R2" fullword ascii /* PEStudio Blacklist: os */ /* score: '8.00' */
    condition:
        uint16(0) == 0x5a4d and filesize < 1677KB and all of them
}
