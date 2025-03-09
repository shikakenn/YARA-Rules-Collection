/* FIVE EYES ------------------------------------------------------------------------------- */

rule FiveEyes_QUERTY_Malwareqwerty_20121 {
    meta:
        id = "4iyW4oeviZIctWO8ABji6n"
        fingerprint = "v1_sha256_e2660abf4959bc57bcf9d95d974cd20718d5d27f371109cb4526cee208544530"
        version = "1.0"
        date = "2015/01/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FiveEyes QUERTY Malware - file 20121.xml"
        category = "INFO"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        hash = "8263fb58350f3b1d3c4220a602421232d5e40726"

    strings:
        $s0 = "<configFileName>20121_cmdDef.xml</configFileName>" fullword ascii
        $s1 = "<name>20121.dll</name>" fullword ascii
        $s2 = "<codebase>\"Reserved for future use.\"</codebase>" fullword ascii
        $s3 = "<plugin xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceS" ascii
        $s4 = "<platform type=\"1\">" fullword ascii
        $s5 = "</plugin>" fullword ascii
        $s6 = "</pluginConfig>" fullword ascii
        $s7 = "<pluginConfig>" fullword ascii
        $s8 = "</platform>" fullword ascii
        $s9 = "</lpConfig>" fullword ascii
        $s10 = "<lpConfig>" fullword ascii
    condition:
        9 of them
}

rule FiveEyes_QUERTY_Malwaresig_20123_sys {
    meta:
        id = "6nE0dtXjkJtIst3ZQWsPVl"
        fingerprint = "v1_sha256_881af0e2ff8fad2bca2ae05ad63b5185356181685daafa7a1b9992a1de017c9e"
        version = "1.0"
        date = "2015/01/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FiveEyes QUERTY Malware - file 20123.sys.bin"
        category = "INFO"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        hash = "a0f0087bd1f8234d5e847363d7e15be8a3e6f099"

    strings:
        $s0 = "20123.dll" fullword ascii
        $s1 = "kbdclass.sys" fullword wide
        $s2 = "IoFreeMdl" fullword ascii
        $s3 = "ntoskrnl.exe" fullword ascii
        $s4 = "KfReleaseSpinLock" fullword ascii
    condition:
        all of them
}

rule FiveEyes_QUERTY_Malwaresig_20123_cmdDef {
    meta:
        id = "7jfJBJzt8Acrz65auSKvb9"
        fingerprint = "v1_sha256_84776764caa79ad68f2dd0d2f890821c75f2efba7c46d674110ba870a40a372a"
        version = "1.0"
        date = "2015/01/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FiveEyes QUERTY Malware - file 20123_cmdDef.xml"
        category = "INFO"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        hash = "7b08fc77629f6caaf8cc4bb5f91be6b53e19a3cd"

    strings:
        $s0 = "<shortDescription>Keystroke Collector</shortDescription>" fullword ascii
        $s1 = "This plugin is the E_Qwerty Kernel Mode driver for logging keys.</description>" fullword ascii
        $s2 = "<commands/>" fullword ascii
        $s3 = "</version>" fullword ascii
        $s4 = "<associatedImplantId>20121</associatedImplantId>" fullword ascii
        $s5 = "<rightsRequired>System or Administrator (if Administrator, I think the DriverIns" ascii
        $s6 = "<platforms>Windows NT, Windows 2000, Windows XP (32/64 bit), Windows 2003 (32/64" ascii
        $s7 = "<projectpath>plugin/Collection</projectpath>" fullword ascii
        $s8 = "<dllDepend>None</dllDepend>" fullword ascii
        $s9 = "<minorType>0</minorType>" fullword ascii
        $s10 = "<pluginname>E_QwertyKM</pluginname>" fullword ascii
        $s11 = "</comments>" fullword ascii
        $s12 = "<comments>" fullword ascii
        $s13 = "<majorType>1</majorType>" fullword ascii
        $s14 = "<files>None</files>" fullword ascii
        $s15 = "<poc>Erebus</poc>" fullword ascii
        $s16 = "</plugin>" fullword ascii
        $s17 = "<team>None</team>" fullword ascii
        $s18 = "<?xml-stylesheet type=\"text/xsl\" href=\"../XSLT/pluginHTML.xsl\"?>" fullword ascii
        $s19 = "<pluginsDepend>U_HookManager v1.0, Kernel Covert Store v1.0</pluginsDepend>" fullword ascii
        $s20 = "<plugin id=\"20123\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi" ascii
    condition:
        14 of them
}

rule FiveEyes_QUERTY_Malwaresig_20121_dll {
    meta:
        id = "v6mwBkRso6CDVYQlNYBtI"
        fingerprint = "v1_sha256_e735a7c26652cbf2bccac80a14568a3582b254ae25e2db56a46c09a714650611"
        version = "1.0"
        date = "2015/01/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FiveEyes QUERTY Malware - file 20121.dll.bin"
        category = "INFO"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        hash = "89504d91c5539a366e153894c1bc17277116342b"

    strings:
        $s0 = "WarriorPride\\production2.0\\package\\E_Wzowski" ascii
        $s1 = "20121.dll" fullword ascii
    condition:
        all of them
}
rule FiveEyes_QUERTY_Malwareqwerty_20123 {
    meta:
        id = "7kSELFtfCr4rI0fZJ3FVVF"
        fingerprint = "v1_sha256_918462399af78b16a8214ceb1d39db554e3136efd4bc643353f0727e4a162516"
        version = "1.0"
        date = "2015/01/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FiveEyes QUERTY Malware - file 20123.xml"
        category = "INFO"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        hash = "edc7228b2e27df9e7ff9286bddbf4e46adb51ed9"

    strings:
        $s0 = "<!-- edited with XMLSPY v5 rel. 4 U (http://www.xmlspy.com) by TEAM (RENEGADE) -" ascii
        $s1 = "<configFileName>20123_cmdDef.xml</configFileName>" fullword ascii
        $s2 = "<name>20123.sys</name>" fullword ascii
        $s3 = "<plugin xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceS" ascii
        $s4 = "<codebase>/bin/i686-pc-win32/debug</codebase>" fullword ascii
        $s5 = "<platform type=\"1\">" fullword ascii
        $s6 = "</plugin>" fullword ascii
        $s7 = "</pluginConfig>" fullword ascii
        $s8 = "<pluginConfig>" fullword ascii
        $s9 = "</platform>" fullword ascii
        $s10 = "</lpConfig>" fullword ascii
        $s11 = "<lpConfig>" fullword ascii
    condition:
        9 of them
}

rule FiveEyes_QUERTY_Malwaresig_20120_dll {
    meta:
        id = "18TCs4zH1bhhoWeItZFt49"
        fingerprint = "v1_sha256_a90b7560d7918a61479aa63c0fa85ddda1d5dda60e87b5d297cb56598c37e254"
        version = "1.0"
        date = "2015/01/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FiveEyes QUERTY Malware - file 20120.dll.bin"
        category = "INFO"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        hash = "6811bfa3b8cda5147440918f83c40237183dbd25"

    strings:
        $s0 = "\\QwLog_%d-%02d-%02d-%02d%02d%02d.txt" fullword wide
        $s1 = "\\QwLog_%d-%02d-%02d-%02d%02d%02d.xml" fullword wide
        $s2 = "Failed to send the EQwerty_driverStatusCommand to the implant." fullword ascii
        $s3 = "- Log Used (number of windows) - %d" fullword wide
        $s4 = "- Log Limit (number of windows) - %d" fullword wide
        $s5 = "Process or User Default Language" fullword wide
        $s6 = "Windows 98/Me, Windows NT 4.0 and later: Vietnamese" fullword wide
        $s7 = "- Logging of keystrokes is switched ON" fullword wide
        $s8 = "- Logging of keystrokes is switched OFF" fullword wide
        $s9 = "Qwerty is currently logging active windows with titles containing the fo" wide
        $s10 = "Windows 95, Windows NT 4.0 only: Korean (Johab)" fullword wide
        $s11 = "FAILED to get Qwerty Status" fullword wide
        $s12 = "- Successfully retrieved Log from Implant." fullword wide
        $s13 = "- Logging of all Windows is toggled ON" fullword wide
        $s14 = "- Logging of all Windows is toggled OFF" fullword wide
        $s15 = "Qwerty FAILED to retrieve window list." fullword wide
        $s16 = "- UNSUCCESSFUL Log Retrieval from Implant." fullword wide
        $s17 = "The implant failed to return a valid status" fullword ascii
        $s18 = "- Log files were NOT generated!" fullword wide
        $s19 = "Windows 2000/XP: Armenian. This is Unicode only." fullword wide
        $s20 = "- This machine is using a PS/2 Keyboard - Continue on using QWERTY" fullword wide
    condition:
        10 of them
}

rule FiveEyes_QUERTY_Malwaresig_20120_cmdDef {
    meta:
        id = "7kz6p0SiKQgUal19FFv9HH"
        fingerprint = "v1_sha256_9c336a09adb5fdf3149e5d0ad716cb854f95effa4ce4dfe3e75f43031e4903ff"
        version = "1.0"
        date = "2015/01/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FiveEyes QUERTY Malware - file 20120_cmdDef.xml"
        category = "INFO"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        hash = "cda9ceaf0a39d6b8211ce96307302a53dfbd71ea"

    strings:
        $s0 = "This PPC gets the current keystroke log." fullword ascii
        $s1 = "This command will add the given WindowTitle to the list of Windows to log keys f" ascii
        $s2 = "This command will remove the WindowTitle corresponding to the given window title" ascii
        $s3 = "This command will return the current status of the Keyboard Logger (Whether it i" ascii
        $s4 = "This command Toggles logging of all Keys. If allkeys is toggled all keystrokes w" ascii
        $s5 = "<definition>Turn logging of all keys on|off</definition>" fullword ascii
        $s6 = "<name>Get Keystroke Log</name>" fullword ascii
        $s7 = "<description>Keystroke Logger Lp Plugin</description>" fullword ascii
        $s8 = "<definition>display help for this function</definition>" fullword ascii
        $s9 = "This command will switch ON Logging of keys. All keys taht are entered to a acti" ascii
        $s10 = "Set the log limit (in number of windows)" fullword ascii
        $s11 = "<example>qwgetlog</example>" fullword ascii
        $s12 = "<aliasName>qwgetlog</aliasName>" fullword ascii
        $s13 = "<definition>The title of the Window whose keys you wish to Log once it becomes a" ascii
        $s14 = "This command will switch OFF Logging of keys. No keystrokes will be captured" fullword ascii
        $s15 = "<definition>The title of the Window whose keys you no longer whish to log</defin" ascii
        $s16 = "<command id=\"32\">" fullword ascii
        $s17 = "<command id=\"3\">" fullword ascii
        $s18 = "<command id=\"7\">" fullword ascii
        $s19 = "<command id=\"1\">" fullword ascii
        $s20 = "<command id=\"4\">" fullword ascii
    condition:
        10 of them
}

rule FiveEyes_QUERTY_Malwareqwerty_20120 {
    meta:
        id = "VHKR6ngnZsEmCxLV3WePF"
        fingerprint = "v1_sha256_7d2617e0ee41ea475608757594cba8ae93f2dbb09b5d01d1fa3324b32ebb8aa0"
        version = "1.0"
        date = "2015/01/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FiveEyes QUERTY Malware - file 20120.xml"
        category = "INFO"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        hash = "597082f05bfd3225587d480c30f54a7a1326a892"

    strings:
        $s0 = "<configFileName>20120_cmdDef.xml</configFileName>" fullword ascii
        $s1 = "<name>20120.dll</name>" fullword ascii
        $s2 = "<codebase>\"Reserved for future use.\"</codebase>" fullword ascii
        $s3 = "<plugin xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceS" ascii
        $s4 = "<platform type=\"1\">" fullword ascii
        $s5 = "</plugin>" fullword ascii
        $s6 = "</pluginConfig>" fullword ascii
        $s7 = "<pluginConfig>" fullword ascii
        $s8 = "</platform>" fullword ascii
        $s9 = "</lpConfig>" fullword ascii
        $s10 = "<lpConfig>" fullword ascii
    condition:
        all of them
}

rule FiveEyes_QUERTY_Malwaresig_20121_cmdDef {
    meta:
        id = "6IHctaNNPM3VQVs2y7laqq"
        fingerprint = "v1_sha256_d73f0e964bd57ed3a2cd782ac204a2b82a9b334e33d64dc61e6414654d7c38d3"
        version = "1.0"
        date = "2015/01/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FiveEyes QUERTY Malware - file 20121_cmdDef.xml"
        category = "INFO"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        hash = "64ac06aa4e8d93ea6063eade7ce9687b1d035907"

    strings:
        $s0 = "<shortDescription>Keystroke Logger Plugin.</shortDescription>" fullword ascii
        $s1 = "<message>Failed to get File Time</message>" fullword ascii
        $s2 = "<description>Keystroke Logger Plugin.</description>" fullword ascii
        $s3 = "<message>Failed to set File Time</message>" fullword ascii
        $s4 = "</commands>" fullword ascii
        $s5 = "<commands>" fullword ascii
        $s6 = "</version>" fullword ascii
        $s7 = "<associatedImplantId>20120</associatedImplantId>" fullword ascii
        $s8 = "<message>No Comms. with Driver</message>" fullword ascii
        $s9 = "</error>" fullword ascii
        $s10 = "<message>Invalid File Size</message>" fullword ascii
        $s11 = "<platforms>Windows (User/Win32)</platforms>" fullword ascii
        $s12 = "<message>File Size Mismatch</message>" fullword ascii
        $s13 = "<projectpath>plugin/Utility</projectpath>" fullword ascii
        $s14 = "<pluginsDepend>None</pluginsDepend>" fullword ascii
        $s15 = "<dllDepend>None</dllDepend>" fullword ascii
        $s16 = "<pluginname>E_QwertyIM</pluginname>" fullword ascii
        $s17 = "<rightsRequired>None</rightsRequired>" fullword ascii
        $s18 = "<minorType>0</minorType>" fullword ascii
        $s19 = "<code>00001002</code>" fullword ascii
        $s20 = "<code>00001001</code>" fullword ascii
    condition:
        12 of them
}
