rule agent_tesla
{
    meta:
        id = "1wbC5wOU60otf1QAXSEnmC"
        fingerprint = "v1_sha256_3945754129dcc58e0abfd7485f5ff0c0afdd1078ae2cf164ca8f59a6f79db1be"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "Stormshield"
        description = "Detecting HTML strings used by Agent Tesla malware"
        category = "INFO"

    strings:
        $html_username    = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_pc_name     = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_os_name     = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_clipboard   = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

    condition:
        3 of them
}

rule AgentTesla
{
    meta:
        id = "3JV6Bfi2H1cfCMIVW0kCnS"
        fingerprint = "v1_sha256_1bf9b26c4cf87e674ddffabe40aba5a45499c6a04d4ff3e43c3cda4cbcb4d188"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "AgentTesla Payload"
        category = "INFO"
        cape_type = "AgentTesla Payload"

    strings:
        $string1 = "smtp" wide
        $string2 = "appdata" wide
        $string3 = "76487-337-8429955-22614" wide
        $string4 = "yyyy-MM-dd HH:mm:ss" wide
        //$string5 = "%site_username%" wide
        $string6 = "webpanel" wide
        $string7 = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:" wide
        $string8 = "<br>IP Address&nbsp;&nbsp;:" wide

        $agt1 = "IELibrary.dll" ascii
        $agt2 = "C:\\Users\\Admin\\Desktop\\IELibrary\\IELibrary\\obj\\Debug\\IELibrary.pdb" ascii
        $agt3 = "GetSavedPasswords" ascii
        $agt4 = "GetSavedCookies" ascii
    condition:
        uint16(0) == 0x5A4D and (all of ($string*) or 3 of ($agt*))
}

rule AgentTeslaV2 {
    meta:
        id = "1RcnutZQBVaXOzqs7NfnYy"
        fingerprint = "v1_sha256_b45296b3b94fa1ff32de48c94329a17402461fb6696e9390565c4dba9738ed78"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "ditekshen"
        description = "AgenetTesla Type 2 Keylogger payload"
        category = "INFO"
        cape_type = "AgentTesla Payload"

    strings:
        $s1 = "get_kbHook" ascii
        $s2 = "GetPrivateProfileString" ascii
        $s3 = "get_OSFullName" ascii
        $s4 = "get_PasswordHash" ascii
        $s5 = "remove_Key" ascii
        $s6 = "FtpWebRequest" ascii
        $s7 = "logins" fullword wide
        $s8 = "keylog" fullword wide
        $s9 = "1.85 (Hash, version 2, native byte-order)" wide

        $cl1 = "Postbox" fullword ascii
        $cl2 = "BlackHawk" fullword ascii
        $cl3 = "WaterFox" fullword ascii
        $cl4 = "CyberFox" fullword ascii
        $cl5 = "IceDragon" fullword ascii
        $cl6 = "Thunderbird" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*)) or (6 of ($s*) and 2 of ($cl*))
}

rule AgentTeslaV3 {
    meta:
        id = "58mTIjm4aKP0RXwNIRp8FK"
        fingerprint = "v1_sha256_26c4fa0ce8de6982eb599f3872e8ab2a6e83da4741db7f3500c94e0a8fe5d459"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "ditekshen"
        description = "AgentTeslaV3 infostealer payload"
        category = "INFO"
        cape_type = "AgentTesla payload"

    strings:
        $s1 = "get_kbok" fullword ascii
        $s2 = "get_CHoo" fullword ascii
        $s3 = "set_passwordIsSet" fullword ascii
        $s4 = "get_enableLog" fullword ascii
        $s5 = "bot%telegramapi%" wide
        $s6 = "KillTorProcess" fullword ascii
        $s7 = "GetMozilla" ascii
        $s8 = "torbrowser" wide
        $s9 = "%chatid%" wide
        $s10 = "logins" fullword wide
        $s11 = "credential" fullword wide
        $s12 = "AccountConfiguration+" wide
        $s13 = "<a.+?href\\s*=\\s*([\"'])(?<href>.+?)\\1[^>]*>" fullword wide
        $s14 = "set_Lenght" fullword ascii
        $s15 = "get_Keys" fullword ascii
        $s16 = "set_AllowAutoRedirect" fullword ascii
        $s17 = "set_wtqQe" fullword ascii
        $s18 = "set_UseShellExecute" fullword ascii
        $s19 = "set_IsBodyHtml" fullword ascii
        $s20 = "set_FElvMn" fullword ascii
        $s21 = "set_RedirectStandardOutput" fullword ascii

        $g1 = "get_Clipboard" fullword ascii
        $g2 = "get_Keyboard" fullword ascii
        $g3 = "get_Password" fullword ascii
        $g4 = "get_CtrlKeyDown" fullword ascii
        $g5 = "get_ShiftKeyDown" fullword ascii
        $g6 = "get_AltKeyDown" fullword ascii

        $m1 = "yyyy-MM-dd hh-mm-ssCookieapplication/zipSCSC_.jpegScreenshotimage/jpeg/log.tmpKLKL_.html<html></html>Logtext/html[]Time" ascii
        $m2 = "%image/jpg:Zone.Identifier\\tmpG.tmp%urlkey%-f \\Data\\Tor\\torrcp=%PostURL%127.0.0.1POST+%2B" ascii
        $m3 = ">{CTRL}</font>Windows RDPcredentialpolicyblobrdgchrome{{{0}}}CopyToComputeHashsha512CopySystemDrive\\WScript.ShellRegReadg401" ascii
        $m4 = "%startupfolder%\\%insfolder%\\%insname%/\\%insfolder%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%insregname%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\RunTruehttp" ascii
        $m5 = "\\WindowsLoad%ftphost%/%ftpuser%%ftppassword%STORLengthWriteCloseGetBytesOpera" ascii
    condition:
        (uint16(0) == 0x5a4d and (8 of ($s*) or (6 of ($s*) and 4 of ($g*)))) or (2 of ($m*))
}

rule AgentTeslaXor
{
    meta:
        id = "7Rtgb3N6zNL3um86SeoyEW"
        fingerprint = "v1_sha256_54581e83e5fa13fae4bda74016b3fa1d18c92e2659f493ebe54d70fd5f77bba5"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "AgentTesla xor-based config decoding"
        category = "INFO"
        cape_type = "AgentTesla Payload"

    strings:
        $decode = {06 91 06 61 20 [4] 61 D2 9C 06 17 58 0A 06 7E [4] 8E 69 FE 04 2D ?? 2A}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule AgentTeslaV4
{
    meta:
        id = "6pzeJlsaSjSYei7blAd4fD"
        fingerprint = "v1_sha256_0a39036f408728ab312a54ff3354453d171424f57f9a8f3b42af867be3037ca9"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "AgentTesla Payload"
        category = "INFO"
        cape_type = "AgentTesla Payload"
        packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"

    strings:
        $decode1 = {(07|FE 0C 01 00) (07|FE 0C 01 00) 8E 69 (17|20 01 00 00 00) 63 8F ?? 00 00 01 25 47 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A D2 61 D2 52}
        $decode2 = {(07|FE 0C 01 00) (08|FE 0C 02 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (11 07|FE 0C 07 00) 91 (06|FE 0C 00 00) (1A|20 04 00 00 00) 58 4A 61 D2 61 D2 52}
        $decode3 = {(07|FE 0C 01 00) (11 07|FE 0C 07 00) 8F ?? 00 00 01 25 47 (07|FE 0C 01 00) (08|FE 0C 02 00) 91 61 D2 52}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule AgentTeslaV4JIT
{
    meta:
        id = "5cJBQ1LCGnldraE3OvJ8OL"
        fingerprint = "v1_sha256_8f7144d2a989ce8d291af926b292f5f0f7772e707b0e49797eba13ecf91b90bc"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "AgentTesla JIT-compiled native code"
        category = "INFO"
        cape_type = "AgentTesla Payload"
        packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"

    strings:
        $decode1 = {8B 01 8B 40 3C FF 50 10 8B C8 E8 [4] 89 45 CC B8 1A 00 00 00}
        $decode2 = {83 F8 18 75 2? 8B [2-5] D1 F8}
        $decode3 = {8D 4C 0? 08 0F B6 01 [0-3] 0F B6 5? 04 33 C2 88 01 B8 19 00 00 00}
    condition:
        2 of them
}

rule AgentTeslaV5 {
    meta:
        id = "2Vq5CF3md7ZKyKGloP0v6R"
        fingerprint = "v1_sha256_e121d0595207185a1dd531def1ebe1bc59d377934ef4035f1444319826a8b192"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "ClaudioWayne"
        description = "AgentTeslaV5 infostealer payload"
        category = "INFO"
        cape_type = "AgentTesla payload"
        sample = "893f4dc8f8a1dcee05a0840988cf90bc93c1cda5b414f35a6adb5e9f40678ce9"

    strings:
        $template1 = "<br>User Name: " fullword wide
        $template2 = "<br>Username: " fullword wide
        $template3 = "<br>RAM: " fullword wide
        $template4 = "<br>Password: " fullword wide
        $template5 = "<br>OSFullName: " fullword wide
        $template6 = "<br><hr>Copied Text: <br>" fullword wide
        $template7 = "<br>CPU: " fullword wide
        $template8 = "<br>Computer Name: " fullword wide
        $template9 = "<br>Application: " fullword wide

        $chromium_browser1 = "Comodo\\Dragon\\User Data" fullword wide
        $chromium_browser2 = "Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer" fullword wide
        $chromium_browser3 = "Google\\Chrome\\User Data" fullword wide
        $chromium_browser4 = "Elements Browser\\User Data" fullword wide
        $chromium_browser5 = "Yandex\\YandexBrowser\\User Data" fullword wide
        $chromium_browser6 = "MapleStudio\\ChromePlus\\User Data" fullword wide

        $mozilla_browser1 = "\\Mozilla\\SeaMonkey\\" fullword wide
        $mozilla_browser2 = "\\K-Meleon\\" fullword wide
        $mozilla_browser3 = "\\NETGATE Technologies\\BlackHawk\\" fullword wide
        $mozilla_browser4 = "\\Thunderbird\\" fullword wide
        $mozilla_browser5 = "\\8pecxstudios\\Cyberfox\\" fullword wide
        $mozilla_browser6 = "360Chrome\\Chrome\\User Data" fullword wide
        $mozilla_browser7 = "\\Mozilla\\Firefox\\" fullword wide

        $database1 = "Berkelet DB" fullword wide
        $database2 = " 1.85 (Hash, version 2, native byte-order)" fullword wide
        $database3 = "00061561" fullword wide
        $database4 = "key4.db" fullword wide
        $database5 = "key3.db" fullword wide
        $database6 = "global-salt" fullword wide
        $database7 = "password-check" fullword wide

        $software1 = "\\FileZilla\\recentservers.xml" fullword wide
        $software2 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide
        $software3 = "\\The Bat!" fullword wide
        $software4 = "\\Apple Computer\\Preferences\\keychain.plist" fullword wide
        $software5 = "\\MySQL\\Workbench\\workbench_user_data.dat" fullword wide
        $software6 = "\\Trillian\\users\\global\\accounts.dat" fullword wide
        $software7 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" fullword wide
        $software8 = "FTP Navigator\\Ftplist.txt" fullword wide
        $software9 = "NordVPN" fullword wide
        $software10 = "JDownloader 2.0\\cfg" fullword wide
    condition:
        uint16(0) == 0x5a4d and 4 of ($template*) and 3 of ($chromium_browser*) and 3 of ($mozilla_browser*) and 3 of ($database*) and 5 of ($software*)
}
