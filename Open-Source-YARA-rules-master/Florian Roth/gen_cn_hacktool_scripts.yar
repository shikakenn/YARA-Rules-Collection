/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-06-13
    Identifier: CN-Tools Scripts
    Reference: Diclosed hacktool set at http://w2op.us/ (Mirror: http://tools.zjqhr.com) 
*/


rule CN_Tools_xbat {
    meta:
        id = "4homV4VE6KirViHsCUsnty"
        fingerprint = "v1_sha256_c6dae76bbda7b43eef348c61e1330405923baf724f1aa5d2b51132dde89248fe"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file xbat.vbs"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "a7005acda381a09803b860f04d4cae3fdb65d594"

    strings:
        $s0 = "ws.run \"srss.bat /start\",0 " fullword ascii 
        $s1 = "Set ws = Wscript.CreateObject(\"Wscript.Shell\")" fullword ascii 
    condition:
        uint16(0) == 0x6553 and filesize < 0KB and all of them
}

rule CN_Tools_Temp {
    meta:
        id = "2LZW7PHjqUwesQwgItHVeY"
        fingerprint = "v1_sha256_05fd1cb3f7c8b96ccf824013c130a0b21f43724463f8658e23239d009be7f4fe"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Temp.war"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "c3327ef63b0ed64c4906e9940ef877c76ebaff58"

    strings:
        $s0 = "META-INF/context.xml<?xml version=\"1.0\" encoding=\"UTF-8\"?>" fullword ascii 
        $s1 = "browser.jsp" fullword ascii 
        $s3 = "cmd.jsp" fullword ascii
        $s4 = "index.jsp" fullword ascii
    condition:
        uint16(0) == 0x4b50 and filesize < 203KB and all of them
}

rule CN_Tools_srss {
    meta:
        id = "2y9q5iQ2l6OeizM2bYKdg2"
        fingerprint = "v1_sha256_e01fd60adc32be26b0940ecc127a17bfcfe2ebfcf6cefea76ba6adc61d3c18d4"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file srss.bat"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "092ab0797947692a247fe80b100fb4df0f9c37a0"

    strings:
        $s0 = "srss.exe -idx 0 -ip"
        $s1 = "-port 21 -logfilter \"_USER ,_P" ascii 
    condition:
        filesize < 100 and all of them
}

rule dll_UnReg {
    meta:
        id = "470jWgf8A2BK5Gvim4SaIC"
        fingerprint = "v1_sha256_0e534e475a5b4338aa53bea09325dd63a3d451a13b46a70b5208cabd2deecabe"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file UnReg.bat"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "d5e24ba86781c332d0c99dea62f42b14e893d17e"

    strings:
        $s0 = "regsvr32.exe /u C:\\windows\\system32\\PacketX.dll" fullword ascii 
        $s1 = "del /F /Q C:\\windows\\system32\\PacketX.dll" fullword ascii 
    condition:
        filesize < 1KB and 1 of them
}

rule dll_Reg {
    meta:
        id = "50uovZ4uLrzReiEpni9Ygr"
        fingerprint = "v1_sha256_db2032d5689f9fcfc446d5ebe8a6d28c6dbd8bcd1d93769ec969d76f8add4f9d"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Reg.bat"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "cb8a92fe256a3e5b869f9564ecd1aa9c5c886e3f"

    strings:
        $s0 = "copy PacketX.dll C:\\windows\\system32\\PacketX.dll" fullword ascii 
        $s1 = "regsvr32.exe C:\\windows\\system32\\PacketX.dll" fullword ascii 
    condition:
        filesize < 1KB and all of them
}

rule sbin_squid {
    meta:
        id = "1NqQOGlQ4AQRvmMYsN3LID"
        fingerprint = "v1_sha256_c440bcfda55f926354ea5e462fe1e6a0e9e9585bb1c1539c0aa0588405a46105"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file squid.bat"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "8b795a8085c3e6f3d764ebcfe6d59e26fdb91969"

    strings:
        $s0 = "del /s /f /q" fullword ascii
        $s1 = "squid.exe -z" fullword ascii
        $s2 = "net start Squid" fullword ascii 
        $s3 = "net stop Squid" fullword ascii 
    condition:
        filesize < 1KB and all of them
}

rule sql1433_creck {
    meta:
        id = "1Pq47UwBCzWYBsAmkctw86"
        fingerprint = "v1_sha256_2d9ff5f130d625450e7de41832695839f0427a6186569280a224f20e89fe1d8a"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file creck.bat"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "189c11a3b268789a3fbcfac3bd4e03cbfde87b1d"

    strings:
        $s0 = "start anhao3.exe -i S.txt -p  pass3.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii 
        $s1 = "start anhao1.exe -i S.txt -p  pass1.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii 
        $s2 = "start anhao2.exe -i S.txt -p  pass2.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii 
    condition:
        uint16(0) == 0x7473 and filesize < 1KB and 1 of them
}

rule sql1433_Start {
    meta:
        id = "6AheBegberOyAMoMxb2LkT"
        fingerprint = "v1_sha256_b7dfc2b04e838fa3a71487287a50e183443eb62b69cd23494294f231b43baf2f"
        version = "1.0"
        date = "2015-06-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Chinese Hacktool Set - file Start.bat"
        category = "INFO"
        reference = "http://tools.zjqhr.com/"
        hash = "bd4be10f4c3a982647b2da1a8fb2e19de34eaf01"

    strings:
        $s1 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii 
        $s2 = "start creck.bat" fullword ascii 
        $s3 = "del s1.txt" fullword ascii
        $s4 = "del Result.txt" fullword ascii
        $s5 = "del s.TXT" fullword ascii
        $s6 = "mode con cols=48 lines=20" fullword ascii
    condition:
        filesize < 1KB and 2 of them
}
