/*
    Yara Rule to detect Backspace Malware mentioned in FireEye APT30 Report
    https://www.fireeye.com/blog/threat-research/2015/04/apt_30_and_the_mecha.html

    13.04.2015 
    v1.0
    please report back false positives via the 'issue' section of the LOKI github page
*/

rule APT30_Generic_H {
    meta:
        id = "5eAlrfjjYSTmkHjUsofXO3"
        fingerprint = "v1_sha256_bcdae342a2e54ad5284e72c3a2c31d5e3fc54f6c961159ed0096254c5226f338"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file db3e5c2f2ce07c2d3fa38d6fc1ceb854"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash1 = "2a4c8752f3e7fde0139421b8d5713b29c720685d"
        hash2 = "4350e906d590dca5fcc90ed3215467524e0a4e3d"

    strings:
        $s0 = "\\Temp1020.txt" fullword ascii
        $s1 = "Xmd.Txe" fullword ascii
        $s2 = "\\Internet Exp1orer" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_2 {
    meta:
        id = "27SacrfxIEnHle4ToyOh5P"
        fingerprint = "v1_sha256_e34dbb90fc868b0619d3d2aa1b6176252836a6ae72e6f52b1eba632054f7c272"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file c4dec6d69d8035d481e4f2c86f580e81"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "0359ffbef6a752ee1a54447b26e272f4a5a35167"

    strings:
        $s0 = "ForZRLnkWordDlg.EXE" fullword wide
        $s1 = "ForZRLnkWordDlg Microsoft " fullword wide
        $s9 = "ForZRLnkWordDlg 1.0 " fullword wide
        $s11 = "ForZRLnkWordDlg" fullword wide
        $s12 = " (C) 2011" fullword wide
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_3 {
    meta:
        id = "kPlU5d91NjbHxKxbOgSq8"
        fingerprint = "v1_sha256_ee61ec1fdf27fa21bcc235fce0ab8dc74968b39a747648ce828fb4826cf1d234"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 59e055cee87d8faf6f701293e5830b5a"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "d0320144e65c9af0052f8dee0419e8deed91b61b"

    strings:
        $s5 = "Software\\Mic" ascii
        $s6 = "HHOSTR" ascii
        $s9 = "ThEugh" fullword ascii
        $s10 = "Moziea/" ascii
        $s12 = "%s%s(X-" ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_C {
    meta:
        id = "3cCcRynMURJOAlXy90NxQ7"
        fingerprint = "v1_sha256_b969565eac3b6f548318aae4edc8d8851f522a6c263bcaf2a466ff0ca9af78a4"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 0c4fcef3b583d0ffffc2b14b9297d3a4"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash1 = "8667f635fe089c5e2c666b3fe22eaf3ff8590a69"
        hash2 = "0c4fcef3b583d0ffffc2b14b9297d3a4"
        hash3 = "37aee58655f5859e60ece6b249107b87"
        hash4 = "4154548e1f8e9e7eb39d48a4cd75bcd1"
        hash5 = "a2e0203e665976a13cdffb4416917250"
        hash6 = "b4ae0004094b37a40978ef06f311a75e"
        hash7 = "e39756bc99ee1b05e5ee92a1cdd5faf4"

    strings:
        $s0 = "MYUSER32.dll" fullword ascii
        $s1 = "MYADVAPI32.dll" fullword ascii
        $s2 = "MYWSOCK32.dll" fullword ascii
        $s3 = "MYMSVCRT.dll" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_4 {
    meta:
        id = "49Kia9w9Hvo0vpOZHzn2mm"
        fingerprint = "v1_sha256_ec9542acb583bd5812d561bea70e89e0fcddc1eaef14d3ea5b8ad29711ed17ae"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 6ba315275561d99b1eb8fc614ff0b2b3"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "75367d8b506031df5923c2d8d7f1b9f643a123cd"

    strings:
        $s0 = "GetStartupIn" ascii
        $s1 = "enMutex" ascii
        $s2 = "tpsvimi" ascii
        $s3 = "reateProcesy" ascii
        $s5 = "FreeLibr1y*S" ascii
        $s6 = "foAModuleHand" ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_5 {
    meta:
        id = "LgZfUyl3flpLq022Fw04e"
        fingerprint = "v1_sha256_3738076d97bf19404bad20c2419eae83dd2b65400d5bd135ffe73362c008de9b"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file ebf42e8b532e2f3b19046b028b5dfb23"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "1a2dd2a0555dc746333e7c956c58f7c4cdbabd4b"

    strings:
        $s0 = "Version 4.7.3001" fullword wide
        $s1 = "Copyright (c) Microsoft Corporation 2004" fullword wide
        $s3 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the U" wide
        $s7 = "msmsgs" fullword wide
        $s10 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_6 {
    meta:
        id = "5Hn3hPewBOnuVMdomhiRej"
        fingerprint = "v1_sha256_139719139056f575967629f0153e0a05239bc26f61f6d4324cfb6a816518c3df"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file ee1b23c97f809151805792f8778ead74"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "00e69b059ad6b51b76bc476a115325449d10b4c0"

    strings:
        $s0 = "GreateProcessA" fullword ascii
        $s1 = "Ternel32.dll" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_7 {
    meta:
        id = "52aYxPkXwgpeQW8jkHDoDg"
        fingerprint = "v1_sha256_f7922d795bc92714a9ef4861bc9c4ac9921a73749e3aa1d5f7dbc3c991fe7145"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 74b87086887e0c67ffb035069b195ac7"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "868d1f4c106a08bd2e5af4f23139f0e0cd798fba"

    strings:
        $s0 = "datain" fullword ascii
        $s3 = "C:\\Prog" ascii
        $s4 = "$LDDATA$" ascii
        $s5 = "Maybe a Encrypted Flash" fullword ascii
        $s6 = "Jean-loup Gailly" ascii
        $s8 = "deflate 1.1.3 Copyright" ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_E {
    meta:
        id = "3fWCFvnKwnFugN4O63cHoB"
        fingerprint = "v1_sha256_5ccf1f1334dc300d13aa8dbc080d2d839815d102958fde2b8709c11f522412fd"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 8ff473bedbcc77df2c49a91167b1abeb"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash1 = "1dbb584e19499e26398fb0a7aa2a01b7"
        hash2 = "572c9cd4388699347c0b2edb7c6f5e25"
        hash3 = "8ff473bedbcc77df2c49a91167b1abeb"
        hash4 = "a813eba27b2166620bd75029cc1f04b0"
        hash5 = "b5546842e08950bc17a438d785b5a019"

    strings:
        $s0 = "Nkfvtyvn}" ascii
        $s6 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_8 {
    meta:
        id = "6BihFHqG2hnkqpPbwJ5Dh6"
        fingerprint = "v1_sha256_bff21d517e97d2b13dff2b5ebc9a5b82b8f7635943c89f992b41d269623cd498"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 44b98f22155f420af4528d17bb4a5ec8"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "9531e21652143b8b129ab8c023dc05fef2a17cc3"

    strings:
        $s0 = "ateProcessA" ascii
        $s1 = "Ternel32.dllFQ" fullword ascii
        $s2 = "StartupInfoAModuleHand" fullword ascii
        $s3 = "OpenMutex" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_B {
    meta:
        id = "7fAns7M6QBPdUePyIoFkky"
        fingerprint = "v1_sha256_527c823607836f138369224b7d8d492d36d9ab7a150e64fd5ebbaf99538d6d53"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 29395c528693b69233c1c12bef8a64b3"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash1 = "0fcb4ffe2eb391421ec876286c9ddb6c"
        hash2 = "29395c528693b69233c1c12bef8a64b3"
        hash3 = "4c6b21e98ca03e0ef0910e07cef45dac"
        hash4 = "550459b31d8dabaad1923565b7e50242"
        hash5 = "65232a8d555d7c4f7bc0d7c5da08c593"
        hash6 = "853a20f5fc6d16202828df132c41a061"
        hash7 = "ed151602dea80f39173c2f7b1dd58e06"

    strings:
        $s2 = "Moziea/4.0" ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_I {
    meta:
        id = "2nLhVcofuYXRLfxdCjmcES"
        fingerprint = "v1_sha256_e6f0edcbf6e0590c8b4a558142053d5938e86d13d65787f02336dc2a173d5963"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file fe211c7a081c1dac46e3935f7c614549"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash1 = "fe211c7a081c1dac46e3935f7c614549"
        hash2 = "8c9db773d387bf9b3f2b6a532e4c937c"

    strings:
        $s0 = "Copyright 2012 Google Inc. All rights reserved." fullword wide
        $s1 = "(Prxy%c-%s:%u)" fullword ascii
        $s2 = "Google Inc." fullword wide
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_9 {
    meta:
        id = "6TKGJ2PKqWqzvNWdWejshp"
        fingerprint = "v1_sha256_0c5465bdafcbca02f855a0cba1fbb4c19d8d21b714dbe777b942dcd1a7acb257"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file e3ae3cbc024e39121c87d73e87bb2210"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "442bf8690401a2087a340ce4a48151c39101652f"

    strings:
        $s0 = "\\Windo" ascii
        $s2 = "oHHOSTR" ascii
        $s3 = "Softwa]\\Mic" ascii
        $s4 = "Startup'T" ascii
        $s6 = "Ora\\%^" ascii
        $s7 = "\\Ohttp=r" ascii
        $s17 = "help32Snapshot0L" ascii
        $s18 = "TimUmoveH" ascii
        $s20 = "WideChc[lobalAl" ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}
rule APT30_Sample_10 {
    meta:
        id = "6KCUzOAFHvLAcJomG6n81s"
        fingerprint = "v1_sha256_5a6bd8223fbce133bd11b903edfd7f8ff5a436e26a47c048a5ac606ad4a0b564"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 8c713117af4ca6bbd69292a78069e75b"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "eb518cda3c4f4e6938aaaee07f1f7db8ee91c901"

    strings:
        $s0 = "Version 4.7.3001" fullword wide
        $s1 = "Copyright (c) Microsoft Corporation 2004" fullword wide
        $s2 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the U" wide
        $s3 = "!! Use Connect Method !!" fullword ascii
        $s4 = "(Prxy%c-%s:%u)" fullword ascii
        $s5 = "msmsgs" fullword wide
        $s18 = "(Prxy-No)" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_11 {
    meta:
        id = "5jCwzqenoKhvKrhHI2Twkf"
        fingerprint = "v1_sha256_5e86b53591caa7c783a946205a3d04f91c71294d844e6f6ee88c3bc78e603ea0"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file d97aace631d6f089595f5ce177f54a39"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "59066d5d1ee3ad918111ed6fcaf8513537ff49a6"

    strings:
        $s0 = "System\\CurrentControlSet\\control\\ComputerName\\ComputerName" fullword ascii
        $s1 = "msofscan.exe" fullword wide
        $s2 = "Mozilla/4.0 (compatible; MSIE 5.0; Win32)" fullword ascii
        $s3 = "Microsoft? is a registered trademark of Microsoft Corporation." fullword wide
        $s4 = "Windows XP Professional x64 Edition or Windows Server 2003" fullword ascii
        $s9 = "NetEagle_Scout - " fullword ascii
        $s10 = "Server 4.0, Enterprise Edition" fullword ascii
        $s11 = "Windows 3.1(Win32s)" fullword ascii
        $s12 = "%s%s%s %s" fullword ascii
        $s13 = "Server 4.0" fullword ascii
        $s15 = "Windows Millennium Edition" fullword ascii
        $s16 = "msofscan" fullword wide
        $s17 = "Eagle-Norton360-OfficeScan" fullword ascii
        $s18 = "Workstation 4.0" fullword ascii
        $s19 = "2003 Microsoft Office system" fullword wide
    condition:
        filesize < 250KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_12 {
    meta:
        id = "2TNh2KHTZT51sSrnsKRlSn"
        fingerprint = "v1_sha256_997c91267f956bd7d2a7edca9817ebc80bbf1eed944b3bc01cc8bb01927deb1e"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file c95cd106c1fecbd500f4b97566d8dc96"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "b02b5720ff0f73f01eb2ba029a58b645c987c4bc"

    strings:
        $s0 = "Richic" fullword ascii
        $s1 = "Accept: image/gif, */*" fullword ascii
        $s2 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
    condition:
        filesize < 250KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_13 {
    meta:
        id = "358e86VojbX31INnh7ht7i"
        fingerprint = "v1_sha256_cd5285e8b78493b64704cec21c13d0a017d66936aa8356cfea2aa77c6f87b9e7"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 95bb314fe8fdbe4df31a6d23b0d378bc"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "a359f705a833c4a4254443b87645fd579aa94bcf"

    strings:
        $s0 = "msofscan.exe" fullword wide
        $s1 = "Microsoft? is a registered trademark of Microsoft Corporation." fullword wide
        $s2 = "Microsoft Office Word Plugin Scan" fullword wide
        $s3 = "? 2006 Microsoft Corporation.  All rights reserved." fullword wide
        $s4 = "msofscan" fullword wide
        $s6 = "2003 Microsoft Office system" fullword wide
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_14 {
    meta:
        id = "39AxKKfzwwIG0EPvrzkIFI"
        fingerprint = "v1_sha256_fca338dac073d01b2f97679c380a54ff295740bb62e9dcaf0c0a4772dbbfc30a"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 6f931c15789d234881be8ae8ccfe33f4"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "b0740175d20eab79a5d62cdbe0ee1a89212a8472"

    strings:
        $s0 = "AdobeReader.exe" fullword wide
        $s1 = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" fullword ascii
        $s4 = "10.1.7.27" fullword wide
        $s5 = "Copyright 1984-2012 Adobe Systems Incorporated and its licensors. All ri" wide
        $s8 = "Adobe Reader" fullword wide
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_15 {
    meta:
        id = "6QJhG3yJ8XhvoYNls5azSr"
        fingerprint = "v1_sha256_5179f39bdcb064f55479ad147a019dd0b3874783c6bad650e84cfd9d0430bb70"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file e26a2afaaddfb09d9ede505c6f1cc4e3"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "7a8576804a2bbe4e5d05d1718f90b6a4332df027"

    strings:
        $s0 = "\\Windo" ascii
        $s2 = "HHOSTR"  ascii
        $s3 = "Softwa]\\Mic" ascii
        $s4 = "Startup'T" fullword ascii
        $s17 = "help32Snapshot0L" fullword ascii
        $s18 = "TimUmoveH" ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_16 {
    meta:
        id = "4mlmR2mdgzoDF2G7p1NhbC"
        fingerprint = "v1_sha256_0281f97db3ef98b91e0b4450c92daccfc059343dc34893aef74cae38243a76f4"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 37e568bed4ae057e548439dc811b4d3a"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "066d06ac08b48d3382d46bbeda6ad411b6d6130e"

    strings:
        $s0 = "\\Temp1020.txt" fullword ascii
        $s1 = "cmcbqyjs" fullword ascii
        $s2 = "SPVSWh\\" fullword ascii
        $s4 = "PSShxw@" fullword ascii
        $s5 = "VWhHw@" fullword ascii
        $s7 = "SVWhHw@" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_A {
    meta:
        id = "1sK4qv0pljbWhvu06kKcfe"
        fingerprint = "v1_sha256_c20660a8a55c6c6cb058fb233e0b29e1e4be2683181dbdfb06e17037d0ed8c31"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file af1c1c5d8031c4942630b6a10270d8f4"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash1 = "9f49aa1090fa478b9857e15695be4a89f8f3e594"
        hash2 = "396116cfb51cee090822913942f6ccf81856c2fb"
        hash3 = "fef9c3b4b35c226501f7d60816bb00331a904d5b"
        hash4 = "7c9a13f1fdd6452fb6d62067f958bfc5fec1d24e"
        hash5 = "5257ba027abe3a2cf397bfcae87b13ab9c1e9019"

    strings:
        $s5 = "WPVWhhiA" fullword ascii
        $s6 = "VPWVhhiA" fullword ascii
        $s11 = "VPhhiA" fullword ascii
        $s12 = "uUhXiA" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_17 {
    meta:
        id = "6ctx2qCdgoVorLGi1Jkaob"
        fingerprint = "v1_sha256_43913151325fbce993dbfec0acf64ca835b12270c47156ae81b0ce4f32c7bde1"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 23813c5bf6a7af322b40bd2fd94bd42e"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "c3aa52ff1d19e8fc6704777caf7c5bd120056845"

    strings:
        $s1 = "Nkfvtyvn}]ty}ztU" fullword ascii
        $s4 = "IEXPL0RE" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}
rule APT30_Sample_18 {
    meta:
        id = "2nAy1APigegghHdum62HeJ"
        fingerprint = "v1_sha256_d20f1d1b7b43defc36c7b1f99f14ed9e73e770b6f43d0ad92110cf9178b35b15"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file b2138a57f723326eda5a26d2dec56851"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "355436a16d7a2eba8a284b63bb252a8bb1644751"

    strings:
        $s0 = "w.km-nyc.com" fullword ascii
        $s1 = "tscv.exe" fullword ascii
        $s2 = "Exit/app.htm" ascii
        $s3 = "UBD:\\D" ascii
        $s4 = "LastError" ascii
        $s5 = "MicrosoftHaveAck" ascii
        $s7 = "HHOSTR" ascii
        $s20 = "XPL0RE." ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_G {
    meta:
        id = "5gg1XlnrrDE2ZUmMFtiUOQ"
        fingerprint = "v1_sha256_6926d73839958acd06835c1943edb150a0f60cdc269fac053531a0e0483e0521"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 53f1358cbc298da96ec56e9a08851b4b"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "1612b392d6145bfb0c43f8a48d78c75f"
        hash = "53f1358cbc298da96ec56e9a08851b4b"
        hash = "c2acc9fc9b0f050ec2103d3ba9cb11c0"
        hash = "f18be055fae2490221c926e2ad55ab11"

    strings:
        $s0 = "%s\\%s\\%s=%s" fullword ascii
        $s1 = "Copy File %s OK!" fullword ascii
        $s2 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
        $s4 = "open=%s" fullword ascii
        $s5 = "Maybe a Encrypted Flash Disk" fullword ascii
        $s12 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_19 {
    meta:
        id = "56wub7Os25LIbWYqJjL9F1"
        fingerprint = "v1_sha256_4192a1b05849ec80c940ea5a86f1b1136e68a02347922bf149d38f9f37af1cf4"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 5d4f2871fd1818527ebd65b0ff930a77"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "cfa438449715b61bffa20130df8af778ef011e15"

    strings:
        $s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
        $s1 = "%s,Volume:%s,Type:%s,TotalSize:%uMB,FreeSize:%uMB" fullword ascii
        $s2 = "\\TEMP\\" fullword ascii
        $s3 = "\\Temporary Internet Files\\" fullword ascii
        $s5 = "%s TotalSize:%u Bytes" fullword ascii
        $s6 = "This Disk Maybe a Encrypted Flash Disk!" fullword ascii
        $s7 = "User:%-32s" fullword ascii
        $s8 = "\\Desktop\\" fullword ascii
        $s9 = "%s.%u_%u" fullword ascii
        $s10 = "Nick:%-32s" fullword ascii
        $s11 = "E-mail:%-32s" fullword ascii
        $s13 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
        $s14 = "Type:%-8s" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and 8 of them
}

rule APT30_Generic_E_v2 {
    meta:
        id = "6rxDOLZOQaOI7uTYBpCKGT"
        fingerprint = "v1_sha256_25a7e5780f56b4f9cfb76494926c446a39a88bef2cda82b31e6de2b85c5edbda"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 71f25831681c19ea17b2f2a84a41bbfb"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "eca53a9f6251ddf438508b28d8a483f91b99a3fd"

    strings:
        $s0 = "Nkfvtyvn}duf_Z}{Ys" fullword ascii
        $s1 = "Nkfvtyvn}*Zrswru1i" fullword ascii
        $s2 = "Nkfvtyvn}duf_Z}{V" fullword ascii
        $s3 = "Nkfvtyvn}*ZrswrumT\\b" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_20 {
    meta:
        id = "2ZqIvYKqUDxUaMQAlieNjQ"
        fingerprint = "v1_sha256_f94cbd4b8e7ba302db9ac4ef3617bd68aa0aa1ee3cfc6dfee4621223bbdae3c5"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 5ae51243647b7d03a5cb20dccbc0d561"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "b1c37632e604a5d1f430c9351f87eb9e8ea911c0"

    strings:
        $s0 = "dizhi.gif" fullword ascii
        $s2 = "Mozilla/u" ascii
        $s3 = "XicrosoftHaveAck" ascii
        $s4 = "flyeagles" ascii
        $s10 = "iexplore." ascii
        $s13 = "WindowsGV" fullword ascii
        $s16 = "CatePipe" fullword ascii
        $s17 = "'QWERTY:/webpage3" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_21 {
    meta:
        id = "5AVDjA9JBjkpRIb8qq7oTb"
        fingerprint = "v1_sha256_e3e431bb6915d99b8aa1915419b60ba47372005b9b4994a924746a91bad80310"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 78c4fcee5b7fdbabf3b9941225d95166"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "d315daa61126616a79a8582145777d8a1565c615"

    strings:
        $s0 = "Service.dll" fullword ascii
        $s1 = "(%s:%s %s)" fullword ascii
        $s2 = "%s \"%s\",%s %s" fullword ascii
        $s5 = "Proxy-%s:%u" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_22 {
    meta:
        id = "6LLxHgAHkXCzoFhVgv4fRO"
        fingerprint = "v1_sha256_88a45d248eba7b9776e2e7d345d2948e00a94a7e359acb89d1943be55ab342ad"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file fad06d7b4450c4631302264486611ec3"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "0d17a58c24753e5f8fd5276f62c8c7394d8e1481"

    strings:
        $s1 = "(\\TEMP" fullword ascii
        $s2 = "Windows\\Cur" fullword ascii
        $s3 = "LSSAS.exeJ" fullword ascii
        $s4 = "QC:\\WINDOWS" fullword ascii
        $s5 = "System Volume" fullword ascii
        $s8 = "PROGRAM FILE" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_F {
    meta:
        id = "5CfZlgm6tAnLSnx6I6425U"
        fingerprint = "v1_sha256_7a3a71ebf8b5f5045d36eecece12bc43848c3313974f7cdcb1f59732b8631915"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 4c10a1efed25b828e4785d9526507fbc"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash1 = "09010917cd00dc8ddd21aeb066877aa2"
        hash2 = "4c10a1efed25b828e4785d9526507fbc"
        hash3 = "b7b282c9e3eca888cbdb5a856e07e8bd"
        hash4 = "df1799845b51300b03072c6569ab96d5"

    strings:
        $s0 = "\\~zlzl.exe" fullword ascii
        $s2 = "\\Internet Exp1orer" fullword ascii
        $s3 = "NodAndKabIsExcellent" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_23 {
    meta:
        id = "5Cf6FLtkmzlvQS6daHiWuD"
        fingerprint = "v1_sha256_64ff048b061431e0834ac40bfccb0d9e8ca60ffb022578ef910e6ffc511be6ed"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file a5ca2c5b4d8c0c1bc93570ed13dcab1a"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "9865e24aadb4480bd3c182e50e0e53316546fc01"

    strings:
        $s0 = "hostid" ascii
        $s1 = "\\Window" ascii
        $s2 = "%u:%u%s" fullword ascii
        $s5 = "S2tware\\Mic" ascii
        $s6 = "la/4.0 (compa" ascii
        $s7 = "NameACKernel" fullword ascii
        $s12 = "ToWideChc[lo" fullword ascii
        $s14 = "help32SnapshotfL" ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_24 {
    meta:
        id = "63ZyC7cCgSjrmPlTY2Is0g"
        fingerprint = "v1_sha256_9d550fd0225f1c4e3b16ae53648644d7bb5c80e99e2a1a3d199e51c7219c2e94"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 062fe1336459a851bd0ea271bb2afe35"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "572caa09f2b600daa941c60db1fc410bef8d1771"

    strings:
        $s1 = "dizhi.gif" fullword ascii
        $s3 = "Mozilla/4.0" fullword ascii
        $s4 = "lyeagles" fullword ascii
        $s6 = "HHOSTR" ascii
        $s7 = "#MicrosoftHaveAck7" ascii
        $s8 = "iexplore." fullword ascii
        $s17 = "ModuleH" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_25 {
    meta:
        id = "66qjgnWwh9C9Qr7iQC4mIq"
        fingerprint = "v1_sha256_4400184a9319c676f66550111a4f06d505151715df8ce62b067c771a182d366e"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file c4c068200ad8033a0f0cf28507b51842"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "44a21c8b3147fabc668fee968b62783aa9d90351"

    strings:
        $s1 = "C:\\WINDOWS" fullword ascii
        $s2 = "aragua" fullword ascii
        $s4 = "\\driver32\\7$" fullword ascii
        $s8 = "System V" fullword ascii
        $s9 = "Compu~r" fullword ascii
        $s10 = "PROGRAM L" fullword ascii
        $s18 = "GPRTMAX" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_26 {
    meta:
        id = "1il9VoO2PeRJ0GmXNz9c1U"
        fingerprint = "v1_sha256_b585687c071dc2dddb888906f47b7af6bc7683e902d3afb42364896e800fac5c"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 428fc53c84e921ac518e54a5d055f54a"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "e26588113417bf68cb0c479638c9cd99a48e846d"

    strings:
        $s1 = "forcegue" fullword ascii
        $s3 = "Windows\\Cur" fullword ascii
        $s4 = "System Id" fullword ascii
        $s5 = "Software\\Mic" fullword ascii
        $s6 = "utiBy0ToWideCh&$a" fullword ascii
        $s10 = "ModuleH" fullword ascii
        $s15 = "PeekNamed6G" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_D {
    meta:
        id = "6WCBXdSV5hG6Ul6fLw5jBe"
        fingerprint = "v1_sha256_81c0cc5c6b0d33c17399f1b3e0dd7bfd8b98d8f4e26f4403e4eab84bed8d28f8"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 597805832d45d522c4882f21db800ecf"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash1 = "35dfb55f419f476a54241f46e624a1a4"
        hash2 = "4fffcbdd4804f6952e0daf2d67507946"
        hash3 = "597805832d45d522c4882f21db800ecf"
        hash4 = "6bd422d56e85024e67cc12207e330984"
        hash5 = "82e13f3031130bd9d567c46a9c71ef2b"
        hash6 = "b79d87ff6de654130da95c73f66c15fa"

    strings:
        $s0 = "Windows Security Service Feedback" fullword wide
        $s1 = "wssfmgr.exe" fullword wide
        $s2 = "\\rb.htm" fullword ascii
        $s3 = "rb.htm" fullword ascii
        $s4 = "cook5" ascii
        $s5 = "5, 4, 2600, 0" fullword wide
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_27 {
    meta:
        id = "73hwooijA5oAyJCrjPL418"
        fingerprint = "v1_sha256_d2875ae78ca027be205822b60fccfd1fed1168fba2c7f0884e6e6f0283a4ba1f"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file d38e02eac7e3b299b46ff2607dd0f288"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "959573261ca1d7e5ddcd19447475b2139ca24fe1"

    strings:
        $s0 = "Mozilla/4.0" fullword ascii
        $s1 = "dizhi.gif" fullword ascii
        $s5 = "oftHaveAck+" ascii
        $s10 = "HlobalAl" fullword ascii
        $s13 = "$NtRND1$" fullword ascii
        $s14 = "_NStartup" fullword ascii
        $s16 = "GXSYSTEM" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_28 {
    meta:
        id = "st0RTH2be4zDgfOtkGk17"
        fingerprint = "v1_sha256_5ea80f8635d2c8925383e89ae1170a8b4e54669f7283e1f6125289132ad6dd0e"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file e62a63307deead5c9fcca6b9a2d51fb0"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash1 = "e62a63307deead5c9fcca6b9a2d51fb0"
        hash2 = "5b590798da581c894d8a87964763aa8b"

    strings:
        $s0 = "www.flyeagles.com" fullword ascii
        $s1 = "iexplore.exe" fullword ascii
        $s2 = "www.km-nyc.com" fullword ascii
        $s3 = "cmdLine.exe" fullword ascii
        $s4 = "Software\\Microsoft\\CurrentNetInf" fullword ascii
        $s5 = "/dizhi.gif" ascii
        $s6 = "/connect.gif" ascii
        $s7 = "USBTest.sys" fullword ascii
        $s8 = "/ver.htm" fullword ascii
        $s11 = "\\netscv.exe" fullword ascii
        $s12 = "/app.htm" fullword ascii
        $s13 = "\\netsvc.exe" fullword ascii
        $s14 = "/exe.htm" fullword ascii
        $s18 = "MicrosoftHaveAck" fullword ascii
        $s19 = "MicrosoftHaveExit" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and 7 of them
}

rule APT30_Sample_29 {
    meta:
        id = "6IJ7Yz61CWRrOvtZSKgIZX"
        fingerprint = "v1_sha256_89c7d335143c739c48dc75fdd92236cc892531373e90305a5a8cd7a12e34d83c"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 1b81b80ff0edf57da2440456d516cc90"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "44492c53715d7c79895904543843a321491cb23a"

    strings:
        $s0 = "LSSAS.exe" fullword ascii
        $s1 = "Software\\Microsoft\\FlashDiskInf" fullword ascii
        $s2 = ".petite" fullword ascii
        $s3 = "MicrosoftFlashExit" fullword ascii
        $s4 = "MicrosoftFlashHaveExit" fullword ascii
        $s5 = "MicrosoftFlashHaveAck" fullword ascii
        $s6 = "\\driver32" fullword ascii
        $s7 = "MicrosoftFlashZJ" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_30 {
    meta:
        id = "1HcXxOvnN9jVuu8od4qnrM"
        fingerprint = "v1_sha256_5ecfc8d53b768f624c8765f70708bfaae5396d7aa6b0335f7c656f4350649c5d"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file bf8616bbed6d804a3dea09b230c2ab0c"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "3b684fa40b4f096e99fbf535962c7da5cf0b4528"

    strings:
        $s0 = "5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)" fullword wide
        $s3 = "RnhwtxtkyLRRMf{jJ}ny" fullword ascii
        $s4 = "RnhwtxtkyLRRJ}ny" fullword ascii
        $s5 = "ZRLDownloadToFileA" fullword ascii
        $s9 = "5.1.2600.2180" fullword wide
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_31 {
    meta:
        id = "5rO9qCsSZI3aPbauDNZyGn"
        fingerprint = "v1_sha256_956ee2dc11f480213442d23d210377cc58aae5f297e1ff0f4afc468a242a6112"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file d8e68db503f4155ed1aeba95d1f5e3e4"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "8b4271167655787be1988574446125eae5043aca"

    strings:
        $s0 = "\\ZJRsv.tem" fullword ascii
        $s1 = "forceguest" fullword ascii
        $s4 = "\\$NtUninstallKB570317$" fullword ascii
        $s8 = "[Can'tGetIP]" fullword ascii
        $s14 = "QWERTY:,`/" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_J {
    meta:
        id = "7hpF8YUxDe84XWp0Gf8pU1"
        fingerprint = "v1_sha256_63f26f543b8b13a078099d6bce828197c77692e87a6bcbe4d82d7f073cf47ffe"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file baff5262ae01a9217b10fcd5dad9d1d5"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash1 = "49aca228674651cba776be727bdb7e60"
        hash2 = "5c7a6b3d1b85fad17333e02608844703"
        hash3 = "649fa64127fef1305ba141dd58fb83a5"
        hash4 = "9982fd829c0048c8f89620691316763a"
        hash5 = "baff5262ae01a9217b10fcd5dad9d1d5"
        hash6 = "9982fd829c0048c8f89620691316763a"

    strings:
        $s0 = "Launcher.EXE" fullword wide
        $s1 = "Symantec Security Technologies" fullword wide
        $s2 = "\\Symantec LiveUpdate.lnk" fullword ascii
        $s3 = "Symantec Service Framework" fullword wide
        $s4 = "\\ccSvcHst.exe" fullword ascii
        $s5 = "\\wssfmgr.exe" fullword ascii
        $s6 = "Symantec Corporation" fullword wide
        $s7 = "\\5.1.0.29" fullword ascii
        $s8 = "\\Engine" fullword ascii
        $s9 = "Copyright (C) 2000-2010 Symantec Corporation. All rights reserved." fullword wide
        $s10 = "Symantec LiveUpdate" fullword ascii
        $s11 = "\\Norton360" fullword ascii
        $s15 = "BinRes" fullword ascii
        $s16 = "\\readme.lz" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Microfost {
    meta:
        id = "547fOCE9U0BXcWaaGZuOxm"
        fingerprint = "v1_sha256_1fe5be3a88859fd3d485adfba92cf117afedc739bd0a46c039124919c3b81361"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 310a4a62ba3765cbf8e8bbb9f324c503"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "57169cb4b8ef7a0d7ebd7aa039d1a1efd6eb639e"

    strings:
        $s1 = "Copyright (c) 2007 Microfost All Rights Reserved" fullword wide
        $s2 = "Microfost" fullword wide
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_K {
    meta:
        id = "1U7opAC3N5EMPv4VKxzjyP"
        fingerprint = "v1_sha256_171b5485fe6e1389a77bc1cfc21a363c42eafcaa0878686c266e0eb634401c7d"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file b5a343d11e1f7340de99118ce9fc1bbb"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "142bc01ad412799a7f9ffed994069fecbd5a2f93"

    strings:
        $x1 = "Maybe a Encrypted Flash" fullword ascii
    
        $s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
        $s1 = "\\TEMP\\" fullword ascii
        $s2 = "\\Temporary Internet Files\\" fullword ascii
        $s5 = "%s Size:%u Bytes" fullword ascii
        $s7 = "$.DATA$" fullword ascii
        $s10 = "? Size:%u By s" fullword ascii
        $s12 = "Maybe a Encrypted Flash" fullword ascii
        $s14 = "Name:%-32s" fullword ascii
        $s15 = "NickName:%-32s" fullword ascii
        $s19 = "Email:%-32s" fullword ascii
        $s21 = "C:\\Prog" ascii
        $s22 = "$LDDATA$" ascii
        $s31 = "Copy File %s OK!" fullword ascii
        $s32 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
        $s34 = "open=%s" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and ( all of ($x*) and 3 of ($s*) )
}

rule APT30_Sample_33 {
    meta:
        id = "5aKdDocl325icwJkRE3c0t"
        fingerprint = "v1_sha256_295c2d9fcf1c3bab54650fd1d203dfb8c12269945aad8927066ef6f815abea69"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 5eaf3deaaf2efac92c73ada82a651afe"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "72c568ee2dd75406858c0294ccfcf86ad0e390e4"

    strings:
        $s0 = "Version 4.7.3001" fullword wide
        $s1 = "msmsgr.exe" fullword wide
        $s2 = "MYUSER32.dll" fullword ascii
        $s3 = "MYADVAPI32.dll" fullword ascii
        $s4 = "CeleWare.NET1" fullword ascii
        $s6 = "MYMSVCRT.dll" fullword ascii
        $s7 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the" wide
        $s8 = "WWW.CeleWare.NET1" ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and 6 of them
}

rule APT30_Sample_34 {
    meta:
        id = "1YcD34BQG0mWwpfWfgFE8b"
        fingerprint = "v1_sha256_2406f9613585669f88c389ea9729a089f6aef13fba46d60b713f51cd3a946b5d"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file a9e8e402a7ee459e4896d0ba83543684"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "216868edbcdd067bd2a9cce4f132d33ba9c0d818"

    strings:
        $s0 = "dizhi.gif" ascii
        $s1 = "eagles.vip.nse" ascii
        $s4 = "o%S:S0" ascii
        $s5 = "la/4.0" ascii
        $s6 = "s#!<4!2>s02==<'s1" ascii
        $s7 = "HlobalAl" ascii
        $s9 = "vcMicrosoftHaveAck7"  ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_35 {
    meta:
        id = "6YXyRmpDq7NEgiMxEDeYlz"
        fingerprint = "v1_sha256_a70d9471215ddcfe84a39b33f53c4114b205aa2cc95cd93081afe442ee2b8b42"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 414854a9b40f7757ed7bfc6a1b01250f"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "df48a7cd6c4a8f78f5847bad3776abc0458499a6"

    strings:
        $s0 = "WhBoyIEXPLORE.EXE.exe" fullword ascii
        $s5 = "Startup>A" fullword ascii
        $s18 = "olhelp32Snapshot" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_1 {
    meta:
        id = "5US54n3chxQFJbWINTOZzM"
        fingerprint = "v1_sha256_5f20b60b8721d62731708630a3443741c956304c553f651572282336995f6d4f"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - file 4c6b21e98ca03e0ef0910e07cef45dac"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        hash = "8cea83299af8f5ec6c278247e649c9d91d4cf3bc"

    strings:
        $s0 = "#hostid" fullword ascii
        $s1 = "\\Windows\\C" ascii
        $s5 = "TimUmove" fullword ascii
        $s6 = "Moziea/4.0 (c" fullword ascii
        $s7 = "StartupNA" fullword ascii
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_1 {
    meta:
        id = "52T4VE132n3WkoyYnZppaQ"
        fingerprint = "v1_sha256_943e44defb8c594a92d95f91f7bf868642b0375c9aa088bca77bfed8e5d54a43"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - from files 08b54f9b2b3fb19e388d390d278f3e44, 11876eaadeac34527c28f4ddfadd1e8d, 28f2396a1e306d05519b97a3a46ee925, 80e39b656f9a77503fa3e6b7dd123ee3, d591dc11ecffdfaf1626c1055417a50d, 8e2eee994cd1922e82dea58705cc9631, e9e514f8b1561011b4f034263c33a890"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        super_rule = 1
        hash0 = "aaa5c64200ff0818c56ebe4c88bcc1143216c536"
        hash1 = "cb4263cab467845dae9fae427e3bbeb31c6a14c2"
        hash2 = "b69b95db8a55a050d6d6c0cba13d73975b8219ca"
        hash3 = "5c29e21bbe8873778f9363258f5e570dddcadeb9"
        hash4 = "d5cb07d178963f2dea2c754d261185ecc94e09d6"
        hash5 = "626dcdd7357e1f8329e9137d0f9883f57ec5c163"
        hash6 = "843997b36ed80d3aeea3c822cb5dc446b6bfa7b9"

    strings:
        $s0 = "%s\\%s.txt" fullword
        $s1 = "\\ldsysinfo.txt" fullword
        $s4 = "(Extended Wansung)" fullword
        $s6 = "Computer Name:" fullword
        $s7 = "%s %uKB %04u-%02u-%02u %02u:%02u" fullword
        $s8 = "ASSAMESE" fullword
        $s9 = "BELARUSIAN" fullword
        $s10 = "(PR China)" fullword
        $s14 = "(French)" fullword
        $s15 = "AdvancedServer" fullword
        $s16 = "DataCenterServer" fullword
        $s18 = "(Finland)" fullword
        $s19 = "%s %04u-%02u-%02u %02u:%02u" fullword
        $s20 = "(Chile)" fullword
    condition:
        filesize < 250KB and uint16(0) == 0x5A4D and all of them
}
rule APT30_Generic_2 {
    meta:
        id = "1KhTvNmRh7IohjRRL50vy2"
        fingerprint = "v1_sha256_b992036d31458992b0caabd7fecf91d62eb762a2d7eb6652125abcd87c02fc4b"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - from many files"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        super_rule = 1
        hash0 = "aba8b9fa213e5e2f1f0404d13fecc20ea8651b57"
        hash1 = "7f11f5c9475240e5dd2eea7726c9229972cffc1f"
        hash2 = "94d3f91d1e50ecea729617729013c3d143bf2c3e"
        hash3 = "7e516ec04f28c76d67b8111ddfe58bbd628362cc"
        hash4 = "6b27bc0b0460b0a25b45d897ed4f399106c284d9"
        hash5 = "6df5b4b3da0964153bad22fb1f69483ae8316655"
        hash6 = "b68bce61dfd8763c3003480ba4066b3cb1ef126e"
        hash7 = "cc124682246d098740cfa7d20aede850d49b6597"
        hash8 = "1ef415bca310575944934fc97b0aa720943ba512"
        hash9 = "0559ab9356dcc869da18b2c96f48b76478c472b3"
        hash10 = "f15272042a4f9324ad5de884bd50f4072f4bdde3"
        hash11 = "1d93d5f5463cdf85e3c22c56ed1381957f4efaac"
        hash12 = "b6f1fb0f8a2fb92a3c60e154f24cfbca1984529f"
        hash13 = "9967a99a1b627ddb6899919e32a0f544ea498b48"
        hash14 = "95a3c812ca0ad104f045b26c483495129bcf37ca"
        hash15 = "bde9a72b2113d18b4fa537cc080d8d8ba1a231e8"
        hash16 = "ce1f53e06feab1e92f07ed544c288bf39c6fce19"
        hash17 = "72dae031d885dbf492c0232dd1c792ab4785a2dc"
        hash18 = "a2ccba46e40d0fb0dd3e1dba160ecbb5440862ec"
        hash19 = "c8007b59b2d495029cdf5b7b8fc8a5a1f7aa7611"
        hash20 = "9c6f470e2f326a055065b2501077c89f748db763"
        hash21 = "af3e232559ef69bdf2ee9cd96434dcec58afbe5a"
        hash22 = "e72e67ba32946c2702b7662c510cc1242cffe802"
        hash23 = "8fc0b1618b61dce5f18eba01809301cb7f021b35"
        hash24 = "6a8159da055dac928ba7c98ea1cdbe6dfb4a3c22"
        hash25 = "47463412daf0b0a410d3ccbb7ea294db5ff42311"
        hash26 = "e6efa0ccfddda7d7d689efeb28894c04ebc72be2"
        hash27 = "43a3fc9a4fee43252e9a570492e4efe33043e710"
        hash28 = "7406ebef11ca9f97c101b37f417901c70ab514b1"
        hash29 = "53ed9b22084f89b4b595938e320f20efe65e0409"

    strings:
        $s0 = "%s\\%s\\KB985109.log" fullword
        $s1 = "%s\\%s\\KB989109.log" fullword
        $s2 = "Opera.exe" fullword wide
        $s3 = "%s:All online success on %u!" fullword
        $s4 = "%s:list online success on %u!" fullword
        $s5 = "%s:All online fail!" fullword
        $s6 = "Copyright Opera Software 1995-" fullword wide
        $s7 = "%s:list online fail!" fullword
        $s8 = "OnlineTmp.txt" fullword
        $s9 = "Opera Internet Browser" fullword wide
        $s12 = "Opera Software" fullword wide
        $s15 = "Check lan have done!!!" fullword
        $s16 = "List End." fullword
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_3 {
    meta:
        id = "1qbzmKVJLBQtc67YuUijBY"
        fingerprint = "v1_sha256_c400febf29be432e112db0c8087414a2d997fbdc4d955f80300a7cd83bd1577c"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - from files 6e689351d94389ac6fdc341b859c7f6f, a813eba27b2166620bd75029cc1f04b0, b4ae0004094b37a40978ef06f311a75e"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        super_rule = 1
        hash0 = "b90ac3e58ed472829e2562023e6e892d2d61ac44"
        hash1 = "342036ace2e9e6d504b0dec6399e4fa92de46c12"
        hash2 = "5cdf397dfd9eb66ff5ff636777f6982c1254a37a"

    strings:
        $s0 = "Acrobat.exe" fullword wide
        $s14 = "********************************" fullword
        $s16 = "FFFF:>>>>>>>>>>>>>>>>>@" fullword
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_4 {
    meta:
        id = "3ZDdpN2GZQ3wxdzxHSQS3y"
        fingerprint = "v1_sha256_da52284189f4599281165b6194fc1e5a51b9a56e0fc51925a98c34c2bc33a982"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - from files 021e134c48cd9ce9eaf6a1c105197e5d, 7c307ca84f922674049c0c43ca09bec1, b8617302180d331e197cc0433fc5023d, e6289e7f9f26be692cbe6f335a706014"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        super_rule = 1
        hash0 = "bb390f99bfde234bbed59f6a0d962ba874b2396c"
        hash1 = "b47e20ac5889700438dc241f28f4e224070810d2"
        hash2 = "a9a50673ac000a313f3ddba55d63d9773b9f4143"
        hash3 = "ac96d7f5957aef09bd983465c497de24c6d17a92"

    strings:
        $s0 = "del NetEagle_Scout.bat" fullword
        $s1 = "NetEagle_Scout.bat" fullword
        $s2 = "\\visit.exe" fullword
        $s3 = "\\System.exe" fullword
        $s4 = "\\System.dat" fullword
        $s5 = "\\ieupdate.exe" fullword
        $s6 = "GOTO ERROR" fullword
        $s7 = ":ERROR" fullword
        $s9 = "IF EXIST " fullword
        $s10 = "ioiocn" fullword
        $s11 = "SetFileAttribute" fullword
        $s12 = "le_0*^il" fullword
        $s13 = "le_.*^il" fullword
        $s14 = "le_-*^il" fullword
    condition:
        filesize < 250KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_5 {
    meta:
        id = "3kHeEx63VCelxFZ9Sbh47n"
        fingerprint = "v1_sha256_eaeddbd16a77fc98fb2014f334ed7bf9358773a1b22704327a15fdf2c0de641a"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - from files 592381dfa14e61bce089cd00c9b118ae, b493ad490b691b8732983dcca8ea8b6f, b83d43e3b2f0b0a0e5cc047ef258c2cb"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        super_rule = 1
        hash0 = "cb4833220c508182c0ccd4e0d5a867d6c4e675f8"
        hash1 = "dfc9a87df2d585c479ab02602133934b055d156f"
        hash2 = "bf59d5ff7d38ec5ffb91296e002e8742baf24db5"

    strings:
        $s0 = "regsvr32 /s \"%ProgramFiles%\\Norton360\\Engine\\5.1.0.29\\ashelper.dll\"" fullword
        $s1 = "name=\"ftpserver.exe\"/>" fullword
        $s2 = "LiveUpdate.EXE" fullword wide
        $s3 = "<description>FTP Explorer</description>" fullword
        $s4 = "\\ashelper.dll" fullword
        $s5 = "LiveUpdate" fullword wide
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_6 {
    meta:
        id = "4z0Cch75u2VRs0efGY8iAX"
        fingerprint = "v1_sha256_ff7473e43e11e31fe6ad997009834f661a0120317e479184410456c99f72b613"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - from files 168d207d0599ed0bb5bcfca3b3e7a9d3, 1e6ee89fddcf23132ee12802337add61, 5dd625af837e164dd2084b1f44a45808"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        super_rule = 1
        hash0 = "b9aafb575d3d1732cb8fdca5ea226cebf86ea3c9"
        hash1 = "2c5e347083b77c9ead9e75d41e2fabe096460bba"
        hash2 = "5d39a567b50c74c4a921b5f65713f78023099933"

    strings:
        $s0 = "GetStar" fullword
        $s1 = ".rdUaS" fullword
        $s2 = "%sOTwp/&A\\L" fullword
        $s3 = "a Encrt% Flash Disk" fullword
        $s4 = "ypeAutoRuChec" fullword
        $s5 = "NoDriveT" fullword
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_7 {
    meta:
        id = "4GNGTtFEK4SuMvfkXKyyGt"
        fingerprint = "v1_sha256_b5a272cbeb46be9b120acdbe12d795eddc05765777e4157d818c2b91ea7b782b"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - from files 853a20f5fc6d16202828df132c41a061, 9c0cad1560cd0ffe2aa570621ef7d0a0, b590c15499448639c2748ff9e0d214b2"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        super_rule = 1
        hash0 = "2415f661046fdbe3eea8cd276b6f13354019b1a6"
        hash1 = "e814914079af78d9f1b71000fee3c29d31d9b586"
        hash2 = "0263de239ccef669c47399856d481e3361408e90"

    strings:
        $s1 = "Xjapor_*ata" fullword
        $s2 = "Xjapor_o*ata" fullword
        $s4 = "Ouopai" fullword
    condition:
        filesize < 100KB and uint16(0) == 0x5A4D and all of them
}
rule APT30_Generic_8 {
    meta:
        id = "KnMUPQEGRoNB2PatZqAhQ"
        fingerprint = "v1_sha256_2c240d2a35ce3d621d108d03d4e720ddf86e248047fb4dd7f9724e64020caa7f"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - from files 7c307ca84f922674049c0c43ca09bec1, b8617302180d331e197cc0433fc5023d, e6289e7f9f26be692cbe6f335a706014"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        super_rule = 1
        hash0 = "b47e20ac5889700438dc241f28f4e224070810d2"
        hash1 = "a9a50673ac000a313f3ddba55d63d9773b9f4143"
        hash2 = "ac96d7f5957aef09bd983465c497de24c6d17a92"

    strings:
        $s0 = "Windows NT4.0" fullword
        $s1 = "Windows NT3.51" fullword
        $s2 = "%d;%d;%d;%ld;%ld;%ld;" fullword
        $s3 = "%s %d.%d Build%d %s" fullword
        $s4 = "MSAFD Tcpip [TCP/IP]" fullword
        $s5 = "SQSRSS" fullword
        $s8 = "WM_COMP" fullword
        $s9 = "WM_MBU" fullword
        $s11 = "WM_GRID" fullword
        $s12 = "WM_RBU" fullword
    condition:
        filesize < 250KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_9 {
    meta:
        id = "2wnqud483dmW5TUdihyax5"
        fingerprint = "v1_sha256_0b30c2f0bd654371bf3ac4f9d4e700e1544b62a6c0a072d506160c443fc5fe9d"
        version = "1.0"
        date = "2015/04/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "FireEye APT30 Report Sample - from files 0cdc35ffc222a714ee138b57d29c8749, 10aa368899774463a355f1397e6e5151, 3166baffecccd0934bdc657c01491094, d28d67b4397b7ce1508d10bf3054ffe5"
        category = "INFO"
        reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
        super_rule = 1
        hash0 = "00d9949832dc3533592c2ce06a403ef19deddce9"
        hash1 = "27a2b981d4c0bb8c3628bfe990db4619ddfdff74"
        hash2 = "05f66492c163ec2a24c6a87c7a43028c5f632437"
        hash3 = "263f094da3f64e72ef8dc3d02be4fb33de1fdb96"

    strings:
        $s0 = "%s\\%s\\$NtRecDoc$" fullword
        $s1 = "%s(%u)%s" fullword
        $s2 = "http://%s%s%s" fullword
        $s3 = "1.9.1.17" fullword wide
        $s4 = "(C)Firefox and Mozilla Developers, according to the MPL 1.1/GPL 2.0/LGPL" wide
    condition:
        filesize < 250KB and uint16(0) == 0x5A4D and all of them
}

