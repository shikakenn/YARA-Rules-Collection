rule Explosive_EXE : APT { 
    meta:
        id = "5DaMpFmnlnWxiPexzoAapz"
        fingerprint = "v1_sha256_77eb74586f5ef2878c0d283b925e6e066f704d00525303990cf5ea7988a6637d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Check Point Software Technologies Inc."
        description = "Explosion/Explosive Malware - Volatile Cedar APT"
        category = "INFO"

    strings:
        $DLD_S = "DLD-S:" 
        $DLD_E = "DLD-E:"
    condition:
        all of them and
        uint16(0) == 0x5A4D
}

rule Explosion_Sample_1 {
    meta:
        id = "2FJAiPUYvsAHx0Qc4bsrGZ"
        fingerprint = "v1_sha256_3a665fcd21f27595dc9191871859bed03004196f7846b91724ec9bf8a932ee36"
        version = "1.0"
        score = 70
        date = "2015/04/03"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Explosion/Explosive Malware - Volatile Cedar APT - file b74bd5660baf67038353136978ed16dbc7d105c60c121cf64c61d8f3d31de32c"
        category = "INFO"
        reference = "http://goo.gl/5vYaNb"
        hash = "c97693ecb36247bdb44ab3f12dfeae8be4d299bb"

    strings:
        $s5 = "REG ADD \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $s9 = "WinAutologon From Winlogon Reg" fullword ascii
        $s10 = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" fullword ascii
        $s11 = "IE:Password-Protected sites" fullword ascii
        $s12 = "\\his.sys" fullword ascii
        $s13 = "HTTP Password" fullword ascii
        $s14 = "\\data.sys" fullword ascii
        $s15 = "EL$_RasDefaultCredentials#0" fullword wide
        $s17 = "Office Outlook HTTP" fullword ascii
        $s20 = "Hist :<b> %ws</b>  :%s </br></br>" fullword ascii
    condition:
        all of them and  
        uint16(0) == 0x5A4D
}

rule Explosion_Sample_2 {
    meta:
        id = "5MoDVSLV2sDTdVEmo134Oh"
        fingerprint = "v1_sha256_db7ead96e0a9b4cf5c5cc885eac421cc11988f60d03f94de5fe828899d115bf0"
        version = "1.0"
        score = 70
        date = "2015/04/03"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Explosion/Explosive Malware - Volatile Cedar APT - file bfc63b30624332f4fc2e510f95b69d18dd0241eb0d2fcd33ed2e81b7275ab488"
        category = "INFO"
        reference = "http://goo.gl/5vYaNb"
        hash = "62fe6e9e395f70dd632c70d5d154a16ff38dcd29"

    strings:
        $s0 = "serverhelp.dll" fullword wide
        $s1 = "Windows Help DLL" fullword wide
        $s5 = "SetWinHoK" fullword ascii
    condition:
        all of them and  
        uint16(0) == 0x5A4D
}

rule Explosion_Generic_1 {
    meta:
        id = "2FqD9LXRYlI1TxFpSj3crR"
        fingerprint = "v1_sha256_8b6e1e6aa838036989040dfbf4f6f3e347a717967deef740b35d1752b5c91da5"
        version = "1.0"
        score = 70
        date = "2015/04/03"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Generic Rule for Explosion/Explosive Malware - Volatile Cedar APT"
        category = "INFO"
        reference = "not set"
        super_rule = 1
        hash0 = "d0f059ba21f06021579835a55220d1e822d1233f95879ea6f7cb9d301408c821"
        hash1 = "1952fa94b582e9af9dca596b5e51c585a78b8b1610639e3b878bbfa365e8e908"
        hash2 = "d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726"
        hash3 = "e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747"
        hash4 = "03641e5632673615f23b2a8325d7355c4499a40f47b6ae094606a73c56e24ad0"

    strings:
        $s0 = "autorun.exe" fullword
        $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.1; .NET CL"
        $s2 = "%drp.exe" fullword
        $s3 = "%s_%s%d.exe" fullword
        $s4 = "open=autorun.exe" fullword
        $s5 = "http://www.microsoft.com/en-us/default.aspx" fullword
        $s10 = "error.renamefile" fullword
        $s12 = "insufficient lookahead" fullword
        $s13 = "%s %s|" fullword
        $s16 = ":\\autorun.exe" fullword
    condition:
        7 of them and  
        uint16(0) == 0x5A4D 
}

rule Explosive_UA {
    meta:
        id = "2DXTC9RbdkyVBUpxE5vl4C"
        fingerprint = "v1_sha256_9ed7fedcf9cda868803c8ace393e08709a747b909178e19cdbb1b116edbb82f9"
        version = "1.0"
        score = 60
        date = "2015/04/03"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Explosive Malware Embedded User Agent - Volatile Cedar APT http://goo.gl/HQRCdw"
        category = "INFO"
        reference = "http://goo.gl/HQRCdw"

    strings:	
        $x1 = "Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.1; .NET CLR 2.0.50727)" fullword
    condition:
        $x1 and  
        uint16(0) == 0x5A4D 
}

rule Webshell_Caterpillar_ASPX {
    meta:
        id = "3ef5Fs0hLY73tlzXjP6Nxi"
        fingerprint = "v1_sha256_9df2e4a25052136d6e622273f917bd15df410869a8cf3075c773a14ea62a2a55"
        version = "1.0"
        date = "2015/04/03"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Volatile Cedar Webshell - from file caterpillar.aspx"
        category = "INFO"
        reference = "http://goo.gl/emons5"
        super_rule = 1
        hash0 = "af4c99208fb92dc42bc98c4f96c3536ec8f3fe56"

    strings:
        $s0 = "Dim objNewRequest As WebRequest = HttpWebRequest.Create(sURL)" fullword
        $s1 = "command = \"ipconfig /all\"" fullword
        $s3 = "For Each xfile In mydir.GetFiles()" fullword
        $s6 = "Dim oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
        $s10 = "recResult = adoConn.Execute(strQuery)" fullword
        $s12 = "b = Request.QueryString(\"src\")" fullword
        $s13 = "rw(\"<a href='\" + link + \"' target='\" + target + \"'>\" + title + \"</a>\")" fullword
    condition:
        all of them
}
