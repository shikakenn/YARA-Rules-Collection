/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-09-16
    Identifier: Iron Panda
*/

/* Rule Set ----------------------------------------------------------------- */

rule IronPanda_DNSTunClient {
    meta:
        id = "3y4JDespcb1lVa6Xs3fQjO"
        fingerprint = "v1_sha256_503967cd0778ecbeb96316362fefebf57b561c6b658ccf37ee6c643db7d2ddff"
        version = "1.0"
        score = 80
        date = "2015-09-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Iron Panda malware DnsTunClient - file named.exe"
        category = "INFO"
        reference = "https://goo.gl/E4qia9"
        hash = "a08db49e198068709b7e52f16d00a10d72b4d26562c0d82b4544f8b0fb259431"

    strings:
        $s1 = "dnstunclient -d or -domain <domain>" fullword ascii
        $s2 = "dnstunclient -ip <server ip address>" fullword ascii
        $s3 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"\\Microsoft\\Windows\\PLA\\System\\Microsoft Windows\" /tr " fullword ascii
        $s4 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"Microsoft Windows\" /tr " fullword ascii
        $s5 = "taskkill /im conime.exe" fullword ascii
        $s6 = "\\dns control\\t-DNSTunnel\\DnsTunClient\\DnsTunClient.cpp" fullword ascii
        $s7 = "UDP error:can not bing the port(if there is unclosed the bind process?)" fullword ascii
        $s8 = "use error domain,set domain pls use -d or -domain mark(Current: %s,recv %s)" fullword ascii
        $s9 = "error: packet num error.the connection have condurt,pls try later" fullword ascii
        $s10 = "Coversation produce one error:%s,coversation fail" fullword ascii
        $s11 = "try to add many same pipe to select group(or mark is too easy)." fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 400KB and 2 of them ) 
        or
        5 of them
}

rule IronPanda_Malware1 {
    meta:
        id = "7RSqWbx49GdKi00jv2Q79u"
        fingerprint = "v1_sha256_4b50a2c7f0f94b678fc560eefb217c067e934f8e7d64bc0f0d16afcccccd0d08"
        version = "1.0"
        date = "2015-09-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Iron Panda Malware"
        category = "INFO"
        reference = "https://goo.gl/E4qia9"
        hash = "a0cee5822ddf254c254a5a0b7372c9d2b46b088a254a1208cb32f5fe7eca848a"

    strings:
        $x1 = "activedsimp.dll" fullword wide
        $s1 = "get_BadLoginAddress" fullword ascii
        $s2 = "get_LastFailedLogin" fullword ascii
        $s3 = "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED" fullword ascii
        $s4 = "get_PasswordExpirationDate" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule IronPanda_Webshell_JSP {
    meta:
        id = "757zo3fWKqMAlDHTnE47iA"
        fingerprint = "v1_sha256_747ce812b156bf03f8d14ef84e7d2e8535c7c70590dfcb50ce3e957bec745efc"
        version = "1.0"
        date = "2015-09-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Iron Panda Malware JSP"
        category = "INFO"
        reference = "https://goo.gl/E4qia9"
        hash = "3be95477e1d9f3877b4355cff3fbcdd3589bb7f6349fd4ba6451e1e9d32b7fa6"

    strings:
        $s1 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
        $s2 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
        $s3 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
    condition:
        filesize < 330KB and 1 of them
}

rule IronPanda_Malware_Htran {
    meta:
        id = "13evSUDQDyxSvbZRMQdxIj"
        fingerprint = "v1_sha256_74fa1ad262df2594a654258b167d57b5390637528883d99f2d05e4b8b7c63993"
        version = "1.0"
        date = "2015-09-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Iron Panda Malware Htran"
        category = "INFO"
        reference = "https://goo.gl/E4qia9"
        hash = "7903f94730a8508e9b272b3b56899b49736740cea5037ea7dbb4e690bcaf00e7"

    strings:
        $s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
        $s2 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
        $s3 = "-slave <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
        $s4 = "[-] ERROR: Must supply logfile name." fullword ascii
        $s5 = "[SERVER]connection to %s:%d error" fullword ascii
        $s6 = "[+] Make a Connection to %s:%d...." fullword ascii
        $s7 = "[+] Waiting another Client on port:%d...." fullword ascii
        $s8 = "[+] Accept a Client on port %d from %s" fullword ascii
        $s9 = "[+] Make a Connection to %s:%d ......" fullword ascii
        $s10 = "cmshared_get_ptr_from_atom" fullword ascii
        $s11 = "_cmshared_get_ptr_from_atom" fullword ascii
        $s12 = "[+] OK! I Closed The Two Socket." fullword ascii
        $s13 = "[-] TransmitPort invalid." fullword ascii
        $s14 = "[+] Waiting for Client on port:%d ......" fullword ascii
    condition:
         ( uint16(0) == 0x5a4d and filesize < 125KB and 3 of them ) 
         or 
         5 of them
}

rule IronPanda_Malware2 {
    meta:
        id = "2Qtj2lo0lznzDuYEfDzNj8"
        fingerprint = "v1_sha256_59adf25b51cc98b698bd3210e0fb46139073911f18019a1e853fd049241ed50d"
        version = "1.0"
        date = "2015-09-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Iron Panda Malware"
        category = "INFO"
        reference = "https://goo.gl/E4qia9"
        hash = "a89c21dd608c51c4bf0323d640f816e464578510389f9edcf04cd34090decc91"

    strings:
        $s0 = "\\setup.exe" fullword ascii
        $s1 = "msi.dll.urlUT" fullword ascii
        $s2 = "msi.dllUT" fullword ascii
        $s3 = "setup.exeUT" fullword ascii
        $s4 = "/c del /q %s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 180KB and all of them
}

rule IronPanda_Malware3 {
    meta:
        id = "4pBb3j3rH7vJNqJGu9jzO7"
        fingerprint = "v1_sha256_ca55fc5aa655fb221808b4c82db520cae24e0d93422293b6ed5e573b343e93ac"
        version = "1.0"
        date = "2015-09-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Iron Panda Malware"
        category = "INFO"
        reference = "https://goo.gl/E4qia9"
        hash = "5cd2af844e718570ae7ba9773a9075738c0b3b75c65909437c43201ce596a742"

    strings:
        $s0 = "PluginDeflater.exe" fullword wide
        $s1 = ".Deflated" fullword wide
        $s2 = "PluginDeflater" fullword ascii
        $s3 = "DeflateStream" fullword ascii /* Goodware String - occured 1 times */
        $s4 = "CompressionMode" fullword ascii /* Goodware String - occured 4 times */
        $s5 = "System.IO.Compression" fullword ascii /* Goodware String - occured 6 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 10KB and all of them
}

rule IronPanda_Malware4 {
    meta:
        id = "6XVzciVUfVAZoa2sziv3u1"
        fingerprint = "v1_sha256_12661c8862eeb82d55a3912e0a499beb6bb19f7abe9ccfe6fa0506e6a032cfe4"
        version = "1.0"
        date = "2015-09-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Iron Panda Malware"
        category = "INFO"
        reference = "https://goo.gl/E4qia9"
        hash = "0d6da946026154416f49df2283252d01ecfb0c41c27ef3bc79029483adc2240c"

    strings:
        $s0 = "TestPlugin.dll" fullword wide
        $s1 = "<a href='http://www.baidu.com'>aasd</a>" fullword wide
        $s2 = "Zcg.Test.AspxSpyPlugins" fullword ascii
        $s6 = "TestPlugin" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 10KB and all of them
}

