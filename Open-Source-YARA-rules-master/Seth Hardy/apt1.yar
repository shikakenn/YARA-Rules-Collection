rule LIGHTDART_APT1 {
    meta:
        id = "3x6toe4TAyr0LRlpfTsZCV"
        fingerprint = "v1_sha256_9d26e3a70af3f4d45409eecd319562ea721acbe9f5305f5a30f42ff4e54eb1a8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "ret.log" wide ascii
                $s2 = "Microsoft Internet Explorer 6.0" wide ascii
                $s3 = "szURL Fail" wide ascii
                $s4 = "szURL Successfully" wide ascii
                $s5 = "%s&sdate=%04ld-%02ld-%02ld" wide ascii
        condition:
                all of them
}

rule AURIGA_APT1 {
    meta:
        id = "3UMoNDTqfshAzrdwLYWUFk"
        fingerprint = "v1_sha256_f8e65be704f84a9516e32a3f72a59bb5515f2fc957001d8a23e7a9b2bc8008c2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "superhard corp." wide ascii
                $s2 = "microsoft corp." wide ascii
                $s3 = "[Insert]" wide ascii
                $s4 = "[Delete]" wide ascii
                $s5 = "[End]" wide ascii
                $s6 = "!(*@)(!@KEY" wide ascii
                $s7 = "!(*@)(!@SID=" wide ascii
        condition:
                all of them
}

rule AURIGA_driver_APT1 {
    meta:
        id = "XL4k68Ae0ek2oOWJYE86"
        fingerprint = "v1_sha256_089cffdce6570b647062ddf1d1ea8453bba75a54d2589b1d68c8aa79ca809f33"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "Services\\riodrv32" wide ascii
                $s2 = "riodrv32.sys" wide ascii
                $s3 = "svchost.exe" wide ascii
                $s4 = "wuauserv.dll" wide ascii
                $s5 = "arp.exe" wide ascii
                $pdb = "projects\\auriga" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule BANGAT_APT1 {
    meta:
        id = "2j4sI2MH8IowDSconCAPqT"
        fingerprint = "v1_sha256_690e30c12a91a4e5f2da90aff84c5d3eea2862284c5d75b26bbe6d1714306a4d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "superhard corp." wide ascii
                $s2 = "microsoft corp." wide ascii
                $s3 = "[Insert]" wide ascii
                $s4 = "[Delete]" wide ascii
                $s5 = "[End]" wide ascii
                $s6 = "!(*@)(!@KEY" wide ascii
                $s7 = "!(*@)(!@SID=" wide ascii
                $s8 = "end      binary output" wide ascii
                $s9 = "XriteProcessMemory" wide ascii
                $s10 = "IE:Password-Protected sites" wide ascii
                $s11 = "pstorec.dll" wide ascii

        condition:
                all of them
}

rule BISCUIT_GREENCAT_APT1 {
    meta:
        id = "3brhGkZgvEHM9QYEStrtrm"
        fingerprint = "v1_sha256_df65de6af1b22ade2218f3292bc48b0a1e5b5d22b93ff3c60b922dbd68d28b4e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "zxdosml" wide ascii
                $s2 = "get user name error!" wide ascii
                $s3 = "get computer name error!" wide ascii
                $s4 = "----client system info----" wide ascii
                $s5 = "stfile" wide ascii
                $s6 = "cmd success!" wide ascii

        condition:
                all of them
}

rule BOUNCER_APT1 {
    meta:
        id = "37FQMMTBFuz5b19Q5YaB4t"
        fingerprint = "v1_sha256_c87506da6849ed66d56c937190141b00cf41a0ee47cb9ccc5ebc6a9928f29750"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg" wide ascii
                $s2 = "IDR_DATA%d" wide ascii

                $s3 = "asdfqwe123cxz" wide ascii
                $s4 = "Mode must be 0(encrypt) or 1(decrypt)." wide ascii

        condition:
                ($s1 and $s2) or ($s3 and $s4)

}

rule BOUNCER_DLL_APT1 {
    meta:
        id = "2fZ6DeY05sxXY01IqNlZGE"
        fingerprint = "v1_sha256_2868fecfc885aa7804ec8410abcbaedfb2d0d7613f35d7164b208d5a81461fd3"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "new_connection_to_bounce():" wide ascii
                $s2 = "usage:%s IP port [proxip] [port] [key]" wide ascii

        condition:
                all of them
}

rule CALENDAR_APT1 {
    meta:
        id = "4E8KddxFQOjDfQNcHznZNv"
        fingerprint = "v1_sha256_12833420a33c44928911e2cda2dd786e8772dfffcf4994487fd131cc3cdbdc9c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "content" wide ascii
                $s2 = "title" wide ascii
                $s3 = "entry" wide ascii
                $s4 = "feed" wide ascii
                $s5 = "DownRun success" wide ascii
                $s6 = "%s@gmail.com" wide ascii
                $s7 = "<!--%s-->" wide ascii

                $b8 = "W4qKihsb+So=" wide ascii
                $b9 = "PoqKigY7ggH+VcnqnTcmhFCo9w==" wide ascii
                $b10 = "8oqKiqb5880/uJLzAsY=" wide ascii

        condition:
                all of ($s*) or all of ($b*)
}

rule COMBOS_APT1 {
    meta:
        id = "1E2gn8ReSflyE0vD7rYb06"
        fingerprint = "v1_sha256_6b596e2536bffa0e98d5e83577298ad4e5d3d9b4a343bd5cad7cee930bc321b2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "Mozilla4.0 (compatible; MSIE 7.0; Win32)" wide ascii
                $s2 = "Mozilla5.1 (compatible; MSIE 8.0; Win32)" wide ascii
                $s3 = "Delay" wide ascii
                $s4 = "Getfile" wide ascii
                $s5 = "Putfile" wide ascii
                $s6 = "---[ Virtual Shell]---" wide ascii
                $s7 = "Not Comming From Our Server %s." wide ascii


        condition:
                all of them
}

rule DAIRY_APT1 {
    meta:
        id = "6YaI6zTXpBSN2LEVjlxOsG"
        fingerprint = "v1_sha256_47af02f7936388753f92b17301a63f1c47fa056470cc4057f64f30dbeb6d9f18"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; MSIE 7.0;)" wide ascii
                $s2 = "KilFail" wide ascii
                $s3 = "KilSucc" wide ascii
                $s4 = "pkkill" wide ascii
                $s5 = "pklist" wide ascii


        condition:
                all of them
}

rule GLOOXMAIL_APT1 {
    meta:
        id = "Nvpa7B2Csbpz6ScJOzp8y"
        fingerprint = "v1_sha256_bf2fbd15ec078ab1d1f23e5264e40fe9f55c5ec15b8f81083258230b52eb4dd6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "Kill process success!" wide ascii
                $s2 = "Kill process failed!" wide ascii
                $s3 = "Sleep success!" wide ascii
                $s4 = "based on gloox" wide ascii

                $pdb = "glooxtest.pdb" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule GOGGLES_APT1 {
    meta:
        id = "3ZbQohnssYNzwIHHIm9k2O"
        fingerprint = "v1_sha256_bf2fbd15ec078ab1d1f23e5264e40fe9f55c5ec15b8f81083258230b52eb4dd6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "Kill process success!" wide ascii
                $s2 = "Kill process failed!" wide ascii
                $s3 = "Sleep success!" wide ascii
                $s4 = "based on gloox" wide ascii

                $pdb = "glooxtest.pdb" wide ascii

        condition:
                all of ($s*) or $pdb
}

rule HACKSFASE1_APT1 {
    meta:
        id = "58NYvDA4FYrNEt3izPFITR"
        fingerprint = "v1_sha256_fa79da177ac5217fa2402f4d7405131f1064dd1ddc18435faa4be8c8bc4bb457"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = {cb 39 82 49 42 be 1f 3a}

        condition:
                all of them
}

rule HACKSFASE2_APT1 {
    meta:
        id = "1wShifks3E0Cdqt6bLSIKi"
        fingerprint = "v1_sha256_10d779053d1882906bcc41630a12995d57cdaab994147214dac8515725a7cac6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "Send to Server failed." wide ascii
                $s2 = "HandShake with the server failed. Error:" wide ascii
                $s3 = "Decryption Failed. Context Expired." wide ascii

        condition:
                all of them
}

rule KURTON_APT1 {
    meta:
        id = "2K9CVrNMRgoVX4MjHu3Eqr"
        fingerprint = "v1_sha256_26226b3562e4bd36e47032df2b0df60eb7b746501404d01224da01eea50a171b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; MSIE8.0; Windows NT 5.1)" wide ascii
                $s2 = "!(*@)(!@PORT!(*@)(!@URL" wide ascii
                $s3 = "MyTmpFile.Dat" wide ascii
                $s4 = "SvcHost.DLL.log" wide ascii

        condition:
                all of them
}

rule LONGRUN_APT1 {
    meta:
        id = "4XcYzD2w4nyOC2kXeszrc3"
        fingerprint = "v1_sha256_6ed0190203f9930b74de30e472055bfa740ff8272811f0f219732e2e30c4c17d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0)" wide ascii
                $s2 = "%s\\%c%c%c%c%c%c%c" wide ascii
                $s3 = "wait:" wide ascii
                $s4 = "Dcryption Error! Invalid Character" wide ascii

        condition:
                all of them
}

rule MACROMAIL_APT1 {
    meta:
        id = "5MJPMR4ZRjsD94eO4R42Qe"
        fingerprint = "v1_sha256_46037040cefb32373c2de60b332f8558ec58001eb0c268c2599d52bb063917c4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "svcMsn.dll" wide ascii
                $s2 = "RundllInstall" wide ascii
                $s3 = "Config service %s ok." wide ascii
                $s4 = "svchost.exe" wide ascii

        condition:
                all of them
}

rule MANITSME_APT1 {
    meta:
        id = "4Ngyo3RWX4DlcbeNB8nDwj"
        fingerprint = "v1_sha256_46a8196466afbe6989dc8e4ccd375a94441260d413647673529603884aae18c4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "Install an Service hosted by SVCHOST." wide ascii
                $s2 = "The Dll file that to be released." wide ascii
                $s3 = "SYSTEM\\CurrentControlSet\\Services\\" wide ascii
                $s4 = "svchost.exe" wide ascii

                $e1 = "Man,it's me" wide ascii
                $e2 = "Oh,shit" wide ascii
                $e3 = "Hallelujah" wide ascii
                $e4 = "nRet == SOCKET_ERROR" wide ascii

                $pdb1 = "rouji\\release\\Install.pdb" wide ascii
                $pdb2 = "rouji\\SvcMain.pdb" wide ascii

        condition:
                (all of ($s*)) or (all of ($e*)) or $pdb1 or $pdb2
}

rule MINIASP_APT1 {
    meta:
        id = "65ljsHLtDzKUMlik0z3J2E"
        fingerprint = "v1_sha256_deaeb988a444b996ac0423598db28184d6b6102fd14437adfd42028477e139d0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "miniasp" wide ascii
                $s2 = "wakeup=" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "command is null!" wide ascii
                $s5 = "device_input.asp?device_t=" wide ascii


        condition:
                all of them
}

rule NEWSREELS_APT1 {
    meta:
        id = "1xs7wY162SLQK7gFoQ8RXi"
        fingerprint = "v1_sha256_f595f052dcd95cb61c66c2f9455e38771a718537356d28715eb3054cf2f1b8b0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0)" wide ascii
                $s2 = "name=%s&userid=%04d&other=%c%s" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "command is null!" wide ascii
                $s5 = "noclient" wide ascii
                $s6 = "wait" wide ascii
                $s7 = "active" wide ascii
                $s8 = "hello" wide ascii


        condition:
                all of them
}

rule SEASALT_APT1 {
    meta:
        id = "6lum9ZpCJAzobvPlLA2eE5"
        fingerprint = "v1_sha256_f25e1c5891c004a1eb93ea35b095c4c3934aa385819c9d150628cd1a7de02098"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.00; Windows 98) KSMM" wide ascii
                $s2 = "upfileok" wide ascii
                $s3 = "download ok!" wide ascii
                $s4 = "upfileer" wide ascii
                $s5 = "fxftest" wide ascii


        condition:
                all of them
}

rule STARSYPOUND_APT1 {
    meta:
        id = "4KrCA2cuNVOHxRy6fNHdZC"
        fingerprint = "v1_sha256_1b52ed9fbf8334293a24a17da01205df99a61fdab79832d18137297efadd0342"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "*(SY)# cmd" wide ascii
                $s2 = "send = %d" wide ascii
                $s3 = "cmd.exe" wide ascii
                $s4 = "*(SY)#" wide ascii


        condition:
                all of them
}

rule SWORD_APT1 {
    meta:
        id = "Z5ZzGij88Jc20XJPiQ5c2"
        fingerprint = "v1_sha256_9e7d502be8ccd5395b8b65e7511fea4ba9eaf5f92f79a604c4006753f52e465a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "@***@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@>>>" wide ascii
                $s2 = "sleep:" wide ascii
                $s3 = "down:" wide ascii
                $s4 = "*========== Bye Bye ! ==========*" wide ascii


        condition:
                all of them
}


rule thequickbrow_APT1 {
    meta:
        id = "45WM5BCFTJ6j3TyHUO0aHO"
        fingerprint = "v1_sha256_d80bdf158a3db3794e859f36af268fe692d857352caf3f6ff5eaefb124f2f607"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "thequickbrownfxjmpsvalzydg" wide ascii


        condition:
                all of them
}


rule TABMSGSQL_APT1 {
    meta:
        id = "26cOnz0AZRWtQT7fUzMtLG"
        fingerprint = "v1_sha256_efa20b0889bf1ad043aec6100b3b0ec26a8bdb0627c87b9a0a16461611463519"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

        strings:
                $s1 = "letusgohtppmmv2.0.0.1" wide ascii
                $s2 = "Mozilla/4.0 (compatible; )" wide ascii
                $s3 = "filestoc" wide ascii
                $s4 = "filectos" wide ascii
                $s5 = "reshell" wide ascii

        condition:
                all of them
}

rule CCREWBACK1
{
    meta:
        id = "34NSonsBXIAyP6H7FLqmu4"
        fingerprint = "v1_sha256_d210c7747bc984646b419ef8d02ac630e2f513db5c0dba84af73ede2f8837f26"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "postvalue" wide ascii
    $b = "postdata" wide ascii
    $c = "postfile" wide ascii
    $d = "hostname" wide ascii
    $e = "clientkey" wide ascii
    $f = "start Cmd Failure!" wide ascii
    $g = "sleep:" wide ascii
    $h = "downloadcopy:" wide ascii
    $i = "download:" wide ascii
    $j = "geturl:" wide ascii
    $k = "1.234.1.68" wide ascii

  condition:
    4 of ($a,$b,$c,$d,$e) or $f or 3 of ($g,$h,$i,$j) or $k
}

rule TrojanCookies_CCREW
{
    meta:
        id = "byqjXrv0QEfZeZoeXHht1"
        fingerprint = "v1_sha256_c63c7bae890e608d24d12545363d42079550770f2547079d0b75a83a782e7bb4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "sleep:" wide ascii
    $b = "content=" wide ascii
    $c = "reqpath=" wide ascii
    $d = "savepath=" wide ascii
    $e = "command=" wide ascii


  condition:
    4 of ($a,$b,$c,$d,$e)
}

rule GEN_CCREW1
{
    meta:
        id = "5Xlkgk3Hd30Aqo1nZR41mT"
        fingerprint = "v1_sha256_25e9ae5529bc198c9e3080da58593a47863950adf7190f21a09f703c517225b7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "W!r@o#n$g" wide ascii
    $b = "KerNel32.dll" wide ascii

  condition:
    any of them
}

rule Elise
{
    meta:
        id = "3ysBecXk1Tp5j54eOtaTgn"
        fingerprint = "v1_sha256_173b6d4a48567bf8e203bf783c5a0077118400078143c60daa5e71c32234898f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "SetElise.pdb" wide ascii

  condition:
    $a
}

rule EclipseSunCloudRAT
{
    meta:
        id = "4MrRpBlTTDMWUUXG7WW9X"
        fingerprint = "v1_sha256_47b9840298bc1143fa82b8bf379e479072e51522a3cd2f800ea77b7518869163"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "Eclipse_A" wide ascii
    $b = "\\PJTS\\" wide ascii
    $c = "Eclipse_Client_B.pdb" wide ascii
    $d = "XiaoME" wide ascii
    $e = "SunCloud-Code" wide ascii
    $f = "/uc_server/data/forum.asp" wide ascii

  condition:
    any of them
}

rule MoonProject
{
    meta:
        id = "DdJiieMRCuoXqBDgUBEr2"
        fingerprint = "v1_sha256_feac9d159675846c3d4bddbf58dd6d9ddbf65b4732e32b9490c524e4d60943f9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "Serverfile is smaller than Clientfile" wide ascii
    $b = "\\M tools\\" wide ascii
    $c = "MoonDLL" wide ascii
        $d = "\\M tools\\" wide ascii

  condition:
    any of them
}

rule ccrewDownloader1
{
    meta:
        id = "4JaRBEI64yFxBz8IjYGUpf"
        fingerprint = "v1_sha256_bd87e71f635512a379cc5dc933c48cdf8939f1134b87e1f827c23e13b8a35d87"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = {DD B5 61 F0 20 47 20 57 D6 65 9C CB 31 1B 65 42}

  condition:
    any of them
}

rule ccrewDownloader2
{
    meta:
        id = "79yqocTzE77WklV37cKdAj"
        fingerprint = "v1_sha256_53190b70d09f849cafa78096ee76258d13e15a2b26bb0a8f19ab53a4bf6a2c78"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "3gZFQOBtY3sifNOl" wide ascii
        $b = "docbWUWsc2gRMv9HN7TFnvnKcrWUUFdAEem9DkqRALoD" wide ascii
        $c = "6QVSOZHQPCMc2A8HXdsfuNZcmUnIqWrOIjrjwOeagILnnScxadKEr1H2MZNwSnaJ" wide ascii

  condition:
    any of them
}


rule ccrewMiniasp
{
    meta:
        id = "1ZugawmdjnxMdFLv9N8tz0"
        fingerprint = "v1_sha256_df9b73fd67b97348930edc3d274aa444360ba9711a416725eb86476d6b575343"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "MiniAsp.pdb" wide ascii
    $b = "device_t=" wide ascii

  condition:
    any of them
}


rule ccrewSSLBack2
{
    meta:
        id = "29DATWTjAaiufB4yub6hxr"
        fingerprint = "v1_sha256_880654a7aff713c0f6dc67643518a6caac856751754a195d22aed7fb7832a1bd"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = {39 82 49 42 BE 1F 3A}

  condition:
    any of them
}

rule ccrewSSLBack3
{
    meta:
        id = "miEOpoUjM7pZ2x5g089Om"
        fingerprint = "v1_sha256_5e0dfcc47feef1976be92ebf3d72e94af50ae9a5889fbbf5d67b4df93f53e3d6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "SLYHKAAY" wide ascii

  condition:
    any of them
}


rule ccrewSSLBack1
{
    meta:
        id = "5ZYvuyLVBmSFvO8fRxqmob"
        fingerprint = "v1_sha256_1810d380257eb53985aab072cc78367e80dfffc95f0a2e708a2278f9df9342d8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "!@#%$^#@!" wide ascii
    $b = "64.91.80.6" wide ascii

  condition:
    any of them
}

rule ccrewDownloader3
{
    meta:
        id = "15rVoLzyYx1u2R0U0eXm4K"
        fingerprint = "v1_sha256_f3500ad5e15b38c1a2a72af1557f9757cceaa1d1df5b57c370586341d895cca3"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "ejlcmbv" wide ascii
        $b = "bhxjuisv" wide ascii
        $c = "yqzgrh" wide ascii
        $d = "uqusofrp" wide ascii
        $e = "Ljpltmivvdcbb" wide ascii
        $f = "frfogjviirr" wide ascii
        $g = "ximhttoskop" wide ascii
  condition:
    4 of them
}


rule ccrewQAZ
{
    meta:
        id = "6Gdesbx1jdWiICsihKGKuL"
        fingerprint = "v1_sha256_c0e591b04e72feabe336927d5843a30bc2aca7e15adbcd25c1ff8ca9e870679a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "!QAZ@WSX" wide ascii

  condition:
    $a
}

rule metaxcd
{
    meta:
        id = "30RrXpHRr5LMhejGbxFAzM"
        fingerprint = "v1_sha256_9d1fb46cd0e31f01d11c6349f10252fa93bca7b4567e3407f77fbebb5f4b3b42"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "<meta xcd=" wide ascii

  condition:
    $a
}

rule MiniASP
{
    meta:
        id = "3T9z5eEo8rQCzBnDx8fsRN"
        fingerprint = "v1_sha256_37803c5387a9443bf2dad8324b6f5de16c095b5daf10c49420f8107bb409fe6f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

strings:
    $KEY = { 71 30 6E 63 39 77 38 65 64 61 6F 69 75 6B 32 6D 7A 72 66 79 33 78 74 31 70 35 6C 73 36 37 67 34 62 76 68 6A }
    $PDB = "MiniAsp.pdb" nocase wide ascii

condition:
    any of them
}

rule DownloaderPossibleCCrew
{
    meta:
        id = "9xun6jY4Cz7fcQDX2hjl3"
        fingerprint = "v1_sha256_082b43e5e12e23b19ceac5229e319acb09d652b35fe9089d3d800fb80cc0bd2e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

  strings:
    $a = "%s?%.6u" wide ascii
    $b = "szFileUrl=%s" wide ascii
    $c = "status=%u" wide ascii
    $d = "down file success" wide ascii
        $e = "Mozilla/4.0 (compatible; MSIE 6.0; Win32)" wide ascii

  condition:
    all of them
}

rule APT1_MAPIGET
{
    meta:
        id = "46B3brii7YCJsi7Ay88Zgb"
        fingerprint = "v1_sha256_382927ff74de18bfdf9f17e14e21fe136b5667108d8aac03fa74b0516a7c9071"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $s1 = "%s\\Attachment.dat" wide ascii
        $s2 = "MyOutlook" wide ascii
        $s3 = "mail.txt" wide ascii
        $s4 = "Recv Time:" wide ascii
        $s5 = "Subject:" wide ascii

    condition:
        all of them
}

rule APT1_LIGHTBOLT
{
    meta:
        id = "2nJObxsM6hjGL6ahmXkJoz"
        fingerprint = "v1_sha256_39fef7753ff2db5306a0c644df019c2c4be7ceb164e46f2e4329311e023d7d8c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $str1 = "bits.exe" wide ascii
        $str2 = "PDFBROW" wide ascii
        $str3 = "Browser.exe" wide ascii
        $str4 = "Protect!" wide ascii
    condition:
        2 of them
}

rule APT1_GETMAIL
{
    meta:
        id = "30GpUouVCKWLCzgsrwlETh"
        fingerprint = "v1_sha256_c5db5d914de4cb85e4bc194323744cf24badb7362df08a82bb1eccb770a27c6a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $stra1 = "pls give the FULL path" wide ascii
        $stra2 = "mapi32.dll" wide ascii
        $stra3 = "doCompress" wide ascii

        $strb1 = "getmail.dll" wide ascii
        $strb2 = "doCompress" wide ascii
        $strb3 = "love" wide ascii
    condition:
        all of ($stra*) or all of ($strb*)
}

rule APT1_GDOCUPLOAD
{
    meta:
        id = "2VOzd3yX2msAFvFX8g8ucr"
        fingerprint = "v1_sha256_64c02fc09ccb5e8d82eb794cb68bf0b08158fe4be9b696fe7be69dfd64dda745"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $str1 = "name=\"GALX\"" wide ascii
        $str2 = "User-Agent: Shockwave Flash" wide ascii
        $str3 = "add cookie failed..." wide ascii
        $str4 = ",speed=%f" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_Y21K
{
    meta:
        id = "7lifggcKWyXOaFcgxyaUbD"
        fingerprint = "v1_sha256_8fd28c7c94c9b6f053f660e2431743ac7310469c5fd3930516d61c59d4cb4ba7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "Y29ubmVjdA" wide ascii // connect
        $2 = "c2xlZXA" wide ascii // sleep
        $3 = "cXVpdA" wide ascii // quit
        $4 = "Y21k" wide ascii // cmd
        $5 = "dW5zdXBwb3J0" wide ascii // unsupport
    condition:
        4 of them
}

rule APT1_WEBC2_YAHOO
{
    meta:
        id = "5IQ0PllcMUTBMX90MF4f1D"
        fingerprint = "v1_sha256_4bd5c30dc65da4460450e8c8509489674f9e07387db39bee4f768c675cf15678"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $http1 = "HTTP/1.0" wide ascii
        $http2 = "Content-Type:" wide ascii
        $uagent = "IPHONE8.5(host:%s,ip:%s)" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_UGX
{
    meta:
        id = "4wmF6AbrtOjuZrXWxzf08e"
        fingerprint = "v1_sha256_6395912e0130fbde412ba7ed5bd78a5e8d419681f11f1bf7076461184ff3acc9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $persis = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" wide ascii
        $exe = "DefWatch.exe" wide ascii
        $html = "index1.html" wide ascii
        $cmd1 = "!@#tiuq#@!" wide ascii
        $cmd2 = "!@#dmc#@!" wide ascii
        $cmd3 = "!@#troppusnu#@!" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_TOCK
{
    meta:
        id = "2a3lOx5D37yIjHFhYdJGb5"
        fingerprint = "v1_sha256_f825687fb2822d6bf3ed98dcf254e46ddc88603124a27a0764e7bde4f23f6435"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "InprocServer32" wide ascii
        $2 = "HKEY_PERFORMANCE_DATA" wide ascii
        $3 = "<!---[<if IE 5>]id=" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_TABLE
{
    meta:
        id = "5QxvLGGY7A7fU6LbYk8rll"
        fingerprint = "v1_sha256_e5d01f3f6149927880f05ddc8dc2492af99ff2c2a13a7c0bcb47b26fd6da9e30"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $msg1 = "Fail To Execute The Command" wide ascii
        $msg2 = "Execute The Command Successfully" wide ascii
        $gif1 = /\w+\.gif/
        $gif2 = "GIF89" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_RAVE
{
    meta:
        id = "3NOwZuKOf6r884ru97l3TD"
        fingerprint = "v1_sha256_db2927bcde9078e98ad10be57646841ffb27e856700f210888c69f15c6771bb6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "iniet.exe" wide ascii
        $2 = "cmd.exe" wide ascii
        $3 = "SYSTEM\\CurrentControlSet\\Services\\DEVFS" wide ascii
        $4 = "Device File System" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_QBP
{
    meta:
        id = "2JnZ9yvDG6yjbdp79UN4J9"
        fingerprint = "v1_sha256_2c10dec4c102026ec9f6d09fa125a5bf090038771784e51c1980697aa4cbe6d9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "2010QBP" wide ascii
        $2 = "adobe_sl.exe" wide ascii
        $3 = "URLDownloadToCacheFile" wide ascii
        $4 = "dnsapi.dll" wide ascii
        $5 = "urlmon.dll" wide ascii
    condition:
        4 of them
}

rule APT1_WEBC2_KT3
{
    meta:
        id = "5Daaz2zQsjtZZJNuFgxvhC"
        fingerprint = "v1_sha256_a0fa4b6f1a312450e278fc027bf9354e8fe656efffec0be1c00231d8769cac31"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "*!Kt3+v|" wide ascii
        $2 = " s:" wide ascii
        $3 = " dne" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_HEAD
{
    meta:
        id = "5hKl3uQ7oharIP3BfCY5Mz"
        fingerprint = "v1_sha256_552cc24379a8f7aad7b88570c6c82c16bfbf7e75f9f64bbc202be69e5811ebfa"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "Ready!" wide ascii
        $2 = "connect ok" wide ascii
        $3 = "WinHTTP 1.0" wide ascii
        $4 = "<head>" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_GREENCAT
{
    meta:
        id = "3D5YodjtPgNJcmVf1PU94J"
        fingerprint = "v1_sha256_bca96294b6e15a984199731b989e5cfe36d5072a53a82605b764ad7f533c0577"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "reader_sl.exe" wide ascii
        $2 = "MS80547.bat" wide ascii
        $3 = "ADR32" wide ascii
        $4 = "ControlService failed!" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_DIV
{
    meta:
        id = "1fZysuJpmMqLMdr11u8GAP"
        fingerprint = "v1_sha256_c76fa2af3f99f8bb6f2550e3f83532a39f58f61aee305e5dd605559b48eef9e1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "3DC76854-C328-43D7-9E07-24BF894F8EF5" wide ascii
        $2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $3 = "Hello from MFC!" wide ascii
        $4 = "Microsoft Internet Explorer" wide ascii
    condition:
        3 of them
}

rule APT1_WEBC2_CSON
{
    meta:
        id = "3IdjhSu5W5WNokjkdjT2Ik"
        fingerprint = "v1_sha256_17c203deb1ea995ca86baac5e2133438f3eb3c88ce9544544aa580b738d08a04"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $httpa1 = "/Default.aspx?INDEX=" wide ascii
        $httpa2 = "/Default.aspx?ID=" wide ascii
        $httpb1 = "Win32" wide ascii
        $httpb2 = "Accept: text*/*" wide ascii
        $exe1 = "xcmd.exe" wide ascii
        $exe2 = "Google.exe" wide ascii
    condition:
        1 of ($exe*) and 1 of ($httpa*) and all of ($httpb*)
}

rule APT1_WEBC2_CLOVER
{
    meta:
        id = "51Sk0Q5GSgDtv88fSeezPg"
        fingerprint = "v1_sha256_2e7e3566ec7563c38fbada66501796025daff9f7d1a524878a910ac8184b7039"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $msg1 = "BUILD ERROR!" wide ascii
        $msg2 = "SUCCESS!" wide ascii
        $msg3 = "wild scan" wide ascii
        $msg4 = "Code too clever" wide ascii
        $msg5 = "insufficient lookahead" wide ascii
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; SV1)" wide ascii
        $ua2 = "Mozilla/5.0 (Windows; Windows NT 5.1; en-US; rv:1.8.0.12) Firefox/1.5.0.12" wide ascii
    condition:
        2 of ($msg*) and 1 of ($ua*)
}

rule APT1_WEBC2_BOLID
{
    meta:
        id = "4MLHTobpoTEUJcO0yY4kxt"
        fingerprint = "v1_sha256_90e5ba7818ff0f1c948f850aa85d75bf6c9d0f1ac756f3a9352b862517168072"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $vm = "VMProtect" wide ascii
        $http = "http://[c2_location]/[page].html" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_ADSPACE
{
    meta:
        id = "6FMrERbASEuLB7RhxZpq8w"
        fingerprint = "v1_sha256_40a26a29b97caec6839b5e71d08593576ac8e1a32443a74ba501215dfa056ff2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "<!---HEADER ADSPACE style=" wide ascii
        $2 = "ERSVC.DLL" wide ascii
    condition:
        all of them
}

rule APT1_WEBC2_AUSOV
{
    meta:
        id = "2N0HQIOjyscsgbjxWLhky8"
        fingerprint = "v1_sha256_a2bb75f0ac1a9f99aa463f59e02ce925a1628861be4abdfb6df2872f0fa2325c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "ntshrui.dll" wide ascii
        $2 = "%SystemRoot%\\System32\\" wide ascii
        $3 = "<!--DOCHTML" wide ascii
        $4 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" wide ascii
        $5 = "Ausov" wide ascii
    condition:
        4 of them
}

rule APT1_WARP
{
    meta:
        id = "5IqOrkLe0317wn5wuVdJDh"
        fingerprint = "v1_sha256_a282b4cb41fe3f950149394a722b2dc2cfcf478035120fa42439d4355d01f141"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $err1 = "exception..." wide ascii
        $err2 = "failed..." wide ascii
        $err3 = "opened..." wide ascii
        $exe1 = "cmd.exe" wide ascii
        $exe2 = "ISUN32.EXE" wide ascii
    condition:
        2 of ($err*) and all of ($exe*)
}

rule APT1_TARSIP_ECLIPSE
{
    meta:
        id = "350b0KIVY8D6X5qXVWl39W"
        fingerprint = "v1_sha256_0b4715f43288fe7b9f6e37482d504e1a4db4a5bc7ca423448c4f0f2ba624f823"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $1 = "\\pipe\\ssnp" wide ascii
        $2 = "toobu.ini" wide ascii
        $3 = "Serverfile is not bigger than Clientfile" wide ascii
        $4 = "URL download success" wide ascii
    condition:
        3 of them
}

rule APT1_TARSIP_MOON
{
    meta:
        id = "4Z5wGk1EX64IeqZvU4SDl9"
        fingerprint = "v1_sha256_9a52ca672cd647cca1d7045cb41dfc38e9ed51656c82113a4047907ad811ceb2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $s1 = "\\XiaoME\\SunCloud-Code\\moon" wide ascii
        $s2 = "URL download success!" wide ascii
        $s3 = "Kugoosoft" wide ascii
        $msg1 = "Modify file failed!! So strange!" wide ascii
        $msg2 = "Create cmd process failed!" wide ascii
        $msg3 = "The command has not been implemented!" wide ascii
        $msg4 = "Runas success!" wide ascii
        $onec1 = "onec.php" wide ascii
        $onec2 = "/bin/onec" wide ascii
    condition:
        1 of ($s*) and 1 of ($msg*) and 1 of ($onec*)
}

private rule APT1_payloads
{
    meta:
        id = "2slfnGwU5XPVIJyCXXQSOf"
        fingerprint = "v1_sha256_275199b01115cc70ed2a3d98527d995b16165e49c31f292ffd05fa25a72af8b3"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $pay1 = "rusinfo.exe" wide ascii
        $pay2 = "cmd.exe" wide ascii
        $pay3 = "AdobeUpdater.exe" wide ascii
        $pay4 = "buildout.exe" wide ascii
        $pay5 = "DefWatch.exe" wide ascii
        $pay6 = "d.exe" wide ascii
        $pay7 = "em.exe" wide ascii
        $pay8 = "IMSCMig.exe" wide ascii
        $pay9 = "localfile.exe" wide ascii
        $pay10 = "md.exe" wide ascii
        $pay11 = "mdm.exe" wide ascii
        $pay12 = "mimikatz.exe" wide ascii
        $pay13 = "msdev.exe" wide ascii
        $pay14 = "ntoskrnl.exe" wide ascii
        $pay15 = "p.exe" wide ascii
        $pay16 = "otepad.exe" wide ascii
        $pay17 = "reg.exe" wide ascii
        $pay18 = "regsvr.exe" wide ascii
        $pay19 = "runinfo.exe" wide ascii
        $pay20 = "AdobeUpdate.exe" wide ascii
        $pay21 = "inetinfo.exe" wide ascii
        $pay22 = "svehost.exe" wide ascii
        $pay23 = "update.exe" wide ascii
        $pay24 = "NTLMHash.exe" wide ascii
        $pay25 = "wpnpinst.exe" wide ascii
        $pay26 = "WSDbg.exe" wide ascii
        $pay27 = "xcmd.exe" wide ascii
        $pay28 = "adobeup.exe" wide ascii
        $pay29 = "0830.bin" wide ascii
        $pay30 = "1001.bin" wide ascii
        $pay31 = "a.bin" wide ascii
        $pay32 = "ISUN32.EXE" wide ascii
        $pay33 = "AcroRD32.EXE" wide ascii
        $pay34 = "INETINFO.EXE" wide ascii
    condition:
        1 of them
}

private rule APT1_RARSilent_EXE_PDF
{
    meta:
        id = "4ZgG6u69xtEg6vEbX71EGk"
        fingerprint = "v1_sha256_5cf09d4f15590ca729b48c3a469e0bfa9d9884ca36deaeae724fc7ef9272c688"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $winrar1 = "WINRAR.SFX" wide ascii
        $winrar2 = ";The comment below contains SFX script commands" wide ascii
        $winrar3 = "Silent=1" wide ascii

        $str1 = /Setup=[\s\w\"]+\.(exe|pdf|doc)/
        $str2 = "Steup=\"" wide ascii
    condition:
        all of ($winrar*) and 1 of ($str*)
}

rule APT1_aspnetreport
{
    meta:
        id = "7Uh6D083x4BdGNdsm6qLdO"
        fingerprint = "v1_sha256_2afcf35cdd281b9e13ea86601ab78bf7814373537ca4c52b309a0e5442c4bcbc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $url = "aspnet_client/report.asp" wide ascii
        $param = "name=%s&Gender=%c&Random=%04d&SessionKey=%s" wide ascii
    condition:
        $url and $param and APT1_payloads
}

rule APT1_Revird_svc
{
    meta:
        id = "5yAAYUwwq0vb09TCpD1VzA"
        fingerprint = "v1_sha256_32f7e8039d5bea4bf547fc8c5e512548f8d862b3ca04356c54ff61ae2ba7de22"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $dll1 = "nwwwks.dll" wide ascii
        $dll2 = "rdisk.dll" wide ascii
        $dll3 = "skeys.dll" wide ascii
        $dll4 = "SvcHost.DLL.log" wide ascii
        $svc1 = "InstallService" wide ascii
        $svc2 = "RundllInstallA" wide ascii
        $svc3 = "RundllUninstallA" wide ascii
        $svc4 = "ServiceMain" wide ascii
        $svc5 = "UninstallService" wide ascii
    condition:
        1 of ($dll*) and 2 of ($svc*)
}

rule APT1_letusgo
{
    meta:
        id = "2n3Qs5RezaRcBX34Hf7jDh"
        fingerprint = "v1_sha256_6509e477f706d0ea079bfebc42b5789f001addfd5c92a7aa8764d76d45683bac"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $letus = /letusgo[\w]+v\d\d?\./
    condition:
        $letus
}

rule APT1_dbg_mess
{
    meta:
        id = "3nYT4ZM0zlq1AhMuEser31"
        fingerprint = "v1_sha256_63e614f78b5f137ef68261b6ff53ccb48d20e58f185e2d6ca064adf41ad8b11b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $dbg1 = "Down file ok!" wide ascii
        $dbg2 = "Send file ok!" wide ascii
        $dbg3 = "Command Error!" wide ascii
        $dbg4 = "Pls choose target first!" wide ascii
        $dbg5 = "Alert!" wide ascii
        $dbg6 = "Pls press enter to make sure!" wide ascii
        $dbg7 = "Are you sure to " wide ascii
    condition:
        4 of them and APT1_payloads
}

rule APT1_known_malicious_RARSilent
{
    meta:
        id = "42Ujnpil6LUboHnv1jxvGV"
        fingerprint = "v1_sha256_d3a07e0332b357f0921a8b427d873fe3814aecf1c7c15b1ca3fb5ad359bbd9a9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "NA"
        category = "INFO"
        info = "COMMENTCREW-THREAT-APT1"

    strings:
        $str1 = "Analysis And Outlook.doc\"" wide ascii
        $str2 = "North Korean launch.pdf\"" wide ascii
        $str3 = "Dollar General.doc\"" wide ascii
        $str4 = "Dow Corning Corp.pdf\"" wide ascii
    condition:
        1 of them and APT1_RARSilent_EXE_PDF
}
