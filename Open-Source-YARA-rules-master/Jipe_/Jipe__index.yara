rule AutoIt : packer
{
    meta:
        id = "5qqAAoOMNzH25BSNQn9b1k"
        fingerprint = "v1_sha256_bfe726f71e28ddab64120894a9b5d12af340664f45390b3ee39b746f63534338"
        version = "1.0"
        date = "2013-02-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "AutoIT packer"
        category = "INFO"
        filetype = "memory"

    strings:	
        $a = "This is a compiled AutoIt script. AV researchers please email avsupport@autoitscript.com for support."

    condition:
        $a
}
rule BlackShades : rat
{
    meta:
        id = "1whBEhVAjVMbGfiLXoRqrm"
        fingerprint = "v1_sha256_194db107a3ab29b8d3e76fb3861b97101f53dad7325ccea1ba13a12095b11dea"
        version = "1.0"
        date = "2013-01-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "BlackShades"
        category = "INFO"
        filetype = "memory"

    strings:
        $a = { 42 00 6C 00 61 00 63 00 6B 00 73 00 68 00 61 00 64 00 65 00 73 }
        $b = { 36 00 3C 00 32 00 20 00 32 00 32 00 26 00 31 00 39 00 3E 00 1D 00 17 00 17 00 1C 00 07 00 1B 00 03 00 07 00 28 00 23 00 0C 00 1D 00 10 00 1B 00 12 00 00 00 28 00 37 00 10 00 01 00 06 00 11 00 0B 00 07 00 22 00 11 00 17 00 00 00 1D 00 1B 00 0B 00 2F 00 26 00 01 00 0B }
        $c = { 62 73 73 5F 73 65 72 76 65 72 }
        $d = { 43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44 }
        $e = { 6D 6F 64 49 6E 6A 50 45 }
        $apikey = "f45e373429c0def355ed9feff30eff9ca21eec0fafa1e960bea6068f34209439"

    condition:
        any of ($a, $b, $c, $d, $e) or $apikey		
}


rule Bolonyokte : rat 
{
    meta:
        id = "4B9D0zoz6aEjczIrHycqPg"
        fingerprint = "v1_sha256_9ebe036fa6a3e5acf21c0d0e017ff0266bb20eb15432748a98892799c39a6dc4"
        version = "1.0"
        date = "2013-02-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "UnknownDotNet RAT - Bolonyokte"
        category = "INFO"
        filetype = "memory"

    strings:
        $campaign1 = "Bolonyokte" ascii wide
        $campaign2 = "donadoni" ascii wide
        
        $decoy1 = "nyse.com" ascii wide
        $decoy2 = "NYSEArca_Listing_Fees.pdf" ascii wide
        $decoy3 = "bf13-5d45cb40" ascii wide
        
        $artifact1 = "Backup.zip"  ascii wide
        $artifact2 = "updates.txt" ascii wide
        $artifact3 = "vdirs.dat" ascii wide
        $artifact4 = "default.dat"
        $artifact5 = "index.html"
        $artifact6 = "mime.dat"
        
        $func1 = "FtpUrl"
        $func2 = "ScreenCapture"
        $func3 = "CaptureMouse"
        $func4 = "UploadFile"

        $ebanking1 = "Internet Banking" wide
        $ebanking2 = "(Online Banking)|(Online banking)"
        $ebanking3 = "(e-banking)|(e-Banking)" nocase
        $ebanking4 = "login"
        $ebanking5 = "en ligne" wide
        $ebanking6 = "bancaires" wide
        $ebanking7 = "(eBanking)|(Ebanking)" wide
        $ebanking8 = "Anmeldung" wide
        $ebanking9 = "internet banking" nocase wide
        $ebanking10 = "Banking Online" nocase wide
        $ebanking11 = "Web Banking" wide
        $ebanking12 = "Power"

    condition:
        any of ($campaign*) or 2 of ($decoy*) or 2 of ($artifact*) or all of ($func*) or 3 of ($ebanking*)
}

rule Cerberus : rat
{
    meta:
        id = "6HlVwVzJ2cXolRQPi9k0ZB"
        fingerprint = "v1_sha256_5c27422771a1d51ccf74af95d085a4d2f09f6644b7b3e90b243fd31bf1417e22"
        version = "1.0"
        date = "2013-01-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Cerberus"
        category = "INFO"
        filetype = "memory"

    strings:
        $checkin = "Ypmw1Syv023QZD"
        $clientpong = "wZ2pla"
        $serverping = "wBmpf3Pb7RJe"
        $generic = "cerberus" nocase

    condition:
        any of them
}
rule citadel13xy : banker
{
    meta:
        id = "3xDJDohYqyV6R2KJlb855J"
        fingerprint = "v1_sha256_d8fecb4722f899417a183223f1b1c749934203f844b08438bd5af14815450543"
        version = "1.0"
        date = "2013-01-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Citadel 1.5.x.y trojan banker"
        category = "INFO"
        filetype = "memory"

    strings:
        $a = "Coded by BRIAN KREBS for personnal use only. I love my job & wife."
        $b = "http://%02x%02x%02x%02x%02x%02x%02x%02x.com/%02x%02x%02x%02x/%02x%02x%02x%02x%02x.php"
        $c = "%BOTID%"
        $d = "%BOTNET%"
        $e = "cit_video.module"
        $f = "bc_remove"
        $g = "bc_add"
        $ggurl = "http://www.google.com/webhp"

    condition:
        3 of them
}
rule DarkComet : rat
{
    meta:
        id = "nl8U7Flqja3A6XIMkF1mk"
        fingerprint = "v1_sha256_b0548831f9ac5f27709d6a4e757977dcfb7c73eda3dbb0bfa122c714e2ad3a2c"
        version = "1.0"
        date = "2013-01-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "DarkComet"
        category = "INFO"
        filetype = "memory"

    strings:
        $a = "#BEGIN DARKCOMET DATA --"
        $b = "#EOF DARKCOMET DATA --"
        $c = "DC_MUTEX-"
        $k1 = "#KCMDDC5#-890"
        $k2 = "#KCMDDC51#-890"

    condition:
        any of them
}
rule dotfuscator : packer
{
    meta:
        id = "6Gnq8PJsnCEiqfZfk7rFG5"
        fingerprint = "v1_sha256_c18a24fe408111e04fca411f9f7814d9477cd5e93822df894f8b91b3dc778bfd"
        version = "1.0"
        date = "2013-02-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Dotfuscator"
        category = "INFO"
        filetype = "memory"

    strings:
        $a = "Obfuscated with Dotfuscator"

    condition:
        $a
}
rule ice_ix_12xy : banker
{
    meta:
        id = "5tT6qxxWHxWB0Hi9vh2wCN"
        fingerprint = "v1_sha256_93b8a70c2034ad5178f3da91e3fdcff13e77f13c5547fe54fe8db86603ab93a0"
        version = "1.0"
        date = "2013-01-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "ICE-IX 1.2.x.y trojan banker"
        category = "INFO"
        filetype = "memory"

    strings:
        $regexp1= /bn1=.{32}&sk1=[0-9a-zA-Z]{32}/
        $a = "bn1="
        $b = "&sk1="
        $c = "mario"								//HardDrive GUID artifact
        $d = "FIXME"
        $e = "RFB 003.003"							//VNC artifact
        $ggurl = "http://www.google.com/webhp"

    condition:
        $regexp1 or ($a and $b) or all of ($c,$d,$e,$ggurl) 
}
rule jRAT_conf : rat 
{
    meta:
        id = "6t1QVbDKcvMZ9Rkq7BjEAP"
        fingerprint = "v1_sha256_03fe6628789c3660c32b697ec3e5735588e8892135c30ff63a5fef72d675a2c9"
        version = "1.0"
        date = "2013-10-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "jRAT configuration"
        category = "INFO"
        filetype = "memory"
        ref1 = "https://github.com/MalwareLu/config_extractor/blob/master/config_jRAT.py"
        ref2 = "http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html"

    strings:
        $a = "/port=[0-9]{1,5}SPLIT/" 

    condition: 
        $a
}
rule NetWiredRC_B : rat 
{
    meta:
        id = "3xOu04Kns05qSwaqZ7dSYJ"
        fingerprint = "v1_sha256_fe7d383c31f52f1667721a8593587b2f1c1120fe7fa80ea9b9e63e5090b0b50c"
        version = "1.1"
        date = "2014-12-23"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "NetWiredRC"
        category = "INFO"
        filetype = "memory"

    strings:
        $mutex = "LmddnIkX"

        $str1 = "%s.Identifier"
        $str2 = "%d:%I64u:%s%s;"
        $str3 = "%s%.2d-%.2d-%.4d"
        $str4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
        $str5 = "%.2d/%.2d/%d %.2d:%.2d:%.2d"
        
        $klg1 = "[Backspace]"
        $klg2 = "[Enter]"
        $klg3 = "[Tab]"
        $klg4 = "[Arrow Left]"
        $klg5 = "[Arrow Up]"
        $klg6 = "[Arrow Right]"
        $klg7 = "[Arrow Down]"
        $klg8 = "[Home]"
        $klg9 = "[Page Up]"
        $klg10 = "[Page Down]"
        $klg11 = "[End]"
        $klg12 = "[Break]"
        $klg13 = "[Delete]"
        $klg14 = "[Insert]"
        $klg15 = "[Print Screen]"
        $klg16 = "[Scroll Lock]"
        $klg17 = "[Caps Lock]"
        $klg18 = "[Alt]"
        $klg19 = "[Esc]"
        $klg20 = "[Ctrl+%c]"

    condition: 
        $mutex or (1 of ($str*) and 1 of ($klg*))
}

rule office_document_vba
{
    meta:
        id = "3YlIFDuq8EjY2Qc0hbIEgo"
        fingerprint = "v1_sha256_f51ad520618a62df71792ba88778e05f5260d08688eee6557ac0e38f38685a71"
        version = "1.0"
        date = "2013-12-17"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Office document with embedded VBA"
        category = "INFO"
        reference = "N/A"

    strings:
        $officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
        $zipmagic = "PK"

        $97str1 = "_VBA_PROJECT_CUR" wide
        $97str2 = "VBAProject"
        $97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }

        $xmlstr1 = "vbaProject.bin"
        $xmlstr2 = "vbaData.xml"

    condition:
        ($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}
rule plugX : rat
{
    meta:
        id = "Lbs3HCKO9tj9YNIylews0"
        fingerprint = "v1_sha256_b2e981571cf6e2893bd51a82d3233baca76d21b6591d6e012aded278324ff3df"
        version = "1.0"
        date = "2014-05-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "PlugX RAT"
        category = "INFO"
        filetype = "memory"
        ref1 = "https://github.com/mattulm/IR-things/blob/master/volplugs/plugx.py"

    strings:
        $v1a = { 47 55 4C 50 00 00 00 00 }
        $v1b = "/update?id=%8.8x" 
        $v1algoa = { BB 33 33 33 33 2B } 
        $v1algob = { BB 44 44 44 44 2B } 
        $v2a = "Proxy-Auth:" 
        $v2b = { 68 A0 02 00 00 } 
        $v2k = { C1 8F 3A 71 } 
        
    condition: 
        $v1a at 0 or $v1b or (($v2a or $v2b) and (($v1algoa and $v1algob) or $v2k))
}
rule poisonivy : rat
{
    meta:
        id = "6TztPSanr4DSILq5TeRxs5"
        fingerprint = "v1_sha256_4d2a865697afc0ac3734b49c1cc40579d9422e5fe0ad177308611f82df4110b2"
        version = "1.0"
        date = "2013-02-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Poison Ivy"
        category = "INFO"
        filetype = "memory"
        ref1 = "https://code.google.com/p/volatility/source/browse/trunk/contrib/plugins/malware/poisonivy.py"

    strings:
        $a = { 53 74 75 62 50 61 74 68 ?? 53 4F 46 54 57 41 52 45 5C 43 6C 61 73 73 65 73 5C 68 74 74 70 5C 73 68 65 6C 6C 5C 6F 70 65 6E 5C 63 6F 6D 6D 61 6E 64 [22] 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 41 63 74 69 76 65 20 53 65 74 75 70 5C 49 6E 73 74 61 6C 6C 65 64 20 43 6F 6D 70 6F 6E 65 6E 74 73 5C } 
        
    condition:
        $a
}
rule qadars : banker
{
    meta:
        id = "4hzbACgNl69IirhUOzAi01"
        fingerprint = "v1_sha256_faa176d9b9d14947eaa6445c37bccbf5f55475def58e066d638587fc67cde721"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Qadars - Mobile part. Maybe Perkele."
        category = "INFO"
        filetype = "memory"
        ref1 = "http://www.lexsi-leblog.fr/cert/qadars-nouveau-malware-bancaire-composant-mobile.html"

    strings:
        $cmd1 = "m?D"
        $cmd2 = "m?S"
        $cmd3 = "ALL"
        $cmd4 = "FILTER"
        $cmd5 = "NONE"
        $cmd6 = "KILL"
        $cmd7 = "CANCEL"
        $cmd8 = "SMS"
        $cmd9 = "DIVERT"
        $cmd10 = "MESS"
        $nofilter = "nofilter1111111"
        $botherderphonenumber1 = "+380678409210"

    condition:
        all of ($cmd*) or $nofilter or any of ($botherderphonenumber*)
}
rule shylock :  banker
{
    meta:
        id = "1omfh1Rvc1782vbVxryrjn"
        fingerprint = "v1_sha256_b1e23d67d036361b707a2af7b4f9f8b07d652556c302f7b303db001e71ce2681"
        version = "1.0"
        date = "2013-12-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Shylock Banker"
        category = "INFO"
        ref1 = "http://iocbucket.com/iocs/1b4660d57928df5ca843c21df0b2adb117026cba"
        ref2 = "http://www.trusteer.com/blog/merchant-fraud-returns-%E2%80%93-shylock-polymorphic-financial-malware-infections-rise"
        ref3 = "https://www.csis.dk/en/csis/blog/3811/"

    strings:
        $process1 = "MASTER"
        $process2 = "_SHUTDOWN"
        $process3 = "EVT_VNC"
        $process4 = "EVT_BACK"
        $process5 = "EVT_VNC"
        $process6 = "IE_Hook::GetRequestInfo"
        $process7 = "FF_Hook::getRequestInfo"
        $process8 = "EX_Hook::CreateProcess"
        $process9 = "hijackdll.dll"
        $process10 = "MTX_"
        $process11 = "FF::PR_WriteHook entry"
        $process12 = "FF::PR_WriteHook exit"
        $process13 = "HijackProcessAttach::*** MASTER *** MASTER *** MASTER *** %s PID=%u"
        $process14 = "HijackProcessAttach::entry"
        $process15 = "FF::BEFORE INJECT"
        $process16 = "FF::AFTER INJECT"
        $process17 = "IE::AFTER INJECT"
        $process18 = "IE::BEFORE INJECT"
        $process19 = "*** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** VNC *** %s"
        $process20 = "*** LOG INJECTS *** %s"
        $process21 = "*** inject to process %s not allowed"
        $process22 = "*** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** BackSocks *** %s"
        $process23 = ".?AVFF_Hook@@"
        $process24 = ".?AVIE_Hook@@"
        $process25 = "Inject::InjectDllFromMemory"
        $process26 = "BadSocks.dll"	
        $domain1 = "extensadv.cc"
        $domain2 = "topbeat.cc"
        $domain3 = "brainsphere.cc"
        $domain4 = "commonworldme.cc"
        $domain5 = "gigacat.cc"
        $domain6 = "nw-serv.cc"
        $domain7 = "paragua-analyst.cc"
        
    condition:
        3 of ($process*) or any of ($domain*)
}
rule spyeye : banker
{
    meta:
        id = "6kRK1QgrdBoDuK4wWAGLqU"
        fingerprint = "v1_sha256_1b5f9463348430e48fb22c555dffd8ba033c12cd8729c5e7ce30bbc166f0cf47"
        version = "1.0"
        date = "2012-05-23"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "SpyEye X.Y memory"
        category = "INFO"
        filetype = "memory"

    strings:
        $spyeye = "SpyEye"
        $a = "%BOTNAME%"
        $b = "globplugins"
        $c = "data_inject"
        $d = "data_before"
        $e = "data_after"
        $f = "data_end"
        $g = "bot_version"
        $h = "bot_guid"
        $i = "TakeBotGuid"
        $j = "TakeGateToCollector"
        $k = "[ERROR] : Omfg! Process is still active? Lets kill that mazafaka!"
        $l = "[ERROR] : Update is not successfull for some reason"
        $m = "[ERROR] : dwErr == %u"
        $n = "GRABBED DATA"
        
    condition:
        $spyeye or (any of ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n))
}

rule spyeye_plugins : banker
{
    meta:
        id = "1M2n6T4w73Qg83vAAC37j4"
        fingerprint = "v1_sha256_16b437ece13f7c3b4412942dfb5f121c2d391827e053b02fe51c77525827a7c7"
        version = "1.0"
        date = "2012-05-23"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "SpyEye X.Y Plugins memory"
        category = "INFO"
        filetype = "memory"

    strings:
        $a = "webfakes.dll"
        $b = "config.dat"			//may raise some FP
        $c = "collectors.txt"
        $d = "webinjects.txt"
        $e = "screenshots.txt"
        $f = "billinghammer.dll"
        $g = "block.dll"			//may raise some FP
        $h = "bugreport.dll"		//may raise some FP
        $i = "ccgrabber.dll"
        $j = "connector2.dll"
        $k = "creditgrab.dll"
        $l = "customconnector.dll"
        $m = "ffcertgrabber.dll"
        $n = "ftpbc.dll"
        $o = "rdp.dll"				//may raise some FP
        $p = "rt_2_4.dll"
        $q = "socks5.dll"			//may raise some FP
        $r = "spySpread.dll"
        $s = "w2chek4_4.dll"
        $t = "w2chek4_6.dll"
    
    condition:
        any of them
}
rule swrort : rat
{
    meta:
        id = "1uya4OfAAivrLbwqkHCxOF"
        fingerprint = "v1_sha256_dae0847b2dfeec288ee157b09db924756b686afe2a3b629105c5708874e67255"
        version = "1.0"
        date = "2013-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Trojan:Win32/Swrort / Downloader"
        category = "INFO"
        filetype = "memory"

    strings:
        $path = "c:\\code\\httppump\\inner\\objchk_wxp_x86\\i386\\i.pdb"

    condition:
        all of them
}
rule TerminatorRat : rat 
{
    meta:
        id = "1v3IN4Tpy3IO7MkRhf7aMX"
        fingerprint = "v1_sha256_bad656d9b81392a0b7052fcea57d3b603c8e8fb5f94c8632b2bfa2a312f0e819"
        version = "1.0"
        date = "2013-10-24"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Terminator RAT"
        category = "INFO"
        filetype = "memory"
        ref1 = "http://www.fireeye.com/blog/technical/malware-research/2013/10/evasive-tactics-terminator-rat.html"

    strings:
        $a = "Accelorator"
        $b = "<html><title>12356</title><body>"

    condition:
        all of them
}

rule xtremrat : rat
{
    meta:
        id = "5aE4r8XqXnnlV9zwHU0QIl"
        fingerprint = "v1_sha256_56a079bcd12668a9f810bbe5b85b8816e44444022b32b06b02af56f1af5b0178"
        version = "1.0"
        date = "2012-07-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Xtrem RAT v3.5"
        category = "INFO"
        filetype = "memory"

    strings:
        $a = "XTREME" wide
        $b = "XTREMEBINDER" wide
        $c = "STARTSERVERBUFFER" wide
        $d = "SOFTWARE\\XtremeRAT" wide
        $e = "XTREMEUPDATE" wide
        $f = "XtremeKeylogger" wide
        $g = "myversion|3.5" wide
        $h = "xtreme rat" wide nocase
    condition:
        2 of them
}
