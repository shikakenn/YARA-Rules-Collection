rule spyeye : banker
{
    meta:
        id = "4jrer11RGwN2GAV4xKks3x"
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
        id = "7bJtLd8BbwzsFc5JIxEz1q"
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
