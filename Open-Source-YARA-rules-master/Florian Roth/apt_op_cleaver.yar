/* Op Cleaver -------------------------------------------------------------- */

rule OPCLEAVER_BackDoorLogger
{
    meta:
        id = "5tjKNO39VD2wULqaZq45Eb"
        fingerprint = "v1_sha256_c7716b21e85d7e9fb1e1503071c6cd7dc2f4713051e0b03013e3d123a0d800a6"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Keylogger used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "BackDoorLogger"
        $s2 = "zhuAddress"
    condition:
        all of them
}

rule OPCLEAVER_Jasus
{
    meta:
        id = "13xiku3tGXykCcBaqehl89"
        fingerprint = "v1_sha256_7d6cd7f0f264a0bfdc6af422baa1a0e257cb8f4c39a2cb27a1edaf70201e8564"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "ARP cache poisoner used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "pcap_dump_open"
        $s2 = "Resolving IPs to poison..."
        $s3 = "WARNNING: Gateway IP can not be found"
    condition:
        all of them
}

rule OPCLEAVER_LoggerModule
{
    meta:
        id = "6TO2yHV4JeDs1jCddjejDr"
        fingerprint = "v1_sha256_dd937bc3fc7054874a3c61bbef859dd8a8ec37872a30be6d3e1776957f98db80"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Keylogger used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "%s-%02d%02d%02d%02d%02d.r"
        $s2 = "C:\\Users\\%s\\AppData\\Cookies\\"
    condition:
        all of them
}

rule OPCLEAVER_NetC
{
    meta:
        id = "59GxuFJWTR0Hh9IikeQwyk"
        fingerprint = "v1_sha256_7da739c33da91f07e9e35ceab88a37477372998b4cf4b692b8d26cd1a4d936de"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Net Crawler used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "NetC.exe" wide
        $s2 = "Net Service"
    condition:
        all of them
}

rule OPCLEAVER_ShellCreator2
{
    meta:
        id = "4g74Qi9xfoNSA72RWY4rTo"
        fingerprint = "v1_sha256_5422cf4e4809c1183c3c9870d9a5ddcf806082d8cae81a014255f5f18576101d"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Shell Creator used by attackers in Operation Cleaver to create ASPX web shells"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "ShellCreator2.Properties"
        $s2 = "set_IV"
    condition:
        all of them
}

rule OPCLEAVER_SmartCopy2
{
    meta:
        id = "2ql2guGNrnRdrReNvyBtMF"
        fingerprint = "v1_sha256_5b83588fa80558cd387511d38e9d1c51c488216b9cd27e848d8bdc59cd8ce348"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Malware or hack tool used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "SmartCopy2.Properties"
        $s2 = "ZhuFrameWork"
    condition:
        all of them
}

rule OPCLEAVER_SynFlooder
{
    meta:
        id = "1HlNtutOWufzzHAa4egNcD"
        fingerprint = "v1_sha256_3b9a2ac3363d1f7bc02671290f06e97598c68eb22bb134b9149a371a9dfcb1aa"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Malware or hack tool used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "Unable to resolve [ %s ]. ErrorCode %d"
        $s2 = "your target’s IP is : %s"
        $s3 = "Raw TCP Socket Created successfully."
    condition:
        all of them
}

rule OPCLEAVER_TinyZBot
{
    meta:
        id = "26q64Oe6S4fAw8HqCBG1Ve"
        fingerprint = "v1_sha256_fdc41fbec71602e13105a03a4f44319a139018bda00e87e8f4d9b5e2f6269c14"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Tiny Bot used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "NetScp" wide
        $s2 = "TinyZBot.Properties.Resources.resources"
        $s3 = "Aoao WaterMark"
        $s4 = "Run_a_exe"
        $s5 = "netscp.exe"
        $s6 = "get_MainModule_WebReference_DefaultWS"
        $s7 = "remove_CheckFileMD5Completed"
        $s8 = "http://tempuri.org/"
        $s9 = "Zhoupin_Cleaver"
    condition:
        (($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or $s9)
}

rule OPCLEAVER_ZhoupinExploitCrew
{
    meta:
        id = "1Z8MmrDtKnC5Gab4J1AbVg"
        fingerprint = "v1_sha256_1541f1ebc026d3eaf9b62150085415d12523ee1395fb8cf7ade8608a1b0a11b6"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Keywords used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "zhoupin exploit crew" nocase
        $s2 = "zhopin exploit crew" nocase
    condition:
        1 of them
}

rule OPCLEAVER_antivirusdetector
{
    meta:
        id = "1swOZfCDTi7IeQhjghhmdM"
        fingerprint = "v1_sha256_9a8c2bbd27efab4c5579ea143abbd2f71c477dfd0ddbfb1741359e4d34140d9b"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Hack tool used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "getShadyProcess"
        $s2 = "getSystemAntiviruses"
        $s3 = "AntiVirusDetector"
    condition:
        all of them
}

rule OPCLEAVER_csext
{
    meta:
        id = "N1PKKSAHzC1U42lgtYTxV"
        fingerprint = "v1_sha256_b4d070b71b685608ab84e757d01293749f2c017a6cd5b6ade6591264adc9836b"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Backdoor used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "COM+ System Extentions"
        $s2 = "csext.exe"
        $s3 = "COM_Extentions_bin"
    condition:
        all of them
}

rule OPCLEAVER_kagent
{
    meta:
        id = "73qdGYcu6h9TWqltmrjW4X"
        fingerprint = "v1_sha256_bd72ade7d40db830dc980def5107261f9cb41b713f9a0a1b2f41f7658b31653e"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Backdoor used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "kill command is in last machine, going back"
        $s2 = "message data length in B64: %d Bytes"
    condition:
        all of them
}

rule OPCLEAVER_mimikatzWrapper
{
    meta:
        id = "1Tj3WLXtiPHuFx6bf7APjc"
        fingerprint = "v1_sha256_c643e248a9d8dd653ec99f8b59cdc7af945857a6a0321f93cc6983e85f84baba"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Mimikatz Wrapper used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "mimikatzWrapper"
        $s2 = "get_mimikatz"
    condition:
        all of them
}

rule OPCLEAVER_pvz_in
{
    meta:
        id = "4LHMvCeujYzvN7zNdz1M3P"
        fingerprint = "v1_sha256_eae778162be5dcfa0005bb237c5209e7103db3549e06706744f9ebdf04e192df"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Parviz tool used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "LAST_TIME=00/00/0000:00:00PM$"
        $s2 = "if %%ERRORLEVEL%% == 1 GOTO line"
    condition:
        all of them
}

rule OPCLEAVER_pvz_out
{
    meta:
        id = "4Usuig9KTnZyfZWcstXZRr"
        fingerprint = "v1_sha256_849300c32d2df42a011386903495d271810fd8a40c76d1a0c6295c059deb3a05"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Parviz tool used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "Network Connectivity Module" wide
        $s2 = "OSPPSVC" wide
    condition:
        all of them
}

rule OPCLEAVER_wndTest
{
    meta:
        id = "2MYnlFN64g3ZookLsuxlOV"
        fingerprint = "v1_sha256_3b29c2b92b816bd0559695cb6b0b6e050ca8c5e256ec92448535fe9edf20757f"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Backdoor used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "[Alt]" wide
        $s2 = "<< %s >>:" wide
        $s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"
    condition:
        all of them
}

rule OPCLEAVER_zhCat
{
    meta:
        id = "6h3l1m1CTyg9EU4In1i86n"
        fingerprint = "v1_sha256_ef5112532ba62cb2cf6a1c62b344d9146c5b8e2da50990c8cfd60d91b99bcb5e"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Network tool used by Iranian hackers and used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "Mozilla/4.0 ( compatible; MSIE 7.0; AOL 8.0 )" ascii fullword
        $s2 = "ABC ( A Big Company )" wide fullword
    condition:
        all of them
}

rule OPCLEAVER_zhLookUp
{
    meta:
        id = "6ugPuLsKYFPyn77Ul3UzBI"
        fingerprint = "v1_sha256_9cc476e016708fd1604a63e2391057dc9dd0865448b62742ec596d6de54bf8f6"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Hack tool used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "zhLookUp.Properties"
    condition:
        all of them
}

rule OPCLEAVER_zhmimikatz
{
    meta:
        id = "izNmTUgO2heFMD0N1S6kJ"
        fingerprint = "v1_sha256_1d6ce5b3351d4b01abe0c2f614d002d4e96599b4bfa01138704a3fdf345d0786"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cylance Inc."
        description = "Mimikatz wrapper used by attackers in Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "MimikatzRunner"
        $s2 = "zhmimikatz"
    condition:
        all of them
}

rule OPCLEAVER_Parviz_Developer
{
    meta:
        id = "65gOdXygT675zypl6kKPGU"
        fingerprint = "v1_sha256_6ae043ee5baa7361def79811350317baf54eb76cf15001a7785808dc7947fddc"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Parviz developer known from Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "Users\\parviz\\documents\\" nocase
    condition:
        $s1
}

rule OPCLEAVER_CCProxy_Config
{
    meta:
        id = "3TbHiSj1wxxdBEAU4ORWi6"
        fingerprint = "v1_sha256_6e5c1c75a499434ad6ddd2439d28ac91d500b18418e693761d0b236bf6d6ce42"
        version = "1.0"
        score = 70
        date = "2014/12/02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "CCProxy config known from Operation Cleaver"
        category = "INFO"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

    strings:
        $s1 = "UserName=User-001" fullword ascii
        $s2 = "Web=1" fullword ascii
        $s3 = "Mail=1" fullword ascii
        $s4 = "FTP=0" fullword ascii
        $x1 = "IPAddressLow=78.109.194.114" fullword ascii
    condition:
        all of ($s*) or $x1
}
