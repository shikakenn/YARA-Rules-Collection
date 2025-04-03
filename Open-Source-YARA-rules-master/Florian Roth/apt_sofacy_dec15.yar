/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-12-04
    Identifier: Sofacy Malware
*/

rule Sofacy_Malware_StrangeSpaces {
    meta:
        id = "3w8d0NqYDdVkzBw5gCkw7h"
        fingerprint = "v1_sha256_ee8bbebaa0978d038424cee3775ba312476afa014ce0d57c73d6844f758116ca"
        version = "1.0"
        date = "2015-12-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detetcs strange strings from Sofacy malware with many spaces"
        category = "INFO"
        reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"

    strings:
        $s2 = "Delete Temp Folder Service                                  " fullword wide
        $s3 = " Operating System                        " fullword wide
        $s4 = "Microsoft Corporation                                       " fullword wide
        $s5 = " Microsoft Corporation. All rights reserved.               " fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 50KB and 3 of them
}

rule Sofacy_Malware_AZZY_Backdoor_1 {
    meta:
        id = "5m2blSrn7iJ2A9uuAxPPCu"
        fingerprint = "v1_sha256_9c99f218d856d374423cada147bc38c8319f9ebff1e43e012143fad7af992d29"
        version = "1.0"
        date = "2015-12-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "AZZY Backdoor - Sample 1"
        category = "INFO"
        reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
        hash = "a9dc96d45702538c2086a749ba2fb467ba8d8b603e513bdef62a024dfeb124cb"

    strings:
        $s0 = "advstorshell.dll" fullword wide
        $s1 = "advshellstore.dll" fullword ascii
        $s2 = "Windows Advanced Storage Shell Extension DLL" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}

rule Sofacy_AZZY_Backdoor_Implant_1 {
    meta:
        id = "5u0cHNFjsRcYbj03K22BSN"
        fingerprint = "v1_sha256_6f5d6c49033bf641c018f1e7dd21307d4b13437f7711a8defa741ed22cf3f1fe"
        version = "1.0"
        date = "2015-12-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "AZZY Backdoor Implant 4.3 - Sample 1"
        category = "INFO"
        reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
        hash = "1bab1a3e0e501d3c14652ecf60870e483ed4e90e500987c35489f17a44fef26c"

    strings:
        $s1 = "\\tf394kv.dll" fullword wide
        $s2 = "DWN_DLL_MAIN.dll" fullword ascii
        $s3 = "?SendDataToServer_2@@YGHPAEKEPAPAEPAK@Z" ascii
        $s4 = "?Applicate@@YGHXZ" ascii
        $s5 = "?k@@YGPAUHINSTANCE__@@PBD@Z" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and 2 of them
}

rule Sofacy_AZZY_Backdoor_HelperDLL {
    meta:
        id = "1QRJejQKYcaMVoug2HPB7S"
        fingerprint = "v1_sha256_2d20560eec73c6210c90b7e55ef8d77b9766b80b72356bca491fa9d8454c87f0"
        version = "1.0"
        date = "2015-12-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Dropped C&C helper DLL for AZZY 4.3"
        category = "INFO"
        reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
        hash = "6cd30c85dd8a64ca529c6eab98a757fb326de639a39b597414d5340285ba91c6"

    strings:
        $s0 = "snd.dll" fullword ascii
        $s1 = "InternetExchange" fullword ascii
        $s2 = "SendData"
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

/* Super Rules ------------------------------------------------------------- */

rule Sofacy_CollectorStealer_Gen1 {
    meta:
        id = "4pM4XrbSdJc8SPbKfPCpyt"
        fingerprint = "v1_sha256_1b6693fa45fed5ed001d8fb4b43427c7036d95cb36b125e7242864d000085018"
        version = "1.0"
        date = "2015-12-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Generic rule to detect Sofacy Malware Collector Stealer"
        category = "INFO"
        reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
        super_rule = 1
        hash1 = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
        hash2 = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"

    strings:
        $s0 = "NvCpld.dll" fullword ascii
        $s1 = "NvStop" fullword ascii
        $s2 = "NvStart" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Sofacy_CollectorStealer_Gen2 {
    meta:
        id = "7OUIH7bkLJeHT7cfwLgN82"
        fingerprint = "v1_sha256_2086b4119bae17ec984665ea1e49d5f496a2cf6bf05ab507fe0cfb6e28039349"
        version = "1.0"
        date = "2015-12-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "File collectors / USB stealers - Generic"
        category = "INFO"
        reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
        hash = "e917166adf6e1135444f327d8fff6ec6c6a8606d65dda4e24c2f416d23b69d45"
        hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
        hash = "b1f2d461856bb6f2760785ee1af1a33c71f84986edf7322d3e9bd974ca95f92d"

    strings:
        $s1 = "msdetltemp.dll" fullword ascii
        $s2 = "msdeltemp.dll" fullword wide
        $s3 = "Delete Temp Folder Service" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule Sofacy_CollectorStealer_Gen3 {
    meta:
        id = "3OhrfSeutIV58lySTQPWfA"
        fingerprint = "v1_sha256_8e7f56013629d8b4d0c7600552590e8073deb16d5b6dced11444c2110b88f387"
        version = "1.0"
        date = "2015-12-04"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "File collectors / USB stealers - Generic"
        category = "INFO"
        reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
        hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
        hash = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"

    strings:
        $s1 = "NvCpld.dll" fullword ascii
        $s4 = "NvStart" fullword ascii
        $s5 = "NvStop" fullword ascii

        $a1 = "%.4d%.2d%.2d%.2d%.2d%.2d%.2d%.4d" fullword wide
        $a2 = "IGFSRVC.dll" fullword wide
        $a3 = "Common User Interface" fullword wide
        $a4 = "igfsrvc Module" fullword wide

        $b1 = " Operating System                        " fullword wide
        $b2 = "Microsoft Corporation                                       " fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and
        ( all of ($s*) and (all of ($a*) or all of ($b*)))
}
