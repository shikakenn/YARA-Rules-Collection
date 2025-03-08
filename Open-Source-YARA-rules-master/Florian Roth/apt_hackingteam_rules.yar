/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-07-07
    Identifier: HackingTeam
*/

/* Rule Set ----------------------------------------------------------------- */

rule bin_ndisk {
    meta:
        id = "28j0gmYRz25r52Dny8xXDN"
        fingerprint = "v1_sha256_5f4decfe2d8033ec8f3e1445862b3341ff0ea432053fb91b8409398da04ac796"
        version = "1.0"
        score = 100
        date = "2015-07-07"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Hacking Team Disclosure Sample - file ndisk.sys"
        category = "INFO"
        reference = "https://www.virustotal.com/en/file/a03a6ed90b89945a992a8c69f716ec3c743fa1d958426f4c50378cca5bef0a01/analysis/1436184181/"
        hash = "cf5089752ba51ae827971272a5b761a4ab0acd84"

    strings:
        $s1 = "\\Registry\\Machine\\System\\ControlSet00%d\\services\\ndisk.sys" fullword wide 
        $s2 = "\\Registry\\Machine\\System\\ControlSet00%d\\Enum\\Root\\LEGACY_NDISK.SYS" fullword wide 
        $s3 = "\\Driver\\DeepFrz" fullword wide
        $s4 = "Microsoft Kernel Disk Manager" fullword wide 
        $s5 = "ndisk.sys" fullword wide
        $s6 = "\\Device\\MSH4DEV1" fullword wide
        $s7 = "\\DosDevices\\MSH4DEV1" fullword wide
        $s8 = "built by: WinDDK" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 30KB and 6 of them
}

rule Hackingteam_Elevator_DLL {
    meta:
        id = "zuSnt7tDJWih6M5Stfs5G"
        fingerprint = "v1_sha256_4b4a4c4332c70fca8ef7c10af8115e7073a9b0781b0306463969d83f924edf3a"
        version = "1.0"
        score = 70
        date = "2015-07-07"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Hacking Team Disclosure Sample - file elevator.dll"
        category = "INFO"
        reference = "http://t.co/EG0qtVcKLh"
        hash = "b7ec5d36ca702cc9690ac7279fd4fea28d8bd060"

    strings:
        $s1 = "\\sysnative\\CI.dll" fullword ascii 
        $s2 = "setx TOR_CONTROL_PASSWORD" fullword ascii 
        $s3 = "mitmproxy0" fullword ascii 
        $s4 = "\\insert_cert.exe" fullword ascii
        $s5 = "elevator.dll" fullword ascii
        $s6 = "CRTDLL.DLL" fullword ascii
        $s7 = "fail adding cert" fullword ascii
        $s8 = "DownloadingFile" fullword ascii 
        $s9 = "fail adding cert: %s" fullword ascii
        $s10 = "InternetOpenA fail" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and 6 of them
}

rule HackingTeam_Elevator_EXE {
    meta:
        id = "5izAA0U4aNcq2u20Catf6x"
        fingerprint = "v1_sha256_85c7375b82d5b47927c8c05971e89f39b0e9450eca750b6ea89abd0e30b91557"
        version = "1.0"
        score = 70
        date = "2015-07-07"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Hacking Team Disclosure Sample - file elevator.exe"
        category = "INFO"
        reference = "Hacking Team Disclosure elevator.c"
        hash = "9261693b67b6e379ad0e57598602712b8508998c0cb012ca23139212ae0009a1"
        hash1 = "40a10420b9d49f87527bc0396b19ec29e55e9109e80b52456891243791671c1c"
        hash2 = "92aec56a859679917dffa44bd4ffeb5a8b2ee2894c689abbbcbe07842ec56b8d"

    strings:
        $x1 = "CRTDLL.DLL" fullword ascii
        $x2 = "\\sysnative\\CI.dll" fullword ascii
        $x3 = "\\SystemRoot\\system32\\CI.dll" fullword ascii
        $x4 = "C:\\\\Windows\\\\Sysnative\\\\ntoskrnl.exe" fullword ascii /* PEStudio Blacklist: strings */

        $s1 = "[*] traversing processes" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "_getkprocess" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "[*] LoaderConfig %p" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "loader.obj" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3" ascii /* PEStudio Blacklist: strings */
        $s6 = "[*] token restore" fullword ascii /* PEStudio Blacklist: strings */
        $s7 = "elevator.obj" fullword ascii
        $s8 = "_getexport" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        uint16(0) == 0x5a4d and filesize < 3000KB and all of ($x*) and 3 of ($s*)
}


