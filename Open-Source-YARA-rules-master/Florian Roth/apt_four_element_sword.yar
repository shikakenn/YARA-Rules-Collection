/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-04-18
    Identifier: FourElementSword
    Reference: https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/
*/

/* Rule Set ----------------------------------------------------------------- */

rule FourElementSword_Config_File {
    meta:
        id = "5TSDbvLTVohRuEFEefv7AX"
        fingerprint = "v1_sha256_680e50998093e63a4e3c7d5338ac149efef83cdb41ceb4ce0245e8bd2ab99b84"
        version = "1.0"
        date = "2016-04-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects FourElementSword Malware - file f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"
        category = "INFO"
        reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
        hash = "f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"

    strings:
        $s0 = "01,,hccutils.dll,2" fullword ascii
        $s1 = "RegisterDlls=OurDll" fullword ascii
        $s2 = "[OurDll]" fullword ascii
        $s3 = "[DefaultInstall]" fullword ascii /* Goodware String - occured 16 times */
        $s4 = "Signature=\"$Windows NT$\"" fullword ascii /* Goodware String - occured 26 times */
    condition:
        4 of them
}

rule FourElementSword_T9000 {
    meta:
        id = "1iXFfB1ol1ElEpYQa78AFN"
        fingerprint = "v1_sha256_1c7b063cbe9d44a9d194a180570f8313460f61560ac2cda5d66e048934170faa"
        version = "1.0"
        date = "2016-04-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects FourElementSword Malware - file 5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
        category = "INFO"
        reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
        hash = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"

    strings:
        $x1 = "D:\\WORK\\T9000\\" ascii
        $x2 = "%s\\temp\\HHHH.dat" fullword wide

        $s1 = "Elevate.dll" fullword wide
        $s2 = "ResN32.dll" fullword wide
        $s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword wide
        $s4 = "igfxtray.exe" fullword wide
    condition:
        ( uint16(0) == 0x5a4d and filesize < 500KB and 1 of ($x*) ) or ( all of them )
}

rule FourElementSword_32DLL {
    meta:
        id = "2H0R2cGp2diwcF62UjgJ40"
        fingerprint = "v1_sha256_1351719b2d67d592b9400c6878fb41f59ac3800e6c1e92bb807d22008f0921af"
        version = "1.0"
        date = "2016-04-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects FourElementSword Malware - file 7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"
        category = "INFO"
        reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
        hash = "7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"

    strings:
        $x1 = "%temp%\\tmp092.tmp" fullword ascii

        $s1 = "\\System32\\ctfmon.exe" fullword ascii
        $s2 = "%SystemRoot%\\System32\\" fullword ascii
        $s3 = "32.dll" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 660KB and $x1 ) or ( all of them )
}

rule FourElementSword_Keyainst_EXE {
    meta:
        id = "6SPGstemRjHbphRtObQsxg"
        fingerprint = "v1_sha256_1491de3241a81cce4d80d6dc23886f1d8bf316112c48652a8138aa4cbadbb174"
        version = "1.0"
        date = "2016-04-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects FourElementSword Malware - file cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
        category = "INFO"
        reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
        hash = "cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"

    strings:
        $x1 = "C:\\ProgramData\\Keyainst.exe" fullword ascii

        $s1 = "ShellExecuteA" fullword ascii /* Goodware String - occured 266 times */
        $s2 = "GetStartupInfoA" fullword ascii /* Goodware String - occured 2573 times */
        $s3 = "SHELL32.dll" fullword ascii /* Goodware String - occured 3233 times */
    condition:
        ( uint16(0) == 0x5a4d and filesize < 48KB and $x1 ) or ( all of them )
}

rule FourElementSword_ElevateDLL_2 {
    meta:
        id = "4XbITRHg1PofB9fhQCAhxs"
        fingerprint = "v1_sha256_d5fcb2bacfa0a1f78bfbd3fa7ba3084da9a60f1b8b7880c83d8f225312c179b4"
        version = "1.0"
        date = "2016-04-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects FourElementSword Malware - file 9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"
        category = "INFO"
        reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
        hash = "9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"

    strings:
        $s1 = "Elevate.dll" fullword ascii
        $s2 = "GetSomeF" fullword ascii
        $s3 = "GetNativeSystemInfo" fullword ascii /* Goodware String - occured 530 times */
    condition:
        ( uint16(0) == 0x5a4d and filesize < 25KB and $s1 ) or ( all of them )
}

rule FourElementSword_fslapi_dll_gui {
    meta:
        id = "118QcUh9H6by8CQpWIPgcZ"
        fingerprint = "v1_sha256_909b187f864a240268d0ffcef904b85cd1eaad97dd3a3a808aad58968fbb76c2"
        version = "1.0"
        date = "2016-04-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects FourElementSword Malware - file 2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
        category = "INFO"
        reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
        hash = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"

    strings:
        $s1 = "fslapi.dll.gui" fullword wide
        $s2 = "ImmGetDefaultIMEWnd" fullword ascii /* Goodware String - occured 64 times */
        $s3 = "RichOX" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 12KB and all of them )
}

rule FourElementSword_PowerShell_Start {
    meta:
        id = "1CCZLRbWCNKjvfTYYrBBGc"
        fingerprint = "v1_sha256_7b1986845d97dcd11c8baddb0b49350ad30c6fff98840275befef4ad0b906b54"
        version = "1.0"
        date = "2016-04-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects FourElementSword Malware - file 9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
        category = "INFO"
        reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
        hash = "9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"

    strings:
        $s0 = "start /min powershell C:\\\\ProgramData\\\\wget.exe" ascii
        $s1 = "start /min powershell C:\\\\ProgramData\\\\iuso.exe" fullword ascii
    condition:
        1 of them
}

rule FourElementSword_ResN32DLL {
    meta:
        id = "18zFw6dAKRttXNEV2TPXkb"
        fingerprint = "v1_sha256_87c4fe668fa23f2e9a41a2d40349832318a6a58f0ffc66dcea7de4d6643d47e4"
        version = "1.0"
        date = "2016-04-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects FourElementSword Malware - file bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
        category = "INFO"
        reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
        hash = "bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"

    strings:
        $s1 = "\\Release\\BypassUAC.pdb" ascii
        $s2 = "\\ResN32.dll" fullword wide
        $s3 = "Eupdate" fullword wide
    condition:
        all of them
}

/* Super Rules ------------------------------------------------------------- */

rule FourElementSword_ElevateDLL {
    meta:
        id = "iXLqyPzA8qVHFG7zNUkVN"
        fingerprint = "v1_sha256_d110bae02f00d14c5a71ecf5991e9fc38b29d8056d1e551dc36376875d2e1333"
        version = "1.0"
        date = "2016-04-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects FourElementSword Malware - from files 3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9, 5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
        category = "INFO"
        reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
        super_rule = 1
        hash1 = "3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9"
        hash2 = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"

    strings:
        $x1 = "Elevate.dll" fullword wide
        $x2 = "ResN32.dll" fullword wide

        $s1 = "Kingsoft\\Antivirus" fullword wide
        $s2 = "KasperskyLab\\protected" fullword wide
        $s3 = "Sophos" fullword wide
    condition:
        ( uint16(0) == 0x5a4d and filesize < 500KB and 1 of ($x*) and all of ($s*) )
        or ( all of them )
}
