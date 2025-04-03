/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-03-26
    Identifier: Windows Shells
*/

/* Rule Set ----------------------------------------------------------------- */

rule WindowsShell_s3 {
    meta:
        id = "6vFcMo6oyIP6AOTSAddflZ"
        fingerprint = "v1_sha256_b9274f909b50247a4f5111a14806faadba7814e26805bef7d61eaaf8be4b46ed"
        version = "1.0"
        date = "2016-03-26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects simple Windows shell - file s3.exe"
        category = "INFO"
        reference = "https://github.com/odzhan/shells/"
        hash = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"

    strings:
        $s1 = "cmd                  - execute cmd.exe" fullword ascii
        $s2 = "\\\\.\\pipe\\%08X" fullword ascii
        $s3 = "get <remote> <local> - download file" fullword ascii
        $s4 = "[ simple remote shell for windows v3" fullword ascii
        $s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
        $s6 = "put <local> <remote> - upload file" fullword ascii
        $s7 = "term                 - terminate remote client" fullword ascii
        $s8 = "[ downloading \"%s\" to \"%s\"" fullword ascii
        $s9 = "-l           Listen for incoming connections" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}

rule WindosShell_s1 {
    meta:
        id = "6eJ8oTh1GQarYifF964n1m"
        fingerprint = "v1_sha256_29fcddc549c615ca5cdda60272926671bc1446c3c7b51c9a2fd867b6b68858b2"
        version = "1.0"
        date = "2016-03-26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects simple Windows shell - file s1.exe"
        category = "INFO"
        reference = "https://github.com/odzhan/shells/"
        hash = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"

    strings:
        $s1 = "[ executing cmd.exe" fullword ascii
        $s2 = "[ simple remote shell for windows v1" fullword ascii
        $s3 = "-p <number>  Port number to use (default is 443)" fullword ascii
        $s4 = "usage: s1 <address> [options]" fullword ascii
        $s5 = "[ waiting for connections on %s" fullword ascii
        $s6 = "-l           Listen for incoming connections" fullword ascii
        $s7 = "[ connection from %s" fullword ascii
        $s8 = "[ %c%c requires parameter" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}

rule WindowsShell_s4 {
    meta:
        id = "1YgpxDxbjSBF1RgwDTGBZD"
        fingerprint = "v1_sha256_fff280debdd32a736e37a73800f226bf6def5dd107abd1d9237d92904622c9ec"
        version = "1.0"
        date = "2016-03-26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects simple Windows shell - file s4.exe"
        category = "INFO"
        reference = "https://github.com/odzhan/shells/"
        hash = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"

    strings:
        $s1 = "cmd                  - execute cmd.exe" fullword ascii
        $s2 = "\\\\.\\pipe\\%08X" fullword ascii
        $s3 = "get <remote> <local> - download file" fullword ascii
        $s4 = "[ simple remote shell for windows v4" fullword ascii
        $s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
        $s6 = "[ downloading \"%s\" to \"%s\"" fullword ascii
        $s7 = "[ uploading \"%s\" to \"%s\"" fullword ascii
        $s8 = "-l           Listen for incoming connections" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}

/* Super Rules ------------------------------------------------------------- */

rule WindowsShell_Gen {
    meta:
        id = "1b8babgMUnZyM3zaupJyng"
        fingerprint = "v1_sha256_753dd12f649bcbfcc2c60a2f3be27df5297a671a0ee1856093eed04113616581"
        version = "1.0"
        date = "2016-03-26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects simple Windows shell - from files keygen.exe, s1.exe, s2.exe, s3.exe, s4.exe"
        category = "INFO"
        reference = "https://github.com/odzhan/shells/"
        super_rule = 1
        hash1 = "a7c3d85eabac01e7a7ec914477ea9f17e3020b3b2f8584a46a98eb6a2a7611c5"
        hash2 = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
        hash3 = "df0693caae2e5914e63e9ee1a14c1e9506f13060faed67db5797c9e61f3907f0"
        hash4 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
        hash5 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"

    strings:
        $s0 = "[ %c%c requires parameter" fullword ascii
        $s1 = "[ %s : %i" fullword ascii
        $s2 = "[ %s : %s" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 175KB and 2 of them ) or ( all of them )
}

rule WindowsShell_Gen2 {
    meta:
        id = "4lloiIUIxJKeAOi3EhCw3T"
        fingerprint = "v1_sha256_c5ce27554b2ee25b974b567ef5a9ae877906250073da477f0ab5d71d162ac81a"
        version = "1.0"
        date = "2016-03-26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects simple Windows shell - from files s3.exe, s4.exe"
        category = "INFO"
        reference = "https://github.com/odzhan/shells/"
        super_rule = 1
        hash1 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
        hash2 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"

    strings:
        $s1 = "cmd                  - execute cmd.exe" fullword ascii
        $s2 = "get <remote> <local> - download file" fullword ascii
        $s3 = "REMOTE: CreateFile(\"%s\")" fullword ascii
        $s4 = "put <local> <remote> - upload file" fullword ascii
        $s5 = "term                 - terminate remote client" fullword ascii
        $s6 = "[ uploading \"%s\" to \"%s\"" fullword ascii
        $s7 = "[ error : received %i bytes" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}
