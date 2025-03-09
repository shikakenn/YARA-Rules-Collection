private rule LuckyCatCode : LuckyCat Family 
{
    meta:
        id = "7RSmVCDTxJFEQjGWW3kwu0"
        fingerprint = "v1_sha256_48315b2c3bfa0c2842ba63918fa2ed65eefca68a1aa82dfefc05604995f5d585"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "LuckyCat code tricks"
        category = "INFO"

    strings:
        $xordecrypt = { BF 0F 00 00 00 F7 F7 ?? ?? ?? ?? 32 14 39 80 F2 7B }
        $dll = { C6 ?? ?? ?? 64 C6 ?? ?? ?? 6C C6 ?? ?? ?? 6C }
        $commonletters = { B? 63 B? 61 B? 73 B? 65 }
        
    condition:
        $xordecrypt or ($dll and $commonletters)
}

private rule LuckyCatStrings : LuckyCat Family
{
    meta:
        id = "3N2V7x8OSiT3jmCTMN6Sw2"
        fingerprint = "v1_sha256_b2ba43d3f13a0f7716cb4fd093732c236daf35b5fb4615ff102b5da5d9cb6e0f"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "LuckyCat Identifying Strings"
        category = "INFO"

    strings:
        $xorencrypted = { 77 76 75 7B 7A 79 78 7F 7E 7D 7C 73 72 71 70 }
        $tempvbs = "%s\\~temp.vbs"
        $countphp = "count.php\x00"
        $trojanname = /WMILINK=.*TrojanName=/
        $tmpfile = "d0908076343423d3456.tmp"
        $dirfile = "cmd /c dir /s /a C:\\\\ >'+tmpfolder+'\\\\C.tmp"
        $ipandmac = "objIP.DNSHostName+'_'+objIP.MACAddress.split(':').join('')+'_'+addinf+'@')"
        
    condition:
       any of them
}

rule LuckyCat : Family
{
    meta:
        id = "1qzuCY60cwZpggdrnRL6v6"
        fingerprint = "v1_sha256_ac99899c7e2efac5083bbe2be2615e9bdca8472e602a1fc8114c6fc80570b3fa"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "LuckyCat"
        category = "INFO"

    condition:
        LuckyCatCode or LuckyCatStrings
}
