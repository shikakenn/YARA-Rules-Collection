/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-10-10
    Identifier: Winnti Malware
*/

rule Winnti_signing_cert {
    meta:
        id = "5CfhJwer7mTAUmzHyPCFzK"
        fingerprint = "v1_sha256_6fd5f2808e7d683b9c4b7f5d4ccfd0eb87037eb2e70700b2c083db8c6ddf4a26"
        version = "1.0"
        score = 75
        date = "2015-10-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a signing certificate used by the Winnti APT group"
        category = "INFO"
        reference = "https://securelist.com/analysis/publications/72275/i-am-hdroot-part-1/"
        hash1 = "a9a8dc4ae77b1282f0c8bdebd2643458fc1ceb3145db4e30120dd81676ff9b61"
        hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"

    strings:
        $s1 = "Guangzhou YuanLuo Technology Co." ascii
        $s2 = "Guangzhou YuanLuo Technology Co.,Ltd" ascii
        $s3 = "$Asahi Kasei Microdevices Corporation0" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 700KB and 1 of them
}

rule Winnti_malware_Nsiproxy {
    meta:
        id = "3nwbaPFyjoA4m0p7YVyLeT"
        fingerprint = "v1_sha256_5010e4c1c42f4a5865a36487aff72635541c8f3081454524d53b33da0fa0bf51"
        version = "1.0"
        score = 75
        date = "2015-10-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a Winnti rootkit"
        category = "INFO"
        hash1 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
        hash2 = "cf1e006694b33f27d7c748bab35d0b0031a22d193622d47409b6725b395bffb0"
        hash3 = "326e2cabddb641777d489a9e7a39d52c0dc2dcb1fde1762554ea162792056b6e"
        hash4 = "aff7c7478fe33c57954b6fec2095efe8f9edf5cdb48a680de9439ba62a77945f"
        hash5 = "ba7ccd027fd2c826bbe8f2145d5131eff906150bd98fe25a10fbee2c984df1b8"

    strings:
        $x1 = "\\Driver\\nsiproxy" fullword wide

        $a1 = "\\Device\\StreamPortal" fullword wide
        $a2 = "\\Device\\PNTFILTER" fullword wide

        $s1 = "Cookie: SN=" fullword ascii
        $s2 = "\\BaseNamedObjects\\_transmition_synchronization_" fullword wide
        $s3 = "Winqual.sys" fullword wide
        $s4 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
        $s5 = "http://www.wasabii.com.tw 0" fullword ascii
    condition:
        uint16(0) == 0x5a4d and $x1 and 1 of ($a*) and 2 of ($s*)
}

rule Winnti_malware_UpdateDLL {
    meta:
        id = "29JRiEmXmXYENwoaAX7tgf"
        fingerprint = "v1_sha256_50e7c96a0c5bb264183807797822528c7b44c92e63502a82d6e686ea51d127dc"
        version = "1.0"
        score = 75
        date = "2015-10-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a Winnti malware - Update.dll"
        category = "INFO"
        reference = "VTI research"
        hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
        hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
        hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
        hash4 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"

    strings:
        $c1 = "'Wymajtec$Tima Stempijg Sarviges GA -$G2" fullword ascii
        $c2 = "AHDNEAFE1.sys" fullword ascii
        $c3 = "SOTEFEHJ3.sys" fullword ascii
        $c4 = "MainSYS64.sys" fullword ascii

        $s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide
        $s2 = "Update.dll" fullword ascii
        $s3 = "\\\\.\\pipe\\usbpcex%d" fullword wide
        $s4 = "\\\\.\\pipe\\usbpcg%d" fullword wide
        $s5 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" fullword wide
        $s6 = "\\??\\pipe\\usbpcg%d" fullword wide
        $s7 = "\\??\\pipe\\usbpcex%d" fullword wide
        $s8 = "HOST: %s" fullword ascii
        $s9 = "$$$--Hello" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and
        (
            ( 1 of ($c*) and 3 of ($s*) ) or all of ($s*)
        )
}
rule Winnti_malware_FWPK {
    meta:
        id = "2h0J4yBfJDgZUmqBg1Ifv7"
        fingerprint = "v1_sha256_a800189bc25326e4369911a2399a6b9e5ba16e028a591527f3073411b2ae5f79"
        version = "1.0"
        score = 75
        date = "2015-10-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a Winnti malware - FWPKCLNT.SYS"
        category = "INFO"
        reference = "VTI research"
        hash1 = "1098518786c84b0d31f215122275582bdcd1666653ebc25d50a142b4f5dabf2c"
        hash2 = "9a684ffad0e1c6a22db1bef2399f839d8eff53d7024fb014b9a5f714d11febd7"
        hash3 = "a836397817071c35e24e94b2be3c2fa4ffa2eb1675d3db3b4456122ff4a71368"

    strings:
        $s0 = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" fullword wide
        $s1 = "%x:%d->%x:%d, Flag %s%s%s%s%s, seq %u, ackseq %u, datalen %u" fullword ascii
        $s2 = "FWPKCLNT.SYS" fullword ascii
        $s3 = "Port Layer" fullword wide
        $s4 = "%x->%x, icmp type %d, code %d" fullword ascii
        $s5 = "\\BaseNamedObjects\\{93144EB0-8E3E-4591-B307-8EEBFE7DB28E}" fullword wide
        $s6 = "\\Ndi\\Interfaces" fullword wide
        $s7 = "\\Device\\{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" fullword wide
        $s8 = "Bad packet" fullword ascii
        $s9 = "\\BaseNamedObjects\\EKV0000000000" fullword wide
        $s10 = "%x->%x" fullword ascii
        $s11 = "IPInjectPkt" fullword ascii /* Goodware String - occured 6 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 642KB and all of them
}

rule Winnti_malware_StreamPortal_Gen {
    meta:
        id = "47fWl9rZ5pAHq4fkQXkgYJ"
        fingerprint = "v1_sha256_50fea6f3bc6319c50c22a9aeac67e386559272564480395cfa32f11c32c0582d"
        version = "1.0"
        score = 75
        date = "2015-10-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a Winnti malware - Streamportal"
        category = "INFO"
        reference = "VTI research"
        hash1 = "326e2cabddb641777d489a9e7a39d52c0dc2dcb1fde1762554ea162792056b6e"
        hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
        hash3 = "aff7c7478fe33c57954b6fec2095efe8f9edf5cdb48a680de9439ba62a77945f"

    strings:
        $s0 = "Proxies destination address/port for TCP" fullword wide
        $s3 = "\\Device\\StreamPortal" fullword wide
        $s4 = "Transport-Data Proxy Sub-Layer" fullword wide
        $s5 = "Cookie: SN=" fullword ascii
        $s6 = "\\BaseNamedObjects\\_transmition_synchronization_" fullword wide
        $s17 = "NTOSKRNL.EXE" fullword wide /* Goodware String - occured 4 times */
        $s19 = "FwpsReferenceNetBufferList0" fullword ascii /* Goodware String - occured 5 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 275KB and all of them
}
