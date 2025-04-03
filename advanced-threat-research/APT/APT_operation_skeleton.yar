rule chimera_recordedtv_modified {
    
    meta:
        id = "1lAL2i8GYvhLCPH125SjDL"
        fingerprint = "v1_sha256_7165779b66999259a079fa68f898c5f9fb634adcb9d249366d321dff1014184b"
        version = "1.0"
        date = "2020-04-21"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the modified version of RecordedTV.ms found in the Operation Skeleton"
        category = "MALWARE"
        malware_type = "TROJAN"
        actor_type = "APT"
        reference = "https://cycraft.com/download/%5BTLP-White%5D20200415%20Chimera_V4.1.pdf"
        reference = "https://medium.com/@cycraft_corp/taiwan-high-tech-ecosystem-targeted-by-foreign-apt-group-5473d2ad8730"
        hash = "66f13964c87fc6fe093a9d8cc0de0bf2b3bdaea9564210283fdb97a1dde9893b"
        rule_version = "v1"
        malware_family = "Trojan:W32/RecordedTV"
        actor_group = "Unknown"

    strings:
        
        // Modified byte
        $byte = { C0 0E 5B C3 }
        $s1 = "Encrypted file:  CRC failed in %s (password incorrect ?)" fullword wide
            $s2 = "EBorland C++ - Copyright 1999 Inprise Corporation" fullword ascii
           $s3 = " MacOS file type:  %c%c%c%c  ; " fullword wide
        $s4 = "rar.lng" fullword ascii

    condition:
        
        uint16(0) == 0x5a4d and
        filesize < 900KB and
        all of them
    
}
