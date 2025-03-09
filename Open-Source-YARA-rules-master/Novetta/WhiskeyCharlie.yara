import "pe"

rule WhiskeyCharlie
{
    meta:
        id = "4yCY7qiNbev58NguX3MODi"
        fingerprint = "v1_sha256_e26007beae35e44fd88be9fe511c818e21a63c5b0885bf333ccdf55d4388ab11"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "47ff4f73738acc2f8433dccb2caf980d7444d723ccf2968d69f88f8f96405f96"

    strings:
    /*
        66 89 55 DC     mov     [ebp+SystemTime.wYear], dx
        E8 1E 16 00 00  call    _rand
        6A 0C           push    0Ch
        99              cdq
        59              pop     ecx
        F7 F9           idiv    ecx
        42              inc     edx
        66 89 55 DE     mov     [ebp+SystemTime.wMonth], dx
        E8 0E 16 00 00  call    _rand
        6A 1C           push    1Ch
        99              cdq
        59              pop     ecx
        F7 F9           idiv    ecx
        42              inc     edx
        66 89 55 E2     mov     [ebp+SystemTime.wDay], dx
        E8 FE 15 00 00  call    _rand
        6A 18           push    18h
        99              cdq
        59              pop     ecx
        F7 F9           idiv    ecx
        66 89 55 E4     mov     [ebp+SystemTime.wHour], dx
        E8 EF 15 00 00  call    _rand
        6A 3C           push    3Ch
        99              cdq
        59              pop     ecx
        F7 F9           idiv    ecx
        66 89 55 E6     mov     [ebp+SystemTime.wMinute], dx
        E8 E0 15 00 00  call    _rand
        6A 3C           push    3Ch
        99              cdq
        59              pop     ecx
        F7 F9           idiv    ecx
    */

    $a = {
            66 89 55 DC 
            E8 [4] 
            6A 0C 
            99 
            59 
            F7 F9 
            42 
            66 89 55 DE 
            E8 [4] 
            6A 1C 
            99 
            59 
            F7 F9 
            42 
            66 89 55 E2 
            E8 [4] 
            6A 18 
            99 
            59 
            F7 F9 
            66 89 55 E4 
            E8 [4] 
            6A 3C 
            99 
            59 
            F7 F9 
            66 89 55 E6 
            E8 [4] 
            6A 3C 
            99 
            59 
            F7 F9 
        }

    condition:
        $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
