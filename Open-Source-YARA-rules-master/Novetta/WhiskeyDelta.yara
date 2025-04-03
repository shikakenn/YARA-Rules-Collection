import "pe"

rule WhiskeyDelta
{
    meta:
        id = "2BSnJZU9jHQWsPDQ2Vae3T"
        fingerprint = "v1_sha256_b2f1712e1245f51f9379f0b8a712c96a2eb12f94e0c18814b588b2babed60817"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group  trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "41badf10ef6f469dd1c3be201aba809f9c42f86ad77d7f83bc3895bfa289c635"

    strings:
    /*
        F3 A5           rep movsd
        8B 7C 24 30     mov     edi, [esp+28h+arg_4]
        85 FF           test    edi, edi
        7E 3A           jle     short loc_402018
        8B 74 24 2C     mov     esi, [esp+28h+arg_0]
        8A 44 24 08     mov     al, [esp+28h+var_20]
        53              push    ebx
        8A 4C 24 21     mov     cl, [esp+2Ch+var_B]
        8A 5C 24 2B     mov     bl, [esp+2Ch+var_1]
        32 C1           xor     al, cl
        8A 0C 32        mov     cl, [edx+esi]
        32 C3           xor     al, bl
        32 C8           xor     cl, al
        88 0C 32        mov     [edx+esi], cl
        B9 1E 00 00 00  mov     ecx, 1Eh
        8A 5C 0C 0C     mov     bl, [esp+ecx+2Ch+var_20]
        88 5C 0C 0D     mov     [esp+ecx+2Ch+var_1F], bl
        49              dec     ecx
        83 F9 FF        cmp     ecx, 0FFFFFFFFh
        7F F2           jg      short loc_402000
        42              inc     edx
    */

    $decryption = {
            F3 A5 
            8B 7C 24 30 
            85 FF 
            7E ?? 
            8B 74 24 2C 
            8A 44 24 08 
            53 
            8A 4C 24 21 
            8A 5C 24 2B 
            32 C1 
            8A 0C 32 
            32 C3 
            32 C8 
            88 0C 32 
            B9 1E 00 00 00 
            8A 5C 0C 0C 
            88 5C 0C 0D 
            49 
            83 F9 FF 
            7F ?? 
            42 
        }

    $s1 = "=====IsFile=====" wide
    $s2 = "=====4M=====" wide
    $s3 = "=====IsBackup=====" wide
    
    condition:
        2 of ($s*) 
        or $decryption in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
