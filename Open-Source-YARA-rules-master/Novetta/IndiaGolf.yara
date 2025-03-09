import "pe"

rule IndiaGolf
{
    meta:
        id = "5DubkVEL4AjgiYmKV665nc"
        fingerprint = "v1_sha256_3838858db29c23631ebeb3f1331228fae66158c7007b6f5aaf22873c7020edec"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "3dda69dfb254dcaea2ba6e8323d4b61ab1e130a0694f4c43d336cfb86a760c50"

    strings:
    /*
        FF D6        call    esi ; rand
        8B F8        mov     edi, eax
        C1 E7 10     shl     edi, 10h
        FF D6        call    esi ; rand
        03 F8        add     edi, eax
        89 7C 24 20  mov     [esp+2A90h+var_2A70], edi
        FF D6        call    esi ; rand
        8B F8        mov     edi, eax
        C1 E7 10     shl     edi, 10h
        FF D6        call    esi ; rand
        03 F8        add     edi, eax
        89 7C 24 24  mov     [esp+2A90h+var_2A6C], edi
    */

    $generateRandomID = {
            FF ?? 
            8B ?? 
            C1 ?? 10 
            FF ?? 
            03 F8 
            89 [3]
            FF ?? 
            8B ?? 
            C1 ?? 10 
            FF ?? 
            03 ?? 
            89 
        }

    condition:
        $generateRandomID in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
