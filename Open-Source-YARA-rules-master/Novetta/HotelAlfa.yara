import "pe"

rule HotelAlfa
{
    meta:
        id = "34IpP6QPc4HQfXT1JGfZ58"
        fingerprint = "v1_sha256_d20c54c93c50bc6961c0b5f2dbc1bea2cf97116a93c05dddc9e665aa289441ce"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "58dab205ecb1e0972027eb92f68cec6d208e5ab5.ex_"

    strings:
    
    $resourceHTML = "RSRC_HTML"
    /*
        8A 0C 18  mov     cl, [eax+ebx]
        80 F1 63  xor     cl, 63h
        88 0C 18  mov     [eax+ebx], cl
        8B 4D 00  mov     ecx, [ebp+0]
        40        inc     eax
        3B C1     cmp     eax, ecx
        72 EF     jb      short loc_4010B4
    */

    $rscsDecoderLoop = {
            8A [2] 
            80 F1 ?? 
            88 [2] 
            8B [2] 
            40 
            3B ??
            72 EF 
        }

    condition:
        $resourceHTML and $rscsDecoderLoop in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
