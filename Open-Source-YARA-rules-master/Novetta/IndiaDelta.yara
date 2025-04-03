import "pe"

rule IndiaDelta
{
    meta:
        id = "4KoZEvmg5bjhEI1r9kOrMB"
        fingerprint = "v1_sha256_31cb71c7e3708e0df58e062d2983613630ad17b2591d6c1c5bb9f007ae811349"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "d7b50b1546653bff68220996190446bdc7fc4e38373715b8848d1fb44fe3f53c"

    strings:
    /*
        FF 15 DC 2D 41 00  call    ReadFile_0
        8B 44 24 20        mov     eax, [esp+25Ch+offsetInFile]
        8B 54 24 1C        mov     edx, [esp+25Ch+dwEmbedCnt]
        35 78 56 34 12     xor     eax, 12345678h
        55                 push    ebp
        55                 push    ebp
        81 F2 78 56 34 12  xor     edx, 12345678h
        50                 push    eax
        57                 push    edi
        89 54 24 2C        mov     [esp+26Ch+dwEmbedCnt], edx
        89 44 24 30        mov     [esp+26Ch+offsetInFile], eax
        FF 15 E0 2D 41 00  call    SetFilePointer_0
    */

    $a = {
            FF 15 [4-12] 
            3? 78 56 34 12 
            [0-2] 
            8? ?? 78 56 34 12 
            [0-10]
            FF 15
        }

    condition:
        $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
