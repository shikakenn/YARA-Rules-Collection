import "pe"

rule IndiaBravo_PapaAlfa
{
    meta:
        id = "167OgFfG8hH2o60nRBUT11"
        fingerprint = "v1_sha256_e4b54c946783ae063253f8f8baea321e9f83c6146b7f6b1a72678da0e7a948ee"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
        $ = "pmsconfig.msi" wide
        $ = "scvrit001.bat"
    condition:
        all of them
}

rule IndiaBravo_RomeoCharlie
{
    meta:
        id = "1ji7TNVbIh1M4qZP1C8RFE"
        fingerprint = "v1_sha256_af1b4ca38b2a9c171b0c0fec4ebc585da080140f26d2e85a6505272fe4271410"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "58ad28ac4fb911abb6a20382456c4ad6fe5c8ee5.ex_"
        Status = "Signature is too loose to be useful."

    strings:
    /*
        50                 push    eax             ; argp
        68 7E 66 04 80     push    8004667Eh       ; cmd
        8B 8D DC FE FF FF  mov     ecx, [ebp+skt]
        51                 push    ecx             ; s
        FF 15 58 31 41 00  call    ioctlsocket
        83 F8 FF           cmp     eax, 0FFFFFFFFh
        75 08              jnz     short loc_4043F0
    */

    $a = {
            50 
            68 7E 66 04 80 
            8B 8D [4]
            51 
            FF 15 [4] 
            83 F8 FF 
            75 
        }
    $b1 = "xc123465-efff-87cc-37abcdef9"
    $b2 = "[Check] - PORT ERROR..." wide
    $b3 = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d"

    condition:
        2 of ($b*) or 
        $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule IndiaBravo_RomeoBravo
{
    meta:
        id = "6dQjwSW9cJtr63to2LUorx"
        fingerprint = "v1_sha256_ace0f92c87b16cbbdaf05caecc780a3152ade3b4cd10aad81f3851e046e85795"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "6e3db4da27f12eaba005217eba7cd9133bc258c97fe44605d12e20a556775009"

    strings:
    /*
        E8 C3 FE FF FF     call    generate64ByteRandomNumber
        68 C8 01 00 00     push    1C8h            ; dwLength
        68 D8 E8 40 00     push    offset g_Config ; pvBuffer
        A3 80 EA 40 00     mov     dword ptr g_Config.qwIdentifier, eax
        89 15 84 EA 40 00  mov     dword ptr g_Config.qwIdentifier+4, edx
        E8 F9 E9 FF FF     call    DNSCALCDecode
        83 C4 08           add     esp, 8
        8D 4C 24 08        lea     ecx, [esp+214h+var_20C]
        6A 00              push    0
        51                 push    ecx
        68 C8 01 00 00     push    1C8h
        68 D8 E8 40 00     push    offset g_Config
        56                 push    esi
        FF 15 74 E7 40 00  call    WriteFile_9
        56                 push    esi
        FF 15 6C E7 40 00  call    CloseHandle_9
    */

    $a = {
            E8 [4] 
            68 [2] 00 00 
            68 [4]
            A3 [4]
            89 15 [4]
            E8 [4]
            83 C4 08 
            8D [3]
            6A 00 
            5? 
            68 [2] 00 00 
            68 [4]
            5? 
            FF 15 [4]
            5? 
            FF 15 

        }
        
        $b1 = "tmscompg.msi" wide
        $b2 = "cvrit000.bat"

    condition:
        2 of ($b*) or 
        $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule IndiaBravo_generic
{
    meta:
        id = "1ada8QdIv2MNgidFSVPqXo"
        fingerprint = "v1_sha256_45b9faf77f98669bfb9a65ef745bc92ccf7cae9d83eb19906af16d8a27841627"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
        $extractDll = "[2] - Extract Dll..." wide
        $createSvc = "[3] - CreateSVC..." wide

    condition:
        all of them
    
}
