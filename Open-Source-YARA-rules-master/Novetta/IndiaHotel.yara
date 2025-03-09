import "pe"

rule IndiaHotel
{
    meta:
        id = "1jRzbdYGXzDBhN798NG47"
        fingerprint = "v1_sha256_56b7d9fa96f1a23300334cb988de87659532d5f2882c477a59ee77bb40687e50"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "8a4fc5007faf85e07710dca705108df9fd6252fe3d57dfade314120d72f6d83f"

    strings:
    /*
        6A 0A              push    0Ah             ; int
        8D 85 C4 E4 FF FF  lea     eax, [ebp+Source]
        68 10 02 00 00     push    210h            ; unsigned int
        50                 push    eax             ; void *
        E8 FA 60 00 00     call    ??_L@YGXPAXIHP6EX0@Z1@Z; `eh vector constructor iterator'(void *,uint,int,void (*)(void *),void (*)(void *))
    */

    $fileExtractorArraySetup = {
            6A 0A 
            8D [5-6]
            68 10 02 00 00 
            50 
            E8
        }

    condition:
        $fileExtractorArraySetup in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
