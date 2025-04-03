import "pe"

rule UniformAlfa
{
    meta:
        id = "3dh5MvPASCb6c5uCr9pcMY"
        fingerprint = "v1_sha256_59766ba641355781e3a419a18865fa0963d5dd199f705f53d9509d2344695828"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "a24377681cf56c712e544af01ac8a5dbaa81d16851a17a147bbf5132890d7437"

    strings:
    /*
        8D 44 24 10        lea     eax, [esp+2Ch+ServiceStatus]
        50                 push    eax             ; lpServiceStatus
        6A 01              push    1               ; dwControl
        56                 push    esi             ; hService
        FF D3              call    ebx ; ControlService
        83 7C 24 14 01     cmp     [esp+2Ch+ServiceStatus.dwCurrentState], 1
        75 EF              jnz     short loc_4010A5
        56                 push    esi             ; hService
        FF 15 08 70 40 00  call    ds:DeleteService
    */

    $stopDeleteService = {
            8D [3] 
            5? 
            6A 01 
            5? 
            FF D? 
            83 [3] 01 
            75 ?? 
            5? 
            FF 15  
        }

    condition:
        $stopDeleteService in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
