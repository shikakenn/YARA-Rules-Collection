import "pe"

rule RomeoGolf
{
    meta:
        id = "35wYtoNfg0rT58hZhCZjOO"
        fingerprint = "v1_sha256_3fb0fc99a61e322bd4e8b76960a9aa89b980910abcaa3ecb31757a420f16b5bd"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "7322d6b9328a9c708518c99b03a4ed3aa6ba943d7b439f6b1925e6d52a1828fe"

    strings:
    /*
        FF 15 70 80 01 10  call    ds:GetTickCount
        50                 push    eax             ; unsigned int
        E8 80 93 00 00     call    _srand
        83 C4 04           add     esp, 4
        E8 85 93 00 00     call    _rand
        C1 E0 10           shl     eax, 10h
        89 46 0C           mov     [esi+0Ch], eax
        E8 7A 93 00 00     call    _rand
        01 46 0C           add     [esi+0Ch], eax
        E8 72 93 00 00     call    _rand
        C1 E0 10           shl     eax, 10h
        89 46 08           mov     [esi+8], eax
        E8 67 93 00 00     call    _rand
        01 46 08           add     [esi+8], eax
    */

    $idGen = {FF 15 [4] 50 E8 [4] 83 C4 04 E8 [4] C1 ?? 10 89 [2] E8 [4] 01 [2] E8 [4] C1 ?? 10 89 [2] E8 [4] ?? ?? ?? }
    condition:
        $idGen in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
