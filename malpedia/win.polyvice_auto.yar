rule win_polyvice_auto {

    meta:
        id = "NEDaaik3joNToFOaAdYFo"
        fingerprint = "v1_sha256_099fd1583428c4dcd9d4587ff6b2523b274374d689fdabd70b857d716538d61f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.polyvice."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.polyvice"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 448b7c2434 41c1ef0a 4531fe 4589e7 4131ef 4401f0 458dac0567292914 }
            // n = 7, score = 200
            //   448b7c2434           | inc                 esp
            //   41c1ef0a             | lea                 edx, [edi + ebx - 0x70e44324]
            //   4531fe               | mov                 edi, dword ptr [esp + 0x1c]
            //   4589e7               | inc                 esp
            //   4131ef               | mov                 eax, edi
            //   4401f0               | inc                 ebp
            //   458dac0567292914     | mov                 edi, edx

        $sequence_1 = { 448d4001 4d63c0 4d01c0 488d0c4a 488b13 e8???????? 83ff01 }
            // n = 7, score = 200
            //   448d4001             | inc                 esp
            //   4d63c0               | xor                 edx, esi
            //   4d01c0               | inc                 ebp
            //   488d0c4a             | mov                 esi, edi
            //   488b13               | inc                 ecx
            //   e8????????           |                     
            //   83ff01               | mov                 edi, edi

        $sequence_2 = { 488b4040 4889942498020000 48898424a0020000 488b05???????? 488b10 48899424a8020000 488b5008 }
            // n = 7, score = 200
            //   488b4040             | lea                 edx, [edx + edx + 0x5b9cca4f]
            //   4889942498020000     | inc                 ebp
            //   48898424a0020000     | mov                 esi, edi
            //   488b05????????       |                     
            //   488b10               | mov                 dword ptr [esp + 0x14], edx
            //   48899424a8020000     | mov                 edx, ebx
            //   488b5008             | inc                 ecx

        $sequence_3 = { 4885c0 4889c3 743d 8928 488d0dbcf00000 48897808 ff15???????? }
            // n = 7, score = 200
            //   4885c0               | and                 ebp, ecx
            //   4889c3               | xor                 ebp, eax
            //   743d                 | add                 ebp, edi
            //   8928                 | inc                 ebp
            //   488d0dbcf00000       | mov                 esp, ecx
            //   48897808             | inc                 ebp
            //   ff15????????         |                     

        $sequence_4 = { 488b5020 4889942430040000 488b5028 4889942438040000 488b5030 4889942440040000 }
            // n = 6, score = 200
            //   488b5020             | mov                 ecx, edi
            //   4889942430040000     | mov                 esi, ebx
            //   488b5028             | inc                 esp
            //   4889942438040000     | or                  esi, edx
            //   488b5030             | inc                 esp
            //   4889942440040000     | and                 esi, ecx

        $sequence_5 = { 01d6 01f1 c1cd07 41c1c40e 41c1ed03 4131ec 4531ec }
            // n = 7, score = 200
            //   01d6                 | mov                 esp, ecx
            //   01f1                 | inc                 ecx
            //   c1cd07               | add                 esp, edi
            //   41c1c40e             | inc                 ecx
            //   41c1ed03             | add                 esp, eax
            //   4131ec               | bswap               ebp
            //   4531ec               | inc                 esp

        $sequence_6 = { 894608 49c1e820 4c01ca 4c01c2 4101fb 44891e 89560c }
            // n = 7, score = 200
            //   894608               | dec                 eax
            //   49c1e820             | add                 ebx, esi
            //   4c01ca               | dec                 esp
            //   4c01c2               | add                 ecx, ebx
            //   4101fb               | dec                 ecx
            //   44891e               | add                 esi, edi
            //   89560c               | mov                 edi, ebx

        $sequence_7 = { 488b5918 488b0b ff15???????? 4889d9 89c6 e8???????? 89f0 }
            // n = 7, score = 200
            //   488b5918             | inc                 ebp
            //   488b0b               | xor                 edx, dword ptr [esi + esi*4]
            //   ff15????????         |                     
            //   4889d9               | inc                 edi
            //   89c6                 | xor                 edx, dword ptr [eax]
            //   e8????????           |                     
            //   89f0                 | inc                 esp

        $sequence_8 = { 42083c18 89f7 6644898040080000 29cf 89f9 41d3f9 }
            // n = 6, score = 200
            //   42083c18             | dec                 esp
            //   89f7                 | lea                 esi, [esp + 0x20]
            //   6644898040080000     | dec                 eax
            //   29cf                 | arpl                si, si
            //   89f9                 | dec                 ecx
            //   41d3f9               | mov                 eax, esi

        $sequence_9 = { 41c1cc02 c1c705 4101ff 8b7c2410 31c7 31cf d1c7 }
            // n = 7, score = 200
            //   41c1cc02             | add                 edx, edx
            //   c1c705               | inc                 ecx
            //   4101ff               | ror                 eax, 2
            //   8b7c2410             | inc                 ecx
            //   31c7                 | and                 ecx, esi
            //   31cf                 | inc                 ebp
            //   d1c7                 | mov                 ebx, eax

    condition:
        7 of them and filesize < 369664
}
