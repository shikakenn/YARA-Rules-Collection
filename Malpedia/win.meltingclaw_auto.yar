rule win_meltingclaw_auto {

    meta:
        id = "73Dr2Hf90gxksbX1QJZNPe"
        fingerprint = "v1_sha256_379103784a97b527734f31e44cda4d460b2bdbd8572feff4730fa002535654cf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.meltingclaw."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.meltingclaw"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 488d8da8000000 48ffc9 48ffc1 803900 75f8 4c8d4590 33d2 }
            // n = 7, score = 200
            //   488d8da8000000       | lea                 eax, [0xac95]
            //   48ffc9               | inc                 ecx
            //   48ffc1               | mov                 ecx, 0x1b
            //   803900               | xor                 eax, eax
            //   75f8                 | dec                 eax
            //   4c8d4590             | mov                 dword ptr [ebp - 0x20], eax
            //   33d2                 | mov                 word ptr [ebp - 0x18], ax

        $sequence_1 = { 4c8b0a 33f6 448bc6 48c7420816000000 4c8bd2 48c7421009000000 488bf9 }
            // n = 7, score = 200
            //   4c8b0a               | dec                 eax
            //   33f6                 | mov                 ecx, esi
            //   448bc6               | dec                 eax
            //   48c7420816000000     | mov                 ecx, edi
            //   4c8bd2               | inc                 ebp
            //   48c7421009000000     | test                edi, edi
            //   488bf9               | inc                 ebp

        $sequence_2 = { 7424 83ea01 7412 83fa01 7562 }
            // n = 5, score = 200
            //   7424                 | dec                 eax
            //   83ea01               | mov                 dword ptr [ebp + 0x40], 0x10000
            //   7412                 | dec                 eax
            //   83fa01               | mov                 dword ptr [ebp + 0x70], ebx
            //   7562                 | dec                 eax

        $sequence_3 = { 0fb74c4420 6643890c46 49ffc0 4983f80a 72b0 488b8c2420020000 4833cc }
            // n = 7, score = 200
            //   0fb74c4420           | xchg                dword ptr [esi + edi*8 + 0x25740], edi
            //   6643890c46           | xor                 eax, eax
            //   49ffc0               | dec                 eax
            //   4983f80a             | mov                 ebx, dword ptr [esp + 0x50]
            //   72b0                 | dec                 eax
            //   488b8c2420020000     | mov                 ebp, dword ptr [esp + 0x58]
            //   4833cc               | dec                 eax

        $sequence_4 = { 49c706212a0100 488906 410fbec2 6bc83f 49c70700010000 80c121 418809 }
            // n = 7, score = 200
            //   49c706212a0100       | mov                 dword ptr [ebp + 0xbc], edi
            //   488906               | inc                 ecx
            //   410fbec2             | mov                 ebp, 0x10000
            //   6bc83f               | dec                 esp
            //   49c70700010000       | mov                 dword ptr [esp + 0x50], esp
            //   80c121               | dec                 eax
            //   418809               | lea                 edx, [ebp + 0x80]

        $sequence_5 = { 85c0 78d6 3de4000000 73cf 4803c0 418b84c790bd0100 ebc4 }
            // n = 7, score = 200
            //   85c0                 | inc                 ebp
            //   78d6                 | xor                 eax, eax
            //   3de4000000           | xor                 edx, edx
            //   73cf                 | dec                 eax
            //   4803c0               | mov                 dword ptr [esp + 0x28], ecx
            //   418b84c790bd0100     | mov                 dword ptr [esp + 0x20], edx
            //   ebc4                 | dec                 esp

        $sequence_6 = { 0fb6c0 0fb74c4420 6643890c46 49ffc0 4983f80e 72b0 488b8c2420020000 }
            // n = 7, score = 200
            //   0fb6c0               | dec                 esp
            //   0fb74c4420           | mov                 dword ptr [ebp - 0x48], esp
            //   6643890c46           | dec                 esp
            //   49ffc0               | mov                 dword ptr [ebp - 0x40], ebp
            //   4983f80e             | dec                 eax
            //   72b0                 | mov                 dword ptr [ebp - 0x38], 0x12a21
            //   488b8c2420020000     | dec                 esp

        $sequence_7 = { 7508 48396930 b001 7403 408ac5 }
            // n = 5, score = 200
            //   7508                 | cmp                 dword ptr [eax + 0x18], 8
            //   48396930             | jb                  0xac0
            //   b001                 | dec                 eax
            //   7403                 | mov                 dword ptr [ebp - 0x78], esi
            //   408ac5               | dec                 eax

        $sequence_8 = { 72e8 41881c39 49ffc1 4983f94c 72af 488b5c2408 }
            // n = 6, score = 200
            //   72e8                 | dec                 eax
            //   41881c39             | mov                 edi, dword ptr [esp + 0x40]
            //   49ffc1               | dec                 esp
            //   4983f94c             | mov                 esi, dword ptr [esp + 0x48]
            //   72af                 | dec                 eax
            //   488b5c2408           | cmp                 ecx, 9

        $sequence_9 = { d3e8 4d894708 41894718 410fb608 83e10f 480fbe841140960100 }
            // n = 6, score = 200
            //   d3e8                 | inc                 esp
            //   4d894708             | mov                 ecx, ebx
            //   41894718             | dec                 eax
            //   410fb608             | mov                 dword ptr [esp + 0x20], eax
            //   83e10f               | inc                 ebp
            //   480fbe841140960100     | xor    eax, eax

    condition:
        7 of them and filesize < 348160
}
