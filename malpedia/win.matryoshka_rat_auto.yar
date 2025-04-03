rule win_matryoshka_rat_auto {

    meta:
        id = "16lUjwfkGvE1B7fedzY29Z"
        fingerprint = "v1_sha256_e0e5d3a7b6eaf0039b9fbb2e4baba63862f57599449a2c9f7b8481e16636b102"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.matryoshka_rat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matryoshka_rat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c3 b06f c3 b063 }
            // n = 4, score = 400
            //   c3                   | ret                 
            //   b06f                 | mov                 al, 0x6f
            //   c3                   | ret                 
            //   b063                 | mov                 al, 0x63

        $sequence_1 = { b037 c3 b073 c3 }
            // n = 4, score = 400
            //   b037                 | mov                 al, 0x37
            //   c3                   | ret                 
            //   b073                 | mov                 al, 0x73
            //   c3                   | ret                 

        $sequence_2 = { 747d 488d0d6c400500 e8???????? 4533c9 488d4c2438 4533c0 418d5101 }
            // n = 7, score = 200
            //   747d                 | je                  0x7f
            //   488d0d6c400500       | dec                 eax
            //   e8????????           |                     
            //   4533c9               | lea                 ecx, [0x5406c]
            //   488d4c2438           | inc                 ebp
            //   4533c0               | xor                 ecx, ecx
            //   418d5101             | dec                 eax

        $sequence_3 = { 747e 448b82f4000000 4585c0 7472 }
            // n = 4, score = 200
            //   747e                 | dec                 ebx
            //   448b82f4000000       | mov                 eax, dword ptr [edx + edi*8 + 0x5ed80]
            //   4585c0               | test                byte ptr [eax + edi + 0x38], 0x48
            //   7472                 | je                  0x7f

        $sequence_4 = { 8b4710 835714ff 0b4714 75c9 }
            // n = 4, score = 200
            //   8b4710               | dec                 eax
            //   835714ff             | mov                 edi, eax
            //   0b4714               | je                  0x81
            //   75c9                 | dec                 eax

        $sequence_5 = { 8b4714 85c0 0f8539010000 85db }
            // n = 4, score = 200
            //   8b4714               | mov                 edi, eax
            //   85c0                 | dec                 eax
            //   0f8539010000         | mov                 dword ptr [esp + 0x58], eax
            //   85db                 | dec                 eax

        $sequence_6 = { 747e 83f928 773d 7438 }
            // n = 4, score = 200
            //   747e                 | test                eax, eax
            //   83f928               | je                  0x7e
            //   773d                 | dec                 eax
            //   7438                 | mov                 ebx, eax

        $sequence_7 = { 8b4718 8945f8 85f6 745b }
            // n = 4, score = 200
            //   8b4718               | mov                 esi, dword ptr [edi + 8]
            //   8945f8               | mov                 eax, esi
            //   85f6                 | mov                 eax, dword ptr [edi + 0x10]
            //   745b                 | adc                 dword ptr [edi + 0x14], -1

        $sequence_8 = { 747e 8bcd e8???????? 488bf8 }
            // n = 4, score = 200
            //   747e                 | dec                 ecx
            //   8bcd                 | lea                 edi, [eax - 8]
            //   e8????????           |                     
            //   488bf8               | dec                 eax

        $sequence_9 = { 8b4720 40 895f14 894710 }
            // n = 4, score = 200
            //   8b4720               | jne                 0xfffffed8
            //   40                   | add                 ecx, dword ptr [esp + 0x10]
            //   895f14               | mov                 eax, dword ptr [edi + 0x14]
            //   894710               | test                eax, eax

        $sequence_10 = { 747f 488bcd e8???????? 488bf8 }
            // n = 4, score = 200
            //   747f                 | je                  0x3c
            //   488bcd               | je                  0x80
            //   e8????????           |                     
            //   488bf8               | cmp                 ecx, 0x28

        $sequence_11 = { 8b4724 0fb611 0fb67101 8b4f18 }
            // n = 4, score = 200
            //   8b4724               | mov                 eax, dword ptr [edi + 0x14]
            //   0fb611               | test                eax, eax
            //   0fb67101             | jne                 0x6c
            //   8b4f18               | push                dword ptr [esp + 0x38]

        $sequence_12 = { 8b4714 85c0 7568 ff742438 }
            // n = 4, score = 200
            //   8b4714               | mov                 al, 0x63
            //   85c0                 | ret                 
            //   7568                 | mov                 al, 0x37
            //   ff742438             | ret                 

        $sequence_13 = { 747d 83bc249000000000 7473 4c8d15d68ffdff }
            // n = 4, score = 200
            //   747d                 | lea                 ecx, [esp + 0x38]
            //   83bc249000000000     | inc                 ebp
            //   7473                 | xor                 eax, eax
            //   4c8d15d68ffdff       | inc                 ecx

    condition:
        7 of them and filesize < 843776
}
