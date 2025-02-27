rule win_former_first_rat_auto {

    meta:
        id = "139s7zGcsc4K6Zz0fDdZiP"
        fingerprint = "v1_sha256_ce211a46152dbbb02c8c895324876bff740383a9e542511dce112b8640015613"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.former_first_rat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.former_first_rat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3c31 7529 8d74246c e8???????? b904000000 b8???????? 8db424f4000000 }
            // n = 7, score = 200
            //   3c31                 | cmp                 al, 0x31
            //   7529                 | jne                 0x2b
            //   8d74246c             | lea                 esi, [esp + 0x6c]
            //   e8????????           |                     
            //   b904000000           | mov                 ecx, 4
            //   b8????????           |                     
            //   8db424f4000000       | lea                 esi, [esp + 0xf4]

        $sequence_1 = { 50 68???????? e8???????? 83c408 eb03 894608 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   eb03                 | jmp                 5
            //   894608               | mov                 dword ptr [esi + 8], eax

        $sequence_2 = { e8???????? 8d95f4feffff 52 8bd6 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   8d95f4feffff         | lea                 edx, [ebp - 0x10c]
            //   52                   | push                edx
            //   8bd6                 | mov                 edx, esi

        $sequence_3 = { 0f851d010000 8d8424dc010000 e8???????? 8b15???????? }
            // n = 4, score = 200
            //   0f851d010000         | jne                 0x123
            //   8d8424dc010000       | lea                 eax, [esp + 0x1dc]
            //   e8????????           |                     
            //   8b15????????         |                     

        $sequence_4 = { 894c240c 8bd3 3bc1 7420 8d642400 8bf0 8bfa }
            // n = 7, score = 200
            //   894c240c             | mov                 dword ptr [esp + 0xc], ecx
            //   8bd3                 | mov                 edx, ebx
            //   3bc1                 | cmp                 eax, ecx
            //   7420                 | je                  0x22
            //   8d642400             | lea                 esp, [esp]
            //   8bf0                 | mov                 esi, eax
            //   8bfa                 | mov                 edi, edx

        $sequence_5 = { 740c 68???????? bb06000000 eb0a 68???????? }
            // n = 5, score = 200
            //   740c                 | je                  0xe
            //   68????????           |                     
            //   bb06000000           | mov                 ebx, 6
            //   eb0a                 | jmp                 0xc
            //   68????????           |                     

        $sequence_6 = { 8944243c b8???????? 8d5001 8da42400000000 8a08 40 84c9 }
            // n = 7, score = 200
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax
            //   b8????????           |                     
            //   8d5001               | lea                 edx, [eax + 1]
            //   8da42400000000       | lea                 esp, [esp]
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl

        $sequence_7 = { be05000000 6a1c 8d4c2448 33c0 51 }
            // n = 5, score = 200
            //   be05000000           | mov                 esi, 5
            //   6a1c                 | push                0x1c
            //   8d4c2448             | lea                 ecx, [esp + 0x48]
            //   33c0                 | xor                 eax, eax
            //   51                   | push                ecx

        $sequence_8 = { 48894758 488d4754 48894760 48832100 }
            // n = 4, score = 100
            //   48894758             | add                 eax, ebp
            //   488d4754             | xor                 eax, eax
            //   48894760             | dec                 eax
            //   48832100             | mov                 dword ptr [esp + 0x4c0], eax

        $sequence_9 = { 498d144a 4c3bd2 7306 66418b02 eb45 }
            // n = 5, score = 100
            //   498d144a             | dec                 eax
            //   4c3bd2               | lea                 eax, [edi + 0x54]
            //   7306                 | dec                 eax
            //   66418b02             | mov                 dword ptr [edi + 0x60], eax
            //   eb45                 | dec                 eax

        $sequence_10 = { 41baffff0000 4c8b08 4d3bc8 7443 }
            // n = 4, score = 100
            //   41baffff0000         | dec                 ecx
            //   4c8b08               | cmp                 ecx, esi
            //   4d3bc8               | dec                 eax
            //   7443                 | mov                 dword ptr [edi + 0x58], eax

        $sequence_11 = { 83e95a 0f8487000000 83e901 7425 }
            // n = 4, score = 100
            //   83e95a               | dec                 eax
            //   0f8487000000         | mov                 ebx, edx
            //   83e901               | dec                 eax
            //   7425                 | mov                 edi, ecx

        $sequence_12 = { e8???????? 488bc3 e9???????? f6417804 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   488bc3               | inc                 ebp
            //   e9????????           |                     
            //   f6417804             | xor                 esi, esi

        $sequence_13 = { 48898424c0040000 4533f6 488bda 488bf9 493bce }
            // n = 5, score = 100
            //   48898424c0040000     | dec                 esp
            //   4533f6               | lea                 eax, [eax + eax*8 + 9]
            //   488bda               | dec                 ecx
            //   488bf9               | shl                 eax, 4
            //   493bce               | dec                 ebp

        $sequence_14 = { 488b442440 4c8d44c009 49c1e004 4d03c5 33c0 }
            // n = 5, score = 100
            //   488b442440           | dec                 eax
            //   4c8d44c009           | mov                 ecx, dword ptr [esp + 0xa0]
            //   49c1e004             | nop                 
            //   4d03c5               | dec                 eax
            //   33c0                 | mov                 eax, dword ptr [esp + 0x40]

        $sequence_15 = { 4c89b424c0000000 4c89b424c8000000 488b8c24a0000000 e8???????? 90 }
            // n = 5, score = 100
            //   4c89b424c0000000     | dec                 esp
            //   4c89b424c8000000     | mov                 dword ptr [esp + 0xc0], esi
            //   488b8c24a0000000     | dec                 esp
            //   e8????????           |                     
            //   90                   | mov                 dword ptr [esp + 0xc8], esi

    condition:
        7 of them and filesize < 626688
}
