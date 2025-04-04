rule win_waterminer_auto {

    meta:
        id = "4snFYbobtUAI4BCnnjDSG4"
        fingerprint = "v1_sha256_fee2af94ed2d9b29403d90ebf96331b0858215bab4f3b7310fc1b1dc42373d50"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.waterminer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.waterminer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 03bc24a8000000 488bcd 4c8d0d35cb0300 83e13f }
            // n = 4, score = 100
            //   03bc24a8000000       | inc                 ecx
            //   488bcd               | mov                 eax, dword ptr [eax + eax]
            //   4c8d0d35cb0300       | add                 eax, dword ptr [esp + 0xc]
            //   83e13f               | inc                 esp

        $sequence_1 = { 46 007e9f 46 0000 07 }
            // n = 5, score = 100
            //   46                   | inc                 esi
            //   007e9f               | add                 byte ptr [esi - 0x61], bh
            //   46                   | inc                 esi
            //   0000                 | add                 byte ptr [eax], al
            //   07                   | pop                 es

        $sequence_2 = { 8b5508 3b14cd88c04900 750c 8b45fc 8b04c58cc04900 eb04 }
            // n = 6, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   3b14cd88c04900       | cmp                 edx, dword ptr [ecx*8 + 0x49c088]
            //   750c                 | jne                 0xe
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b04c58cc04900       | mov                 eax, dword ptr [eax*8 + 0x49c08c]
            //   eb04                 | jmp                 6

        $sequence_3 = { 00ed ac 45 00fc ac 45 }
            // n = 6, score = 100
            //   00ed                 | add                 ch, ch
            //   ac                   | lodsb               al, byte ptr [esi]
            //   45                   | inc                 ebp
            //   00fc                 | add                 ah, bh
            //   ac                   | lodsb               al, byte ptr [esi]
            //   45                   | inc                 ebp

        $sequence_4 = { 02d0 49ffc3 418d4001 881418 }
            // n = 4, score = 100
            //   02d0                 | inc                 ecx
            //   49ffc3               | mov                 byte ptr [eax + ebx], cl
            //   418d4001             | inc                 ecx
            //   881418               | mov                 al, byte ptr [ebx]

        $sequence_5 = { 8b55e0 8b450c 8b75e0 668b8c7154074b00 66894c500c }
            // n = 5, score = 100
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b75e0               | mov                 esi, dword ptr [ebp - 0x20]
            //   668b8c7154074b00     | mov                 cx, word ptr [ecx + esi*2 + 0x4b0754]
            //   66894c500c           | mov                 word ptr [eax + edx*2 + 0xc], cx

        $sequence_6 = { 0344240c 4403d0 428b4405e7 418bd2 }
            // n = 4, score = 100
            //   0344240c             | cmp                 ecx, edx
            //   4403d0               | add                 dl, al
            //   428b4405e7           | dec                 ecx
            //   418bd2               | inc                 ebx

        $sequence_7 = { 8b5508 c1fa05 8b4508 83e01f c1e006 8b0c95c02b4b00 837c013800 }
            // n = 7, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   c1fa05               | sar                 edx, 5
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83e01f               | and                 eax, 0x1f
            //   c1e006               | shl                 eax, 6
            //   8b0c95c02b4b00       | mov                 ecx, dword ptr [edx*4 + 0x4b2bc0]
            //   837c013800           | cmp                 dword ptr [ecx + eax + 0x38], 0

        $sequence_8 = { 0fb69144314800 ff249538314800 c745c806000000 eb22 8b45cc 83e801 8945cc }
            // n = 7, score = 100
            //   0fb69144314800       | movzx               edx, byte ptr [ecx + 0x483144]
            //   ff249538314800       | jmp                 dword ptr [edx*4 + 0x483138]
            //   c745c806000000       | mov                 dword ptr [ebp - 0x38], 6
            //   eb22                 | jmp                 0x24
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   83e801               | sub                 eax, 1
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax

        $sequence_9 = { 03c1 03d0 488d051e580500 418b0400 }
            // n = 4, score = 100
            //   03c1                 | lea                 eax, [0x5579f]
            //   03d0                 | inc                 ebx
            //   488d051e580500       | xor                 eax, dword ptr [ecx + eax]
            //   418b0400             | add                 eax, dword ptr [esp + 0x10]

        $sequence_10 = { 6bc01c 8b8880434b00 330d???????? 894dfc 740c }
            // n = 5, score = 100
            //   6bc01c               | imul                eax, eax, 0x1c
            //   8b8880434b00         | mov                 ecx, dword ptr [eax + 0x4b4380]
            //   330d????????         |                     
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   740c                 | je                  0xe

        $sequence_11 = { 8b5508 83e21f c1e206 8b048dc02b4b00 833c10ff }
            // n = 5, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   83e21f               | and                 edx, 0x1f
            //   c1e206               | shl                 edx, 6
            //   8b048dc02b4b00       | mov                 eax, dword ptr [ecx*4 + 0x4b2bc0]
            //   833c10ff             | cmp                 dword ptr [eax + edx], -1

        $sequence_12 = { 03c0 2bc8 0f84ec040000 8d41ff 8b848288d20600 }
            // n = 5, score = 100
            //   03c0                 | add                 eax, dword ptr [esp + 0xc]
            //   2bc8                 | inc                 esp
            //   0f84ec040000         | add                 edx, eax
            //   8d41ff               | dec                 eax
            //   8b848288d20600       | lea                 eax, [0x5561a]

        $sequence_13 = { 02c8 41880c18 418a03 240f }
            // n = 4, score = 100
            //   02c8                 | add                 cl, al
            //   41880c18             | inc                 ecx
            //   418a03               | mov                 byte ptr [eax + ebx], cl
            //   240f                 | inc                 ecx

        $sequence_14 = { 03442410 4403e8 428b4405e7 418bd5 }
            // n = 4, score = 100
            //   03442410             | dec                 esp
            //   4403e8               | lea                 eax, [0x55894]
            //   428b4405e7           | inc                 ecx
            //   418bd5               | xor                 edx, ebp

        $sequence_15 = { 0344240c 4403d0 488d051a560500 418b0400 }
            // n = 4, score = 100
            //   0344240c             | inc                 esp
            //   4403d0               | add                 edx, eax
            //   488d051a560500       | inc                 edx
            //   418b0400             | mov                 eax, dword ptr [ebp + eax - 0x19]

    condition:
        7 of them and filesize < 1556480
}
