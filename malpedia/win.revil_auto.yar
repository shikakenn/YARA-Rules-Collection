rule win_revil_auto {

    meta:
        id = "5cRr6BrW7R30qiQKpewJ6"
        fingerprint = "v1_sha256_120e5cbd30d90d4dc063fdbdb97cb211c1d8a67c5a1d2649d0974884fd7ebfbf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.revil."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7e09 80f92d 0f8509060000 6a03 8d45e0 50 8d45e8 }
            // n = 7, score = 4600
            //   7e09                 | jle                 0xb
            //   80f92d               | cmp                 cl, 0x2d
            //   0f8509060000         | jne                 0x60f
            //   6a03                 | push                3
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   8d45e8               | lea                 eax, [ebp - 0x18]

        $sequence_1 = { 59 8d8568ffffff 50 8d85d0feffff 8db5d0feffff 8dbd80feffff f3a5 }
            // n = 7, score = 4600
            //   59                   | pop                 ecx
            //   8d8568ffffff         | lea                 eax, [ebp - 0x98]
            //   50                   | push                eax
            //   8d85d0feffff         | lea                 eax, [ebp - 0x130]
            //   8db5d0feffff         | lea                 esi, [ebp - 0x130]
            //   8dbd80feffff         | lea                 edi, [ebp - 0x180]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_2 = { 83e801 eb07 b00a 5d c3 83e862 7428 }
            // n = 7, score = 4600
            //   83e801               | sub                 eax, 1
            //   eb07                 | jmp                 9
            //   b00a                 | mov                 al, 0xa
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   83e862               | sub                 eax, 0x62
            //   7428                 | je                  0x2a

        $sequence_3 = { c1ca08 23d6 0bd0 8b4104 57 }
            // n = 5, score = 4600
            //   c1ca08               | ror                 edx, 8
            //   23d6                 | and                 edx, esi
            //   0bd0                 | or                  edx, eax
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   57                   | push                edi

        $sequence_4 = { 8975f0 8955f8 c745bc01000000 895db8 3b5de4 }
            // n = 5, score = 4600
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   c745bc01000000       | mov                 dword ptr [ebp - 0x44], 1
            //   895db8               | mov                 dword ptr [ebp - 0x48], ebx
            //   3b5de4               | cmp                 ebx, dword ptr [ebp - 0x1c]

        $sequence_5 = { 50 e8???????? 8b7d0c 8b4508 59 }
            // n = 5, score = 4600
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   59                   | pop                 ecx

        $sequence_6 = { 8975d8 0fb645ff 0bc8 8bc1 894dd8 }
            // n = 5, score = 4600
            //   8975d8               | mov                 dword ptr [ebp - 0x28], esi
            //   0fb645ff             | movzx               eax, byte ptr [ebp - 1]
            //   0bc8                 | or                  ecx, eax
            //   8bc1                 | mov                 eax, ecx
            //   894dd8               | mov                 dword ptr [ebp - 0x28], ecx

        $sequence_7 = { 334678 3386a0000000 8b4e04 334e2c 334e54 334e7c 338ea4000000 }
            // n = 7, score = 4600
            //   334678               | xor                 eax, dword ptr [esi + 0x78]
            //   3386a0000000         | xor                 eax, dword ptr [esi + 0xa0]
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   334e2c               | xor                 ecx, dword ptr [esi + 0x2c]
            //   334e54               | xor                 ecx, dword ptr [esi + 0x54]
            //   334e7c               | xor                 ecx, dword ptr [esi + 0x7c]
            //   338ea4000000         | xor                 ecx, dword ptr [esi + 0xa4]

        $sequence_8 = { 8bc2 318b80000000 8bcb 3345f4 3375f0 3355f4 }
            // n = 6, score = 4600
            //   8bc2                 | mov                 eax, edx
            //   318b80000000         | xor                 dword ptr [ebx + 0x80], ecx
            //   8bcb                 | mov                 ecx, ebx
            //   3345f4               | xor                 eax, dword ptr [ebp - 0xc]
            //   3375f0               | xor                 esi, dword ptr [ebp - 0x10]
            //   3355f4               | xor                 edx, dword ptr [ebp - 0xc]

        $sequence_9 = { 55 8bec 837d0c20 7605 83c8ff }
            // n = 5, score = 4600
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   837d0c20             | cmp                 dword ptr [ebp + 0xc], 0x20
            //   7605                 | jbe                 7
            //   83c8ff               | or                  eax, 0xffffffff

    condition:
        7 of them and filesize < 155794432
}
