rule win_nachocheese_auto {

    meta:
        id = "4ZsOpIDNvYgbUKbET1QSDA"
        fingerprint = "v1_sha256_cadb77319f92fe40994b6aeeeca327d5d465905297aa3f5228d474dfd2f50f6d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.nachocheese."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nachocheese"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 8945fc eb34 83f817 7532 8b7710 }
            // n = 6, score = 300
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   eb34                 | jmp                 0x36
            //   83f817               | cmp                 eax, 0x17
            //   7532                 | jne                 0x34
            //   8b7710               | mov                 esi, dword ptr [edi + 0x10]

        $sequence_1 = { 3d2cc00000 7f18 3d2bc00000 7d1b }
            // n = 4, score = 300
            //   3d2cc00000           | cmp                 eax, 0xc02c
            //   7f18                 | jg                  0x1a
            //   3d2bc00000           | cmp                 eax, 0xc02b
            //   7d1b                 | jge                 0x1d

        $sequence_2 = { 2bfa 8d47fd 3901 8901 }
            // n = 4, score = 300
            //   2bfa                 | sub                 edi, edx
            //   8d47fd               | lea                 eax, [edi - 3]
            //   3901                 | cmp                 dword ptr [ecx], eax
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_3 = { 56 e8???????? 50 e8???????? 6a0a 6a4e }
            // n = 6, score = 300
            //   56                   | push                esi
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a0a                 | push                0xa
            //   6a4e                 | push                0x4e

        $sequence_4 = { 7305 83c303 eb1c 81fb00000100 }
            // n = 4, score = 300
            //   7305                 | jae                 7
            //   83c303               | add                 ebx, 3
            //   eb1c                 | jmp                 0x1e
            //   81fb00000100         | cmp                 ebx, 0x10000

        $sequence_5 = { 50 32db ff15???????? 85c0 7473 8b55f4 }
            // n = 6, score = 300
            //   50                   | push                eax
            //   32db                 | xor                 bl, bl
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7473                 | je                  0x75
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]

        $sequence_6 = { c785e0f9ffff02000000 ff15???????? 3b05???????? 740a a3???????? }
            // n = 5, score = 300
            //   c785e0f9ffff02000000     | mov    dword ptr [ebp - 0x620], 2
            //   ff15????????         |                     
            //   3b05????????         |                     
            //   740a                 | je                  0xc
            //   a3????????           |                     

        $sequence_7 = { 3d9f000000 7e0d 33c0 c3 }
            // n = 4, score = 300
            //   3d9f000000           | cmp                 eax, 0x9f
            //   7e0d                 | jle                 0xf
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 

        $sequence_8 = { 53 33db 8d4df4 51 66c1c008 }
            // n = 5, score = 300
            //   53                   | push                ebx
            //   33db                 | xor                 ebx, ebx
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx
            //   66c1c008             | rol                 ax, 8

        $sequence_9 = { 33c0 c3 05d13fffff 83f801 }
            // n = 4, score = 300
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 
            //   05d13fffff           | add                 eax, 0xffff3fd1
            //   83f801               | cmp                 eax, 1

        $sequence_10 = { 33c8 894710 8b4708 33c1 }
            // n = 4, score = 300
            //   33c8                 | xor                 ecx, eax
            //   894710               | mov                 dword ptr [edi + 0x10], eax
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   33c1                 | xor                 eax, ecx

        $sequence_11 = { b810270000 6806100000 8945fc 8945f4 }
            // n = 4, score = 300
            //   b810270000           | mov                 eax, 0x2710
            //   6806100000           | push                0x1006
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

        $sequence_12 = { 3d2bc00000 7d1b 3d9c000000 7c07 3d9f000000 }
            // n = 5, score = 300
            //   3d2bc00000           | cmp                 eax, 0xc02b
            //   7d1b                 | jge                 0x1d
            //   3d9c000000           | cmp                 eax, 0x9c
            //   7c07                 | jl                  9
            //   3d9f000000           | cmp                 eax, 0x9f

        $sequence_13 = { 40 50 e8???????? b9???????? 83c424 }
            // n = 5, score = 300
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   e8????????           |                     
            //   b9????????           |                     
            //   83c424               | add                 esp, 0x24

        $sequence_14 = { 8bcf 51 6804010000 68???????? eb38 8dbc24a0010000 8bce }
            // n = 7, score = 300
            //   8bcf                 | mov                 ecx, edi
            //   51                   | push                ecx
            //   6804010000           | push                0x104
            //   68????????           |                     
            //   eb38                 | jmp                 0x3a
            //   8dbc24a0010000       | lea                 edi, [esp + 0x1a0]
            //   8bce                 | mov                 ecx, esi

        $sequence_15 = { 7305 83c302 eb29 81fb00010000 7305 83c303 }
            // n = 6, score = 300
            //   7305                 | jae                 7
            //   83c302               | add                 ebx, 2
            //   eb29                 | jmp                 0x2b
            //   81fb00010000         | cmp                 ebx, 0x100
            //   7305                 | jae                 7
            //   83c303               | add                 ebx, 3

    condition:
        7 of them and filesize < 1064960
}
