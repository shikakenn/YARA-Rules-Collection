rule win_hancitor_auto {

    meta:
        id = "4DrsInl3aN5QnZKEECFQPg"
        fingerprint = "v1_sha256_065eca202c5de0c3aac505b9a1e3b15150d867b922d1e944cb9db0f3b78d775f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.hancitor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hancitor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a00 6824040000 6a00 6a00 6a00 }
            // n = 5, score = 1000
            //   6a00                 | push                0
            //   6824040000           | push                0x424
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_1 = { 6800010000 6a40 68???????? e8???????? }
            // n = 4, score = 900
            //   6800010000           | push                0x100
            //   6a40                 | push                0x40
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_2 = { 750d e8???????? 83c010 a3???????? }
            // n = 4, score = 800
            //   750d                 | jne                 0xf
            //   e8????????           |                     
            //   83c010               | add                 eax, 0x10
            //   a3????????           |                     

        $sequence_3 = { 6a20 68???????? 68???????? e8???????? 83c410 }
            // n = 5, score = 700
            //   6a20                 | push                0x20
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_4 = { 55 8bec 81ec58010000 6a44 }
            // n = 4, score = 700
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec58010000         | sub                 esp, 0x158
            //   6a44                 | push                0x44

        $sequence_5 = { c745fc00000000 b901000000 85c9 7448 }
            // n = 4, score = 600
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   b901000000           | mov                 ecx, 1
            //   85c9                 | test                ecx, ecx
            //   7448                 | je                  0x4a

        $sequence_6 = { 83f801 750e 57 ff15???????? 8bd8 }
            // n = 5, score = 600
            //   83f801               | cmp                 eax, 1
            //   750e                 | jne                 0x10
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_7 = { 8945f4 8b4df8 8b5154 52 8b4508 }
            // n = 5, score = 600
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8b5154               | mov                 edx, dword ptr [ecx + 0x54]
            //   52                   | push                edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_8 = { a1???????? 85c0 740c ff7508 }
            // n = 4, score = 600
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   740c                 | je                  0xe
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_9 = { 83f941 72ed 881d???????? c705????????01000000 }
            // n = 4, score = 600
            //   83f941               | cmp                 ecx, 0x41
            //   72ed                 | jb                  0xffffffef
            //   881d????????         |                     
            //   c705????????01000000     |     

        $sequence_10 = { 6b55fc28 8b45f4 8b4d08 034c1014 51 6b55fc28 8b45f4 }
            // n = 7, score = 600
            //   6b55fc28             | imul                edx, dword ptr [ebp - 4], 0x28
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   034c1014             | add                 ecx, dword ptr [eax + edx + 0x14]
            //   51                   | push                ecx
            //   6b55fc28             | imul                edx, dword ptr [ebp - 4], 0x28
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_11 = { 55 8bec 8b4d08 6a00 6a01 51 }
            // n = 6, score = 600
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   51                   | push                ecx

        $sequence_12 = { 55 8bec a1???????? 0b05???????? 7510 }
            // n = 5, score = 600
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   a1????????           |                     
            //   0b05????????         |                     
            //   7510                 | jne                 0x12

        $sequence_13 = { 0fb708 81e100f00000 c1f90c 66894dfc 0fb755fc 83fa03 }
            // n = 6, score = 600
            //   0fb708               | movzx               ecx, word ptr [eax]
            //   81e100f00000         | and                 ecx, 0xf000
            //   c1f90c               | sar                 ecx, 0xc
            //   66894dfc             | mov                 word ptr [ebp - 4], cx
            //   0fb755fc             | movzx               edx, word ptr [ebp - 4]
            //   83fa03               | cmp                 edx, 3

        $sequence_14 = { e8???????? 83c404 8b550c 8902 b801000000 }
            // n = 5, score = 600
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   8902                 | mov                 dword ptr [edx], eax
            //   b801000000           | mov                 eax, 1

        $sequence_15 = { c60600 ff15???????? 8b3d???????? 85c0 740a }
            // n = 5, score = 600
            //   c60600               | mov                 byte ptr [esi], 0
            //   ff15????????         |                     
            //   8b3d????????         |                     
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc

        $sequence_16 = { 53 56 57 8b483c 33f6 03c8 }
            // n = 6, score = 600
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b483c               | mov                 ecx, dword ptr [eax + 0x3c]
            //   33f6                 | xor                 esi, esi
            //   03c8                 | add                 ecx, eax

        $sequence_17 = { 6bc800 8b5508 0fbe040a 8945fc 8b4dfc 83e962 894dfc }
            // n = 7, score = 600
            //   6bc800               | imul                ecx, eax, 0
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0fbe040a             | movsx               eax, byte ptr [edx + ecx]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83e962               | sub                 ecx, 0x62
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx

        $sequence_18 = { 8b413c 8b440828 03c1 ffd0 33c0 }
            // n = 5, score = 600
            //   8b413c               | mov                 eax, dword ptr [ecx + 0x3c]
            //   8b440828             | mov                 eax, dword ptr [eax + ecx + 0x28]
            //   03c1                 | add                 eax, ecx
            //   ffd0                 | call                eax
            //   33c0                 | xor                 eax, eax

        $sequence_19 = { f8 d1683a 55 08709e 891f }
            // n = 5, score = 100
            //   f8                   | clc                 
            //   d1683a               | shr                 dword ptr [eax + 0x3a], 1
            //   55                   | push                ebp
            //   08709e               | or                  byte ptr [eax - 0x62], dh
            //   891f                 | mov                 dword ptr [edi], ebx

        $sequence_20 = { 05c8e40a00 8945dc 817d88dab21701 7508 8b458c 2b4588 }
            // n = 6, score = 100
            //   05c8e40a00           | add                 eax, 0xae4c8
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   817d88dab21701       | cmp                 dword ptr [ebp - 0x78], 0x117b2da
            //   7508                 | jne                 0xa
            //   8b458c               | mov                 eax, dword ptr [ebp - 0x74]
            //   2b4588               | sub                 eax, dword ptr [ebp - 0x78]

        $sequence_21 = { a1???????? 83c05b a3???????? a1???????? 0345cc a3???????? 817df8b07d0900 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   83c05b               | add                 eax, 0x5b
            //   a3????????           |                     
            //   a1????????           |                     
            //   0345cc               | add                 eax, dword ptr [ebp - 0x34]
            //   a3????????           |                     
            //   817df8b07d0900       | cmp                 dword ptr [ebp - 8], 0x97db0

        $sequence_22 = { 0f8d7f010000 8b45c4 0345cc 8945c4 8b45cc 0345e4 8945cc }
            // n = 7, score = 100
            //   0f8d7f010000         | jge                 0x185
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   0345cc               | add                 eax, dword ptr [ebp - 0x34]
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   0345e4               | add                 eax, dword ptr [ebp - 0x1c]
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax

        $sequence_23 = { 83e803 8945b4 eb22 833d????????00 7414 8b45e4 }
            // n = 6, score = 100
            //   83e803               | sub                 eax, 3
            //   8945b4               | mov                 dword ptr [ebp - 0x4c], eax
            //   eb22                 | jmp                 0x24
            //   833d????????00       |                     
            //   7414                 | je                  0x16
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_24 = { 2b4588 ffd0 ebc9 a1???????? 8945b4 a1???????? 83c044 }
            // n = 7, score = 100
            //   2b4588               | sub                 eax, dword ptr [ebp - 0x78]
            //   ffd0                 | call                eax
            //   ebc9                 | jmp                 0xffffffcb
            //   a1????????           |                     
            //   8945b4               | mov                 dword ptr [ebp - 0x4c], eax
            //   a1????????           |                     
            //   83c044               | add                 eax, 0x44

        $sequence_25 = { 8b45a0 05c8d45566 7440 c745880a000000 eb07 8b4588 }
            // n = 6, score = 100
            //   8b45a0               | mov                 eax, dword ptr [ebp - 0x60]
            //   05c8d45566           | add                 eax, 0x6655d4c8
            //   7440                 | je                  0x42
            //   c745880a000000       | mov                 dword ptr [ebp - 0x78], 0xa
            //   eb07                 | jmp                 9
            //   8b4588               | mov                 eax, dword ptr [ebp - 0x78]

        $sequence_26 = { 55 8bec 83ec78 a1???????? a3???????? c745c488b24000 a1???????? }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec78               | sub                 esp, 0x78
            //   a1????????           |                     
            //   a3????????           |                     
            //   c745c488b24000       | mov                 dword ptr [ebp - 0x3c], 0x40b288
            //   a1????????           |                     

    condition:
        7 of them and filesize < 106496
}
