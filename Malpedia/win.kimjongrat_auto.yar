rule win_kimjongrat_auto {

    meta:
        id = "6IocRQVp2r43hQhbhP57xp"
        fingerprint = "v1_sha256_edaec54e18eb1d3289f1a7f5442afe5f1403cb37fea612fda6550402130dfa44"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.kimjongrat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kimjongrat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff7510 56 e8???????? 83c408 eb30 57 e8???????? }
            // n = 7, score = 100
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   eb30                 | jmp                 0x32
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_1 = { 751c 8b45f4 83c004 8945f4 8b00 43 83c704 }
            // n = 7, score = 100
            //   751c                 | jne                 0x1e
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   83c004               | add                 eax, 4
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   43                   | inc                 ebx
            //   83c704               | add                 edi, 4

        $sequence_2 = { eb02 33db ff7610 57 e8???????? 83c408 85c0 }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   33db                 | xor                 ebx, ebx
            //   ff7610               | push                dword ptr [esi + 0x10]
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax

        $sequence_3 = { c7856cffffffffffffff 8b4510 80380c 7513 8b4dd4 ff31 ff7008 }
            // n = 7, score = 100
            //   c7856cffffffffffffff     | mov    dword ptr [ebp - 0x94], 0xffffffff
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   80380c               | cmp                 byte ptr [eax], 0xc
            //   7513                 | jne                 0x15
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   ff31                 | push                dword ptr [ecx]
            //   ff7008               | push                dword ptr [eax + 8]

        $sequence_4 = { eb30 c6840d64d9ffff5e eb26 c6840d64d9ffff2f eb1c c6840d64d9ffff3f eb12 }
            // n = 7, score = 100
            //   eb30                 | jmp                 0x32
            //   c6840d64d9ffff5e     | mov                 byte ptr [ebp + ecx - 0x269c], 0x5e
            //   eb26                 | jmp                 0x28
            //   c6840d64d9ffff2f     | mov                 byte ptr [ebp + ecx - 0x269c], 0x2f
            //   eb1c                 | jmp                 0x1e
            //   c6840d64d9ffff3f     | mov                 byte ptr [ebp + ecx - 0x269c], 0x3f
            //   eb12                 | jmp                 0x14

        $sequence_5 = { e8???????? 53 57 e8???????? 8b5304 0fbf5b26 83c414 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   53                   | push                ebx
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b5304               | mov                 edx, dword ptr [ebx + 4]
            //   0fbf5b26             | movsx               ebx, word ptr [ebx + 0x26]
            //   83c414               | add                 esp, 0x14

        $sequence_6 = { eb13 8b4d20 0fb6c1 85c9 bb20000000 0f45d8 80cb01 }
            // n = 7, score = 100
            //   eb13                 | jmp                 0x15
            //   8b4d20               | mov                 ecx, dword ptr [ebp + 0x20]
            //   0fb6c1               | movzx               eax, cl
            //   85c9                 | test                ecx, ecx
            //   bb20000000           | mov                 ebx, 0x20
            //   0f45d8               | cmovne              ebx, eax
            //   80cb01               | or                  bl, 1

        $sequence_7 = { c7852cffffff00000000 741e 8d8504ffffff 68???????? 50 e8???????? 83c408 }
            // n = 7, score = 100
            //   c7852cffffff00000000     | mov    dword ptr [ebp - 0xd4], 0
            //   741e                 | je                  0x20
            //   8d8504ffffff         | lea                 eax, [ebp - 0xfc]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_8 = { e8???????? 83c410 5d c3 6a00 b8???????? 6aff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   6a00                 | push                0
            //   b8????????           |                     
            //   6aff                 | push                -1

        $sequence_9 = { e8???????? 668b4608 663345c4 b9007e0000 6623c1 83c40c 663145c4 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   668b4608             | mov                 ax, word ptr [esi + 8]
            //   663345c4             | xor                 ax, word ptr [ebp - 0x3c]
            //   b9007e0000           | mov                 ecx, 0x7e00
            //   6623c1               | and                 ax, cx
            //   83c40c               | add                 esp, 0xc
            //   663145c4             | xor                 word ptr [ebp - 0x3c], ax

    condition:
        7 of them and filesize < 1572864
}
