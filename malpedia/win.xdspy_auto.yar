rule win_xdspy_auto {

    meta:
        id = "2h7gjW0HJkzwuGcqmQmIXY"
        fingerprint = "v1_sha256_1f709444cf724d3961e54f18b66ae4023548e4088934cac26da730f0bde271d9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.xdspy."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xdspy"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d1c8d804e4100 8bf0 83e61f c1e606 8b0b }
            // n = 5, score = 200
            //   8d1c8d804e4100       | lea                 ebx, [ecx*4 + 0x414e80]
            // 
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   8b0b                 | mov                 ecx, dword ptr [ebx]

        $sequence_1 = { 59 59 68d0070000 68???????? }
            // n = 4, score = 200
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   68d0070000           | push                0x7d0
            //   68????????           |                     

        $sequence_2 = { 50 897d80 e8???????? 83c418 8d45c4 50 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   897d80               | mov                 dword ptr [ebp - 0x80], edi
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   8d45c4               | lea                 eax, [ebp - 0x3c]
            //   50                   | push                eax

        $sequence_3 = { e8???????? ff35???????? 8d851cd1ffff 50 e8???????? }
            // n = 5, score = 200
            //   e8????????           |                     
            //   ff35????????         |                     
            //   8d851cd1ffff         | lea                 eax, [ebp - 0x2ee4]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 53 e8???????? 59 59 3bc6 740e 50 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   3bc6                 | cmp                 eax, esi
            //   740e                 | je                  0x10
            //   50                   | push                eax

        $sequence_5 = { e8???????? 59 59 8945e0 85c0 7461 8d0cbd804e4100 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   85c0                 | test                eax, eax
            //   7461                 | je                  0x63
            //   8d0cbd804e4100       | lea                 ecx, [edi*4 + 0x414e80]

        $sequence_6 = { 56 e8???????? 83c414 ebc9 8bc8 c1f905 8d1c8d804e4100 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   ebc9                 | jmp                 0xffffffcb
            //   8bc8                 | mov                 ecx, eax
            //   c1f905               | sar                 ecx, 5
            //   8d1c8d804e4100       | lea                 ebx, [ecx*4 + 0x414e80]

        $sequence_7 = { ebd0 8bc8 c1f905 8d3c8d804e4100 }
            // n = 4, score = 200
            //   ebd0                 | jmp                 0xffffffd2
            //   8bc8                 | mov                 ecx, eax
            //   c1f905               | sar                 ecx, 5
            //   8d3c8d804e4100       | lea                 edi, [ecx*4 + 0x414e80]

        $sequence_8 = { 803073 ffc1 48ffc0 3bca 7cea 803d????????4d }
            // n = 6, score = 100
            //   803073               | xor                 byte ptr [eax], 0x73
            //   ffc1                 | inc                 ecx
            //   48ffc0               | dec                 eax
            //   3bca                 | inc                 eax
            //   7cea                 | cmp                 ecx, edx
            //   803d????????4d       |                     

        $sequence_9 = { 83fa0a 7d15 4863ca 0fb68419b01f0200 }
            // n = 4, score = 100
            //   83fa0a               | mov                 esi, dword ptr [esp + 0x38]
            //   7d15                 | dec                 eax
            //   4863ca               | mov                 edi, dword ptr [esp + 0x40]
            //   0fb68419b01f0200     | cmp                 edx, 0xa

        $sequence_10 = { eb03 488bc7 488b0d???????? 4533c9 41b888130000 498bd5 }
            // n = 6, score = 100
            //   eb03                 | call                eax
            //   488bc7               | movzx               eax, word ptr [ecx + edi + 0x216c0]
            //   488b0d????????       |                     
            //   4533c9               | sub                 ax, 0x47
            //   41b888130000         | inc                 dx
            //   498bd5               | mov                 dword ptr [ecx + eax], eax

        $sequence_11 = { 6642391c47 75f6 4c8bce ba02000000 488bcf ffd0 }
            // n = 6, score = 100
            //   6642391c47           | jge                 0x17
            //   75f6                 | dec                 eax
            //   4c8bce               | arpl                dx, cx
            //   ba02000000           | movzx               eax, byte ptr [ecx + ebx + 0x21fb0]
            //   488bcf               | inc                 dx
            //   ffd0                 | cmp                 dword ptr [edi + eax*2], ebx

        $sequence_12 = { 0fb78439c0160200 6683e847 6642890401 4883c102 4881f92c030000 7ce2 }
            // n = 6, score = 100
            //   0fb78439c0160200     | jne                 0xfffffff8
            //   6683e847             | dec                 esp
            //   6642890401           | mov                 ecx, esi
            //   4883c102             | mov                 edx, 2
            //   4881f92c030000       | dec                 eax
            //   7ce2                 | mov                 ecx, edi

        $sequence_13 = { fe08 488d4001 443838 75f5 488d85f0030000 4438bdf0030000 }
            // n = 6, score = 100
            //   fe08                 | dec                 eax
            //   488d4001             | add                 ecx, 2
            //   443838               | dec                 eax
            //   75f5                 | cmp                 ecx, 0x32c
            //   488d85f0030000       | jl                  0xfffffff8
            //   4438bdf0030000       | jmp                 5

        $sequence_14 = { 668935???????? 488b742438 66893d???????? 488b7c2440 668905???????? }
            // n = 5, score = 100
            //   668935????????       |                     
            //   488b742438           | jl                  0xffffffec
            //   66893d????????       |                     
            //   488b7c2440           | dec                 eax
            //   668905????????       |                     

        $sequence_15 = { 33c9 660f1f440000 420fb6843968a21700 88840dc0280000 488d4901 84c0 }
            // n = 6, score = 100
            //   33c9                 | dec                 eax
            //   660f1f440000         | mov                 eax, edi
            //   420fb6843968a21700     | inc    ebp
            //   88840dc0280000       | xor                 ecx, ecx
            //   488d4901             | inc                 ecx
            //   84c0                 | mov                 eax, 0x1388

    condition:
        7 of them and filesize < 3244032
}
