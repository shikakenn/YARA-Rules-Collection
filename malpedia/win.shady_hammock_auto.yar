rule win_shady_hammock_auto {

    meta:
        id = "21g97lNzaTbdQUlshYMVdZ"
        fingerprint = "v1_sha256_fa878708757191f1b63841f4404f6fa30ea9e29c95ad0fe726f8dc83ae6686cd"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.shady_hammock."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shady_hammock"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 480f4de8 4c8bc5 e8???????? 498b07 482bdd }
            // n = 5, score = 200
            //   480f4de8             | test                eax, eax
            //   4c8bc5               | mov                 ecx, 0x18
            //   e8????????           |                     
            //   498b07               | dec                 esp
            //   482bdd               | lea                 eax, [0x18468]

        $sequence_1 = { ffc3 3b5f18 72d9 33c0 488b5c2450 }
            // n = 5, score = 200
            //   ffc3                 | dec                 esp
            //   3b5f18               | cmp                 eax, edi
            //   72d9                 | ja                  0x1b8c
            //   33c0                 | dec                 ecx
            //   488b5c2450           | mov                 ebx, eax

        $sequence_2 = { 3b5f18 72d9 33c0 488b5c2450 488b6c2458 488b742460 4883c420 }
            // n = 7, score = 200
            //   3b5f18               | cmp                 eax, 1
            //   72d9                 | jne                 0x1d6
            //   33c0                 | dec                 eax
            //   488b5c2450           | lea                 eax, [0x29e6e]
            //   488b6c2458           | je                  0x1ec
            //   488b742460           | dec                 eax
            //   4883c420             | mov                 eax, dword ptr [ebx]

        $sequence_3 = { 48d1e9 482bc1 4c3bf8 77e3 }
            // n = 4, score = 200
            //   48d1e9               | dec                 eax
            //   482bc1               | mov                 ecx, ebx
            //   4c3bf8               | dec                 eax
            //   77e3                 | mov                 dword ptr [ebp - 0x51], eax

        $sequence_4 = { 4c0f45452f 498b02 488d4d27 48894c2438 488d4d18 }
            // n = 5, score = 200
            //   4c0f45452f           | ja                  0x1d92
            //   498b02               | jmp                 0x1c75
            //   488d4d27             | call                dword ptr [eax + 0x30]
            //   48894c2438           | dec                 eax
            //   488d4d18             | add                 eax, -8

        $sequence_5 = { 488d4101 488903 8b4314 488b0b c1e80c a801 }
            // n = 6, score = 200
            //   488d4101             | dec                 eax
            //   488903               | mov                 ebp, ecx
            //   8b4314               | dec                 esp
            //   488b0b               | lea                 eax, [0x18297]
            //   c1e80c               | inc                 ecx
            //   a801                 | mov                 ebx, ecx

        $sequence_6 = { 4803d1 eb03 0fb7d1 498bce ff15???????? }
            // n = 5, score = 200
            //   4803d1               | lea                 edx, [0x17d62]
            //   eb03                 | mov                 ecx, 1
            //   0fb7d1               | dec                 esp
            //   498bce               | lea                 eax, [0x17e89]
            //   ff15????????         |                     

        $sequence_7 = { 488bc6 488bd9 482bc2 493bc0 4c0f42c8 4883791810 488bc1 }
            // n = 7, score = 200
            //   488bc6               | movups              xmm1, xmmword ptr [ecx + 0x50]
            //   488bd9               | movups              xmmword ptr [ebp - 0x19], xmm1
            //   482bc2               | movups              xmmword ptr [ebp + 0x17], xmm0
            //   493bc0               | dec                 eax
            //   4c0f42c8             | mov                 dword ptr [ebp + 0x27], eax
            //   4883791810           | mov                 byte ptr [ebp + 0x2f], al
            //   488bc1               | movups              xmm0, xmmword ptr [ecx + 0x40]

        $sequence_8 = { 7413 4c8bc3 ba01000000 498bcf e8???????? }
            // n = 5, score = 200
            //   7413                 | lea                 eax, [0x24b04]
            //   4c8bc3               | and                 edx, 0x3f
            //   ba01000000           | dec                 eax
            //   498bcf               | mov                 edx, ecx
            //   e8????????           |                     

        $sequence_9 = { 66ffc6 663b7706 72cf 488bd7 }
            // n = 4, score = 200
            //   66ffc6               | dec                 eax
            //   663b7706             | cmove               ebx, eax
            //   72cf                 | mov                 edx, 1
            //   488bd7               | dec                 eax

    condition:
        7 of them and filesize < 635904
}
