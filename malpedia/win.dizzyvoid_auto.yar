rule win_dizzyvoid_auto {

    meta:
        id = "Q4Nzmgzs4gBFNUJFshMbV"
        fingerprint = "v1_sha256_8385659a773378b82a70cc8941b67dcf8ffad28a19525f1f78e990eee9f0fdc1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.dizzyvoid."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dizzyvoid"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 488d4590 4533c0 4889442440 33d2 }
            // n = 4, score = 400
            //   488d4590             | call                dword ptr [edi + 0x58]
            //   4533c0               | dec                 eax
            //   4889442440           | mov                 ecx, ebx
            //   33d2                 | mov                 dword ptr [esp + 0x20], 4

        $sequence_1 = { 4903d1 48c1fa07 488bc2 48c1e83f }
            // n = 4, score = 400
            //   4903d1               | dec                 ecx
            //   48c1fa07             | add                 edx, ecx
            //   488bc2               | dec                 eax
            //   48c1e83f             | sar                 edx, 7

        $sequence_2 = { 48895c2420 4883ceff 448bce 33d2 }
            // n = 4, score = 400
            //   48895c2420           | dec                 esp
            //   4883ceff             | mov                 dword ptr [esp + 0x38], ebp
            //   448bce               | dec                 eax
            //   33d2                 | lea                 eax, [ebp - 0x70]

        $sequence_3 = { 498bc8 48c1e902 418bc1 48c1e802 }
            // n = 4, score = 400
            //   498bc8               | inc                 ecx
            //   48c1e902             | mov                 eax, 0x1006
            //   418bc1               | dec                 eax
            //   48c1e802             | mov                 ebp, eax

        $sequence_4 = { 4889442428 c7442420c0040000 4c8d8de0000000 41b808000000 }
            // n = 4, score = 400
            //   4889442428           | dec                 esp
            //   c7442420c0040000     | mov                 dword ptr [esp + 0x38], ebp
            //   4c8d8de0000000       | dec                 esp
            //   41b808000000         | mov                 dword ptr [esp + 0x30], ebp

        $sequence_5 = { 488bcb c744242004000000 41b806100000 488be8 ff5758 }
            // n = 5, score = 400
            //   488bcb               | shr                 eax, 0x3f
            //   c744242004000000     | dec                 eax
            //   41b806100000         | add                 edx, eax
            //   488be8               | dec                 ecx
            //   ff5758               | add                 edx, ecx

        $sequence_6 = { 44897c2428 48896c2420 448bce 4d8bc6 }
            // n = 4, score = 400
            //   44897c2428           | inc                 ecx
            //   48896c2420           | mov                 eax, 0x1006
            //   448bce               | dec                 eax
            //   4d8bc6               | mov                 ebp, eax

        $sequence_7 = { 448bc6 33d2 b92b040000 ff9358010000 }
            // n = 4, score = 400
            //   448bc6               | inc                 ecx
            //   33d2                 | mov                 eax, ecx
            //   b92b040000           | dec                 eax
            //   ff9358010000         | shr                 eax, 2

        $sequence_8 = { 85c0 7524 a1???????? a3???????? a1???????? c705????????2a134100 }
            // n = 6, score = 200
            //   85c0                 | mov                 eax, esi
            //   7524                 | xor                 edx, edx
            //   a1????????           |                     
            //   a3????????           |                     
            //   a1????????           |                     
            //   c705????????2a134100     |     

        $sequence_9 = { 8d85a8fcffff 50 8b8d90fcffff 51 e8???????? 83c40c }
            // n = 6, score = 200
            //   8d85a8fcffff         | xor                 edx, edx
            //   50                   | dec                 esp
            //   8b8d90fcffff         | mov                 dword ptr [esp + 0x38], ebp
            //   51                   | dec                 esp
            //   e8????????           |                     
            //   83c40c               | mov                 dword ptr [esp + 0x30], ebp

        $sequence_10 = { 83c40c 8bf4 ff9590fcffff 3bf4 }
            // n = 4, score = 200
            //   83c40c               | mov                 ecx, 0x42b
            //   8bf4                 | call                dword ptr [ebx + 0x158]
            //   ff9590fcffff         | inc                 esp
            //   3bf4                 | mov                 eax, esi

        $sequence_11 = { 8b4dfc 33cd e8???????? 81c434040000 3bec e8???????? 8be5 }
            // n = 7, score = 200
            //   8b4dfc               | xor                 ecx, ecx
            //   33cd                 | inc                 ebp
            //   e8????????           |                     
            //   81c434040000         | xor                 eax, eax
            //   3bec                 | dec                 eax
            //   e8????????           |                     
            //   8be5                 | mov                 dword ptr [esp + 0x40], eax

        $sequence_12 = { ff9590fcffff 3bf4 e8???????? 33c0 52 8bcd 50 }
            // n = 7, score = 200
            //   ff9590fcffff         | dec                 esp
            //   3bf4                 | mov                 dword ptr [esp + 0x30], ebp
            //   e8????????           |                     
            //   33c0                 | inc                 ebp
            //   52                   | xor                 eax, eax
            //   8bcd                 | dec                 eax
            //   50                   | mov                 dword ptr [esp + 0x40], eax

        $sequence_13 = { 56 57 8dbdccfbffff b90d010000 }
            // n = 4, score = 200
            //   56                   | xor                 edx, edx
            //   57                   | inc                 esp
            //   8dbdccfbffff         | mov                 eax, esi
            //   b90d010000           | xor                 edx, edx

        $sequence_14 = { a1???????? 33c5 8945fc b9d3000000 be???????? 8dbda8fcffff }
            // n = 6, score = 200
            //   a1????????           |                     
            //   33c5                 | mov                 dword ptr [esp + 0x20], ebp
            //   8945fc               | inc                 esp
            //   b9d3000000           | mov                 ecx, esi
            //   be????????           |                     
            //   8dbda8fcffff         | dec                 ebp

        $sequence_15 = { b90d010000 b8cccccccc f3ab a1???????? 33c5 }
            // n = 5, score = 200
            //   b90d010000           | test                eax, eax
            //   b8cccccccc           | inc                 esp
            //   f3ab                 | mov                 dword ptr [esp + 0x28], edi
            //   a1????????           |                     
            //   33c5                 | dec                 eax

        $sequence_16 = { eb36 8b852ce5ffff 8b8d1ce5ffff 8b0485601c4100 }
            // n = 4, score = 100
            //   eb36                 | lea                 ecx, [ebp + 0xe0]
            //   8b852ce5ffff         | inc                 ecx
            //   8b8d1ce5ffff         | mov                 eax, 8
            //   8b0485601c4100       | inc                 esp

        $sequence_17 = { 6a00 50 6a00 6a00 ff15???????? 6aff 50 }
            // n = 7, score = 100
            //   6a00                 | xor                 edx, edx
            //   50                   | xor                 ecx, ecx
            //   6a00                 | dec                 eax
            //   6a00                 | mov                 dword ptr [esp + 0x20], ebx
            //   ff15????????         |                     
            //   6aff                 | dec                 eax
            //   50                   | or                  esi, 0xffffffff

        $sequence_18 = { c780acff400002000000 6a04 58 6bc000 8b0d???????? }
            // n = 5, score = 100
            //   c780acff400002000000     | dec    eax
            //   6a04                 | mov                 dword ptr [esp + 0x28], eax
            //   58                   | mov                 dword ptr [esp + 0x20], 0x4c0
            //   6bc000               | dec                 esp
            //   8b0d????????         |                     

        $sequence_19 = { 57 a1???????? 33c4 50 8d842478010000 64a300000000 6800100000 }
            // n = 7, score = 100
            //   57                   | mov                 eax, 0x3c67f724
            //   a1????????           |                     
            //   33c4                 | dec                 eax
            //   50                   | mov                 dword ptr [ebx + 0x168], eax
            //   8d842478010000       | inc                 ecx
            //   64a300000000         | mov                 eax, 0xe31ea7f2
            //   6800100000           | dec                 eax

        $sequence_20 = { 8365fc00 833cfd40f2400000 7515 68a00f0000 56 }
            // n = 5, score = 100
            //   8365fc00             | mov                 dword ptr [ebx + 0x170], eax
            //   833cfd40f2400000     | push                esi
            //   7515                 | push                edi
            //   68a00f0000           | lea                 edi, [ebp - 0x434]
            //   56                   | mov                 ecx, 0x10d

        $sequence_21 = { e9???????? 8365c800 c745cc8d314000 a1???????? }
            // n = 4, score = 100
            //   e9????????           |                     
            //   8365c800             | xor                 ecx, ecx
            //   c745cc8d314000       | inc                 ecx
            //   a1????????           |                     

        $sequence_22 = { 8d85f0ebffff 03c1 8b8d1ce5ffff 50 8b852ce5ffff 8b0485601c4100 }
            // n = 6, score = 100
            //   8d85f0ebffff         | inc                 esp
            //   03c1                 | mov                 ecx, esi
            //   8b8d1ce5ffff         | xor                 edx, edx
            //   50                   | xor                 ecx, ecx
            //   8b852ce5ffff         | dec                 esp
            //   8b0485601c4100       | arpl                ax, di

        $sequence_23 = { 47 88440e34 8b049d601c4100 c744063801000000 }
            // n = 4, score = 100
            //   47                   | mov                 dword ptr [esp + 0x28], edi
            //   88440e34             | dec                 eax
            //   8b049d601c4100       | mov                 dword ptr [esp + 0x20], ebp
            //   c744063801000000     | inc                 esp

    condition:
        7 of them and filesize < 479232
}
