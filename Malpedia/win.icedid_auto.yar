rule win_icedid_auto {

    meta:
        id = "4aNYS5I7aRv4hnwPiFkLp9"
        fingerprint = "v1_sha256_e8c9e17a917aa63cbf96d9c82905a16b279179aa1e4dde7e0caa78f60904db7b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.icedid."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 85ff 7418 c60700 47 57 ff15???????? }
            // n = 6, score = 1300
            //   85ff                 | test                edi, edi
            //   7418                 | je                  0x1a
            //   c60700               | mov                 byte ptr [edi], 0
            //   47                   | inc                 edi
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_1 = { 6905????????e8030000 50 ff35???????? ff15???????? }
            // n = 4, score = 1300
            //   6905????????e8030000     |     
            //   50                   | push                eax
            //   ff35????????         |                     
            //   ff15????????         |                     

        $sequence_2 = { 740c 50 ff15???????? 33c0 40 eb11 }
            // n = 6, score = 1300
            //   740c                 | je                  0xe
            //   50                   | push                eax
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   eb11                 | jmp                 0x13

        $sequence_3 = { ff15???????? 8bf7 8bc6 eb02 33c0 }
            // n = 5, score = 1300
            //   ff15????????         |                     
            //   8bf7                 | mov                 esi, edi
            //   8bc6                 | mov                 eax, esi
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 0fb605???????? 0fb60d???????? 50 0fb605???????? 50 0fb605???????? 50 }
            // n = 7, score = 1300
            //   0fb605????????       |                     
            //   0fb60d????????       |                     
            //   50                   | push                eax
            //   0fb605????????       |                     
            //   50                   | push                eax
            //   0fb605????????       |                     
            //   50                   | push                eax

        $sequence_5 = { 7413 ff36 6a08 ff15???????? 50 ff15???????? }
            // n = 6, score = 1300
            //   7413                 | je                  0x15
            //   ff36                 | push                dword ptr [esi]
            //   6a08                 | push                8
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_6 = { ff15???????? 85c0 7420 837c241000 }
            // n = 4, score = 1300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7420                 | je                  0x22
            //   837c241000           | cmp                 dword ptr [esp + 0x10], 0

        $sequence_7 = { 7427 6a3b 56 ff15???????? }
            // n = 4, score = 1300
            //   7427                 | je                  0x29
            //   6a3b                 | push                0x3b
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_8 = { e8???????? 8bf0 8d45fc 50 ff75fc 6a05 }
            // n = 6, score = 1000
            //   e8????????           |                     
            //   8bf0                 | push                edi
            //   8d45fc               | push                ebx
            //   50                   | not                 eax
            //   ff75fc               | and                 eax, dword ptr [ebp - 4]
            //   6a05                 | mov                 esp, ebp

        $sequence_9 = { 8b542414 0302 833800 759f }
            // n = 4, score = 800
            //   8b542414             | inc                 edi
            //   0302                 | add                 ebx, 2
            //   833800               | cmp                 edi, ebp
            //   759f                 | jb                  0xffffffcb

        $sequence_10 = { 47 83c302 3bfd 72c4 8b542414 0302 }
            // n = 6, score = 800
            //   47                   | add                 esp, 0x14
            //   83c302               | inc                 edi
            //   3bfd                 | cmp                 edi, dword ptr [eax + 0x20]
            //   72c4                 | jb                  0xffffffd7
            //   8b542414             | test                edx, edx
            //   0302                 | je                  0x56

        $sequence_11 = { 8b12 85d2 7454 8d6af8 d1ed 6a00 5f }
            // n = 7, score = 800
            //   8b12                 | and                 eax, dword ptr [ebp - 4]
            //   85d2                 | mov                 esp, ebp
            //   7454                 | pop                 ebp
            //   8d6af8               | ret                 
            //   d1ed                 | push                ebp
            //   6a00                 | not                 eax
            //   5f                   | and                 eax, dword ptr [ebp - 4]

        $sequence_12 = { 83c414 47 3b7820 72d1 }
            // n = 4, score = 800
            //   83c414               | mov                 edx, dword ptr [edx]
            //   47                   | test                edx, edx
            //   3b7820               | je                  0x58
            //   72d1                 | lea                 ebp, [edx - 8]

        $sequence_13 = { 3b7820 72d1 5b 33c0 40 5f }
            // n = 6, score = 800
            //   3b7820               | je                  0x56
            //   72d1                 | lea                 ebp, [edx - 8]
            //   5b                   | shr                 ebp, 1
            //   33c0                 | push                0
            //   40                   | shr                 ebp, 1
            //   5f                   | push                0

        $sequence_14 = { 0fb713 8954241c 66c16c241c0c 0fb7d2 }
            // n = 4, score = 800
            //   0fb713               | lea                 eax, [ebp - 4]
            //   8954241c             | push                eax
            //   66c16c241c0c         | push                dword ptr [ebp - 4]
            //   0fb7d2               | push                5

        $sequence_15 = { 8d4508 50 0fb6440b34 50 }
            // n = 4, score = 800
            //   8d4508               | mov                 esp, ebp
            //   50                   | pop                 ebp
            //   0fb6440b34           | ret                 
            //   50                   | push                ebp

        $sequence_16 = { a808 75f5 a804 7406 }
            // n = 4, score = 400
            //   a808                 | test                al, 8
            //   75f5                 | jne                 0xfffffff7
            //   a804                 | test                al, 4
            //   7406                 | je                  8

        $sequence_17 = { ff15???????? 85c0 750a b8010000c0 e9???????? }
            // n = 5, score = 400
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   b8010000c0           | mov                 eax, 0xc0000001
            //   e9????????           |                     

        $sequence_18 = { ff5010 85c0 7407 33c0 }
            // n = 4, score = 400
            //   ff5010               | call                dword ptr [eax + 0x10]
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   33c0                 | xor                 eax, eax

        $sequence_19 = { 85c9 7408 48 8b03 }
            // n = 4, score = 200
            //   85c9                 | test                ecx, ecx
            //   7408                 | je                  0xa
            //   48                   | dec                 eax
            //   8b03                 | mov                 eax, dword ptr [ebx]

        $sequence_20 = { ff15???????? 4d 85ff 7414 ff15???????? }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   4d                   | dec                 ebp
            //   85ff                 | test                edi, edi
            //   7414                 | je                  0x16
            //   ff15????????         |                     

        $sequence_21 = { 33c0 c74424200e000f00 4c 8d486b ff5018 85c0 7593 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   c74424200e000f00     | mov                 dword ptr [esp + 0x20], 0xf000e
            //   4c                   | dec                 esp
            //   8d486b               | lea                 ecx, [eax + 0x6b]
            //   ff5018               | call                dword ptr [eax + 0x18]
            //   85c0                 | test                eax, eax
            //   7593                 | jne                 0xffffff95

        $sequence_22 = { 8b442420 48 8b4c2428 8a09 }
            // n = 4, score = 200
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   48                   | dec                 eax
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   8a09                 | mov                 cl, byte ptr [ecx]

        $sequence_23 = { 8b44480c 8b0c48 48 034f10 48 035728 ff15???????? }
            // n = 7, score = 200
            //   8b44480c             | mov                 eax, dword ptr [eax + ecx*2 + 0xc]
            //   8b0c48               | mov                 ecx, dword ptr [eax + ecx*2]
            //   48                   | dec                 eax
            //   034f10               | add                 ecx, dword ptr [edi + 0x10]
            //   48                   | dec                 eax
            //   035728               | add                 edx, dword ptr [edi + 0x28]
            //   ff15????????         |                     

        $sequence_24 = { ff15???????? 488d5702 488bce ff15???????? }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   488d5702             | dec                 eax
            //   488bce               | lea                 edx, [edi + 2]
            //   ff15????????         |                     

        $sequence_25 = { 44334c2440 48897c2438 4885ff 746b }
            // n = 4, score = 100
            //   44334c2440           | dec                 eax
            //   48897c2438           | mov                 ecx, esi
            //   4885ff               | inc                 esp
            //   746b                 | xor                 ecx, dword ptr [esp + 0x40]

        $sequence_26 = { ff15???????? 8bf8 85c0 7409 8b4c2478 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   8bf8                 | dec                 eax
            //   85c0                 | sub                 esp, 0x40
            //   7409                 | xor                 edi, edi
            //   8b4c2478             | dec                 ebp

        $sequence_27 = { 7506 ff15???????? 80bb8000000040 0f8577ffffff }
            // n = 4, score = 100
            //   7506                 | xor                 edx, edx
            //   ff15????????         |                     
            //   80bb8000000040       | dec                 eax
            //   0f8577ffffff         | test                edi, edi

        $sequence_28 = { 7409 8b4c2478 493b0e 741e }
            // n = 4, score = 100
            //   7409                 | je                  0x1f
            //   8b4c2478             | jmp                 0xffffffa3
            //   493b0e               | dec                 eax
            //   741e                 | mov                 esi, dword ptr [ebp + 0x290]

        $sequence_29 = { 488bf0 4885c0 750d ff15???????? 33c0 e9???????? 8bd7 }
            // n = 7, score = 100
            //   488bf0               | dec                 eax
            //   4885c0               | mov                 esi, dword ptr [ebp + 0x290]
            //   750d                 | dec                 eax
            //   ff15????????         |                     
            //   33c0                 | mov                 edi, dword ptr [esp + 0x38]
            //   e9????????           |                     
            //   8bd7                 | xor                 ecx, ecx

        $sequence_30 = { 488bb590020000 488b7c2438 33c9 33d2 4885ff 7411 }
            // n = 6, score = 100
            //   488bb590020000       | mov                 edi, eax
            //   488b7c2438           | test                eax, eax
            //   33c9                 | je                  0xd
            //   33d2                 | mov                 ecx, dword ptr [esp + 0x78]
            //   4885ff               | test                eax, eax
            //   7411                 | je                  0xb

        $sequence_31 = { 4883ec40 33ff 4d8bf0 482178d8 4c8bfa }
            // n = 5, score = 100
            //   4883ec40             | dec                 eax
            //   33ff                 | mov                 dword ptr [esp + 0x38], edi
            //   4d8bf0               | dec                 eax
            //   482178d8             | test                edi, edi
            //   4c8bfa               | je                  0x75

    condition:
        7 of them and filesize < 303104
}
