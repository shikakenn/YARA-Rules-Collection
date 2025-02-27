rule win_emotet_auto {

    meta:
        id = "1Xx3wn6YAe854kxLYN3f2V"
        fingerprint = "v1_sha256_833ebe5d59874650225701086c74088b08c5f926b449dc8bc3e0d02e1708d1c4"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.emotet."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8a01 3c30 7c04 3c39 7e13 3c61 7c04 }
            // n = 7, score = 2900
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   3c30                 | cmp                 al, 0x30
            //   7c04                 | jl                  6
            //   3c39                 | cmp                 al, 0x39
            //   7e13                 | jle                 0x15
            //   3c61                 | cmp                 al, 0x61
            //   7c04                 | jl                  6

        $sequence_1 = { 7e0b 3c41 7c04 3c5a 7e03 c60158 }
            // n = 6, score = 2900
            //   7e0b                 | jle                 0xd
            //   3c41                 | cmp                 al, 0x41
            //   7c04                 | jl                  6
            //   3c5a                 | cmp                 al, 0x5a
            //   7e03                 | jle                 5
            //   c60158               | mov                 byte ptr [ecx], 0x58

        $sequence_2 = { 7e13 3c61 7c04 3c7a 7e0b 3c41 }
            // n = 6, score = 2900
            //   7e13                 | jle                 0x15
            //   3c61                 | cmp                 al, 0x61
            //   7c04                 | jl                  6
            //   3c7a                 | cmp                 al, 0x7a
            //   7e0b                 | jle                 0xd
            //   3c41                 | cmp                 al, 0x41

        $sequence_3 = { 33c0 3903 5f 5e 0f95c0 5b 8be5 }
            // n = 7, score = 2400
            //   33c0                 | xor                 eax, eax
            //   3903                 | cmp                 dword ptr [ebx], eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   0f95c0               | setne               al
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_4 = { 3c5a 7e03 c60158 41 803900 75dd }
            // n = 6, score = 2400
            //   3c5a                 | cmp                 al, 0x5a
            //   7e03                 | jle                 5
            //   c60158               | mov                 byte ptr [ecx], 0x58
            //   41                   | inc                 ecx
            //   803900               | cmp                 byte ptr [ecx], 0
            //   75dd                 | jne                 0xffffffdf

        $sequence_5 = { 83c020 eb03 0fb7c0 69d23f000100 }
            // n = 4, score = 2300
            //   83c020               | add                 eax, 0x20
            //   eb03                 | jmp                 5
            //   0fb7c0               | movzx               eax, ax
            //   69d23f000100         | imul                edx, edx, 0x1003f

        $sequence_6 = { 8bc1 c1e808 8d5204 c1e910 8842fd 884afe c1e908 }
            // n = 7, score = 2100
            //   8bc1                 | cmp                 al, 0x41
            //   c1e808               | jl                  6
            //   8d5204               | cmp                 al, 0x5a
            //   c1e910               | jle                 9
            //   8842fd               | mov                 byte ptr [ecx], 0x58
            //   884afe               | inc                 ecx
            //   c1e908               | cmp                 al, 0x7a

        $sequence_7 = { 7416 6683385c 740a 83c002 }
            // n = 4, score = 2100
            //   7416                 | jl                  6
            //   6683385c             | cmp                 al, 0x39
            //   740a                 | jle                 0x17
            //   83c002               | cmp                 al, 0x61

        $sequence_8 = { 75f2 eb06 33c9 66894802 }
            // n = 4, score = 2100
            //   75f2                 | cmp                 al, 0x7a
            //   eb06                 | jle                 0x13
            //   33c9                 | cmp                 al, 0x7a
            //   66894802             | jle                 0xd

        $sequence_9 = { 8d5801 f6c30f 7406 83e3f0 }
            // n = 4, score = 2000
            //   8d5801               | lea                 ebx, [eax + 1]
            //   f6c30f               | test                bl, 0xf
            //   7406                 | je                  8
            //   83e3f0               | and                 ebx, 0xfffffff0

        $sequence_10 = { 0faf4510 50 6a08 ff15???????? }
            // n = 4, score = 1900
            //   0faf4510             | imul                eax, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   6a08                 | push                8
            //   ff15????????         |                     

        $sequence_11 = { 8b477c 85c0 7448 8b00 2b878c000000 }
            // n = 5, score = 1900
            //   8b477c               | push                1
            //   85c0                 | push                0
            //   7448                 | mov                 esi, dword ptr [eax + 0x20]
            //   8b00                 | mov                 edi, dword ptr [eax + 0x40]
            //   2b878c000000         | mov                 ebx, eax

        $sequence_12 = { 03c7 56 50 8b4774 03878c000000 50 ff15???????? }
            // n = 7, score = 1900
            //   03c7                 | add                 ebx, 0x3c
            //   56                   | xor                 esi, esi
            //   50                   | mov                 dword ptr [edx + 0xc], esi
            //   8b4774               | mov                 dword ptr [edx + 8], esi
            //   03878c000000         | mov                 dword ptr [edx + 4], esi
            //   50                   | xor                 ecx, ecx
            //   ff15????????         |                     

        $sequence_13 = { 83c40c 8b4d0c 8bc2 0bc1 }
            // n = 4, score = 1900
            //   83c40c               | mov                 edx, esp
            //   8b4d0c               | xor                 esi, esi
            //   8bc2                 | mov                 dword ptr [edx + 0xc], esi
            //   0bc1                 | mov                 dword ptr [edx + 8], esi

        $sequence_14 = { 03878c000000 50 ff15???????? 017758 83c40c 29775c }
            // n = 6, score = 1900
            //   03878c000000         | xor                 esi, esi
            //   50                   | push                esi
            //   ff15????????         |                     
            //   017758               | push                esi
            //   83c40c               | push                eax
            //   29775c               | push                0

        $sequence_15 = { 8b780c 8bd9 83c70c 8b37 }
            // n = 4, score = 1900
            //   8b780c               | jl                  8
            //   8bd9                 | cmp                 al, 0x7a
            //   83c70c               | mov                 al, byte ptr [ecx]
            //   8b37                 | cmp                 al, 0x30

        $sequence_16 = { 8b4604 8b16 8945fc 8d45f8 6a04 50 }
            // n = 6, score = 1900
            //   8b4604               | push                0
            //   8b16                 | push                dword ptr [ebp - 4]
            //   8945fc               | push                0x400
            //   8d45f8               | push                0
            //   6a04                 | push                dword ptr [ebp - 4]
            //   50                   | push                0x400

        $sequence_17 = { 81ca00000020 50 52 51 }
            // n = 4, score = 1800
            //   81ca00000020         | cmp                 al, 0x61
            //   50                   | jl                  0xa
            //   52                   | cmp                 al, 0x7a
            //   51                   | jle                 0x15

        $sequence_18 = { c745fc04000000 50 8d45f8 81ca00000020 50 }
            // n = 5, score = 1800
            //   c745fc04000000       | cmp                 al, 0x39
            //   50                   | jle                 0x19
            //   8d45f8               | cmp                 al, 0x61
            //   81ca00000020         | jl                  0xe
            //   50                   | cmp                 al, 0x7a

        $sequence_19 = { 483bd8 730b 488bcb e8???????? 488bd8 }
            // n = 5, score = 1700
            //   483bd8               | mov                 byte ptr [eax - 3], al
            //   730b                 | movzx               eax, cx
            //   488bcb               | shr                 ecx, 0x10
            //   e8????????           |                     
            //   488bd8               | shr                 ax, 8

        $sequence_20 = { 66c1e908 418848ff 4d3bd9 72cf }
            // n = 4, score = 1700
            //   66c1e908             | dec                 ebp
            //   418848ff             | lea                 eax, [eax + 4]
            //   4d3bd9               | inc                 ecx
            //   72cf                 | mov                 byte ptr [eax - 3], al

        $sequence_21 = { 48895010 4c894018 4c894820 c3 }
            // n = 4, score = 1700
            //   48895010             | mov                 dword ptr [ebp + 0x20], ecx
            //   4c894018             | dec                 ebp
            //   4c894820             | lea                 eax, [eax + 4]
            //   c3                   | inc                 ecx

        $sequence_22 = { 2bca d1e9 03ca c1e906 894d20 }
            // n = 5, score = 1700
            //   2bca                 | inc                 ecx
            //   d1e9                 | mov                 byte ptr [eax - 2], cl
            //   03ca                 | shr                 cx, 8
            //   c1e906               | movzx               eax, cx
            //   894d20               | shr                 ecx, 0x10

        $sequence_23 = { 488bd3 488bcf 488b5c2460 4883c450 }
            // n = 4, score = 1700
            //   488bd3               | sub                 ecx, edx
            //   488bcf               | shr                 ecx, 1
            //   488b5c2460           | add                 ecx, edx
            //   4883c450             | shr                 ecx, 6

        $sequence_24 = { 0fb7c1 c1e910 66c1e808 4d8d4004 418840fd 418848fe }
            // n = 6, score = 1700
            //   0fb7c1               | movzx               eax, cx
            //   c1e910               | shr                 ecx, 0x10
            //   66c1e808             | shr                 ax, 8
            //   4d8d4004             | dec                 ebp
            //   418840fd             | lea                 eax, [eax + 4]
            //   418848fe             | inc                 ecx

        $sequence_25 = { 418bd0 d3e2 418bcb d3e0 03d0 }
            // n = 5, score = 1700
            //   418bd0               | sub                 ecx, edx
            //   d3e2                 | shr                 ecx, 1
            //   418bcb               | add                 ecx, edx
            //   d3e0                 | shr                 ecx, 6
            //   03d0                 | mov                 dword ptr [ebp + 0x6f], ecx

        $sequence_26 = { d3e7 83f841 7208 83f85a }
            // n = 4, score = 1700
            //   d3e7                 | jle                 9
            //   83f841               | mov                 byte ptr [ecx], 0x58
            //   7208                 | inc                 ecx
            //   83f85a               | jle                 0x15

        $sequence_27 = { 4c8bdc 49895b08 49896b10 49897318 49897b20 4156 4883ec70 }
            // n = 7, score = 1700
            //   4c8bdc               | lea                 eax, [eax + 4]
            //   49895b08             | inc                 ecx
            //   49896b10             | mov                 byte ptr [eax - 3], al
            //   49897318             | inc                 ecx
            //   49897b20             | mov                 byte ptr [eax - 2], cl
            //   4156                 | shr                 cx, 8
            //   4883ec70             | dec                 esp

        $sequence_28 = { c1e807 46 83f87f 77f7 }
            // n = 4, score = 1600
            //   c1e807               | add                 esp, 0x50
            //   46                   | dec                 eax
            //   83f87f               | mov                 dword ptr [eax + 0x10], edx
            //   77f7                 | dec                 esp

        $sequence_29 = { f7e1 b84fecc44e 2bca d1e9 }
            // n = 4, score = 1500
            //   f7e1                 | cmp                 al, 0x7a
            //   b84fecc44e           | cmp                 al, 0x30
            //   2bca                 | jl                  6
            //   d1e9                 | cmp                 al, 0x39

        $sequence_30 = { 84c0 75f2 eb03 c60100 }
            // n = 4, score = 1500
            //   84c0                 | shr                 ax, 8
            //   75f2                 | dec                 ebp
            //   eb03                 | lea                 eax, [eax + 4]
            //   c60100               | inc                 ecx

        $sequence_31 = { 83c104 894e04 8b00 85c0 }
            // n = 4, score = 1200
            //   83c104               | jl                  6
            //   894e04               | cmp                 al, 0x7a
            //   8b00                 | jle                 0xf
            //   85c0                 | cmp                 al, 0x41

        $sequence_32 = { 0fb6c0 668942fa c1e910 0fb6c1 }
            // n = 4, score = 1200
            //   0fb6c0               | jle                 5
            //   668942fa             | mov                 byte ptr [ecx], 0x58
            //   c1e910               | inc                 ecx
            //   0fb6c1               | cmp                 byte ptr [ecx], 0

        $sequence_33 = { 7907 83c107 3bf7 72e8 }
            // n = 4, score = 1200
            //   7907                 | inc                 ecx
            //   83c107               | mov                 byte ptr [eax - 1], cl
            //   3bf7                 | dec                 ebp
            //   72e8                 | cmp                 ebx, ecx

        $sequence_34 = { 56 57 6a1e 8d45e0 }
            // n = 4, score = 1100
            //   56                   | lea                 ecx, [ebp - 0x38]
            //   57                   | mov                 dword ptr [ebp - 0x38], eax
            //   6a1e                 | mov                 dword ptr [ebp - 0x2c], esi
            //   8d45e0               | mov                 dword ptr [ebp - 0x28], edx

        $sequence_35 = { 52 52 52 68???????? 52 }
            // n = 5, score = 1100
            //   52                   | inc                 ecx
            //   52                   | mov                 byte ptr [eax], cl
            //   52                   | movzx               eax, cx
            //   68????????           |                     
            //   52                   | shr                 ecx, 0x10

        $sequence_36 = { 83ec48 53 56 57 6a44 }
            // n = 5, score = 1100
            //   83ec48               | movzx               eax, ax
            //   53                   | imul                edx, edx, 0x1003f
            //   56                   | add                 eax, 0x20
            //   57                   | jmp                 8
            //   6a44                 | movzx               eax, ax

        $sequence_37 = { 83f87f 760d 8d642400 c1e807 }
            // n = 4, score = 1000
            //   83f87f               | shr                 ax, 8
            //   760d                 | dec                 ebp
            //   8d642400             | lea                 eax, [eax + 4]
            //   c1e807               | inc                 ecx

        $sequence_38 = { b901000000 83f87f 7609 c1e807 }
            // n = 4, score = 900
            //   b901000000           | cmp                 eax, 0x7f
            //   83f87f               | ja                  0xfffffffd
            //   7609                 | shr                 eax, 7
            //   c1e807               | inc                 ecx

        $sequence_39 = { 7609 c1e807 41 83f87f }
            // n = 4, score = 900
            //   7609                 | jmp                 0xa
            //   c1e807               | cmp                 byte ptr [ecx], 0
            //   41                   | je                  0xf
            //   83f87f               | dec                 eax

        $sequence_40 = { 6a00 6aff 50 51 ff15???????? }
            // n = 5, score = 800
            //   6a00                 | inc                 ebx
            //   6aff                 | cmp                 eax, 0x7f
            //   50                   | ja                  0xfffffffd
            //   51                   | jbe                 0xb
            //   ff15????????         |                     

        $sequence_41 = { 68400000f0 6a18 33f6 56 }
            // n = 4, score = 600
            //   68400000f0           | push                ebx
            //   6a18                 | push                eax
            //   33f6                 | push                ebx
            //   56                   | push                esi

        $sequence_42 = { 83ec08 56 68400000f0 6a18 }
            // n = 4, score = 600
            //   83ec08               | shr                 eax, 7
            //   56                   | inc                 ecx
            //   68400000f0           | cmp                 eax, 0x7f
            //   6a18                 | ja                  0xfffffffd

        $sequence_43 = { 6a00 ff75fc 6800040000 6a00 6a00 }
            // n = 5, score = 600
            //   6a00                 | inc                 edx
            //   ff75fc               | cmp                 eax, 0x7f
            //   6800040000           | ja                  0xfffffffc
            //   6a00                 | jns                 9
            //   6a00                 | add                 ecx, 7

        $sequence_44 = { 53 56 8bf1 bb00c34c84 }
            // n = 4, score = 600
            //   53                   | imul                edx, edx, 0x1003f
            //   56                   | lea                 ebx, [eax + 1]
            //   8bf1                 | test                bl, 0xf
            //   bb00c34c84           | je                  0x17

        $sequence_45 = { 50 56 6800800000 6a6a }
            // n = 4, score = 600
            //   50                   | shr                 eax, 7
            //   56                   | inc                 esi
            //   6800800000           | cmp                 eax, 0x7f
            //   6a6a                 | ja                  0xfffffffd

        $sequence_46 = { 31d2 f7f1 8b0d???????? 8a1c11 }
            // n = 4, score = 500
            //   31d2                 | add                 eax, 0x20
            //   f7f1                 | jmp                 5
            //   8b0d????????         |                     
            //   8a1c11               | movzx               eax, ax

        $sequence_47 = { 8d0492 89ca 29c2 89d0 }
            // n = 4, score = 500
            //   8d0492               | push                eax
            //   89ca                 | mov                 dword ptr [ebp - 0x34], ecx
            //   29c2                 | lea                 ecx, [ebp - 0x38]
            //   89d0                 | mov                 dword ptr [ebp - 0x38], eax

        $sequence_48 = { 01c1 8b55f4 8b0402 83f800 }
            // n = 4, score = 500
            //   01c1                 | add                 ebx, 0x10
            //   8b55f4               | mov                 edi, edx
            //   8b0402               | mov                 esi, ecx
            //   83f800               | mov                 edx, dword ptr [edi]

        $sequence_49 = { 6a03 6a00 6a00 ff7508 53 50 }
            // n = 6, score = 500
            //   6a03                 | add                 dword ptr [edi + 0x58], esi
            //   6a00                 | add                 esp, 0xc
            //   6a00                 | mov                 eax, dword ptr [edi + 0x74]
            //   ff7508               | add                 eax, dword ptr [edi + 0x8c]
            //   53                   | push                eax
            //   50                   | add                 dword ptr [edi + 0x58], esi

        $sequence_50 = { 8b466c 5f 5e 5b 8be5 5d }
            // n = 6, score = 500
            //   8b466c               | and                 ebx, 0xfffffff0
            //   5f                   | lea                 ebx, [eax + 1]
            //   5e                   | test                bl, 0xf
            //   5b                   | je                  0xe
            //   8be5                 | and                 ebx, 0xfffffff0
            //   5d                   | add                 ebx, 0x10

        $sequence_51 = { 8bf1 bb00c34c84 57 33ff }
            // n = 4, score = 500
            //   8bf1                 | cmp                 dword ptr [ebx], eax
            //   bb00c34c84           | pop                 edi
            //   57                   | pop                 esi
            //   33ff                 | setne               al

        $sequence_52 = { 01ca 89d6 83c604 8b7de0 8b4c0f04 83f900 }
            // n = 6, score = 500
            //   01ca                 | add                 esp, 0xc
            //   89d6                 | mov                 ecx, dword ptr [ebp + 0xc]
            //   83c604               | mov                 eax, edx
            //   8b7de0               | imul                eax, dword ptr [ebp + 0x10]
            //   8b4c0f04             | push                eax
            //   83f900               | push                8

        $sequence_53 = { 01ca 89d6 83c60c 8b7df4 8b4c0f0c }
            // n = 5, score = 500
            //   01ca                 | imul                edx, edx, 0x1003f
            //   89d6                 | movzx               eax, ax
            //   83c60c               | add                 eax, 0x20
            //   8b7df4               | jmp                 8
            //   8b4c0f0c             | movzx               eax, ax

        $sequence_54 = { 83ec10 53 6a00 8d45fc }
            // n = 4, score = 500
            //   83ec10               | mov                 eax, edx
            //   53                   | or                  eax, ecx
            //   6a00                 | add                 eax, dword ptr [edi + 0x8c]
            //   8d45fc               | push                eax

        $sequence_55 = { 8d4df8 51 ff75f8 50 6a03 6a30 }
            // n = 6, score = 500
            //   8d4df8               | inc                 ecx
            //   51                   | cmp                 eax, 0x7f
            //   ff75f8               | push                0
            //   50                   | push                -1
            //   6a03                 | push                eax
            //   6a30                 | push                ecx

        $sequence_56 = { 55 8bec 83ec08 56 57 8bf1 33ff }
            // n = 7, score = 500
            //   55                   | mov                 eax, dword ptr [edi + 0x7c]
            //   8bec                 | test                eax, eax
            //   83ec08               | je                  0x4a
            //   56                   | mov                 eax, dword ptr [eax]
            //   57                   | sub                 eax, dword ptr [edi + 0x8c]
            //   8bf1                 | add                 eax, edi
            //   33ff                 | push                esi

        $sequence_57 = { 8b7020 8b7840 89c3 83c33c }
            // n = 4, score = 300
            //   8b7020               | movzx               eax, ax
            //   8b7840               | imul                edx, edx, 0x1003f
            //   89c3                 | cmp                 ax, 0x5a
            //   83c33c               | ja                  0xa

        $sequence_58 = { 743e 8b5c2430 85db 741d }
            // n = 4, score = 200
            //   743e                 | inc                 ecx
            //   8b5c2430             | cmp                 eax, 0x7f
            //   85db                 | mov                 ecx, 1
            //   741d                 | cmp                 eax, 0x7f

        $sequence_59 = { 33d2 c605????????00 0fb6d8 e8???????? }
            // n = 4, score = 200
            //   33d2                 | ja                  0xfffffff9
            //   c605????????00       |                     
            //   0fb6d8               | mov                 ecx, 1
            //   e8????????           |                     

        $sequence_60 = { 8bf8 e8???????? eb04 8b7c2430 }
            // n = 4, score = 200
            //   8bf8                 | shr                 eax, 7
            //   e8????????           |                     
            //   eb04                 | inc                 ecx
            //   8b7c2430             | cmp                 eax, 0x7f

        $sequence_61 = { e8???????? 84c0 7519 33c9 0f1f4000 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   84c0                 | ja                  2
            //   7519                 | mov                 ecx, 1
            //   33c9                 | cmp                 eax, 0x7f
            //   0f1f4000             | jbe                 0xe

        $sequence_62 = { 31c9 89e2 31f6 89720c }
            // n = 4, score = 200
            //   31c9                 | ja                  0xfffffffd
            //   89e2                 | test                al, al
            //   31f6                 | jne                 0xfffffff4
            //   89720c               | jmp                 7

        $sequence_63 = { 31f6 89720c 897208 897204 }
            // n = 4, score = 200
            //   31f6                 | movzx               eax, ax
            //   89720c               | add                 eax, 0x20
            //   897208               | jmp                 0xd
            //   897204               | movzx               eax, ax

        $sequence_64 = { ff15???????? 83f803 7405 83f802 751e }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   83f803               | jbe                 0xb
            //   7405                 | shr                 eax, 7
            //   83f802               | inc                 ecx
            //   751e                 | cmp                 eax, 0x7f

        $sequence_65 = { e8???????? 488d1527400000 41b804010000 8b4850 890d???????? 33c9 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   488d1527400000       | cmp                 eax, 0x7f
            //   41b804010000         | jbe                 0xb
            //   8b4850               | shr                 eax, 7
            //   890d????????         |                     
            //   33c9                 | inc                 ecx

        $sequence_66 = { 83c310 89542454 894c2450 895c244c }
            // n = 4, score = 100
            //   83c310               | cmp                 esi, edi
            //   89542454             | jb                  0xffffffec
            //   894c2450             | push                edx
            //   895c244c             | push                edx

        $sequence_67 = { 8b1f 8bac2484000000 8b7d00 8b6c2478 01fd 89442438 8b442478 }
            // n = 7, score = 100
            //   8b1f                 | mov                 byte ptr [ecx], 0
            //   8bac2484000000       | shr                 eax, 7
            //   8b7d00               | inc                 edx
            //   8b6c2478             | cmp                 eax, 0x7f
            //   01fd                 | ja                  0xfffffffd
            //   89442438             | jns                 9
            //   8b442478             | add                 ecx, 7

        $sequence_68 = { 8d95fcfeffff 52 e8???????? 8db5fcfeffff }
            // n = 4, score = 100
            //   8d95fcfeffff         | xor                 ecx, ecx
            //   52                   | nop                 dword ptr [eax]
            //   e8????????           |                     
            //   8db5fcfeffff         | test                al, al

        $sequence_69 = { 488d15c6220000 488bcb ff15???????? 85c0 7528 }
            // n = 5, score = 100
            //   488d15c6220000       | mov                 ecx, 1
            //   488bcb               | cmp                 eax, 0x7f
            //   ff15????????         |                     
            //   85c0                 | jbe                 0xe
            //   7528                 | shr                 eax, 7

        $sequence_70 = { 5b c3 8b442408 8b0c850440d800 8b542410 }
            // n = 5, score = 100
            //   5b                   | cmp                 eax, 0x7f
            //   c3                   | ja                  7
            //   8b442408             | shr                 eax, 7
            //   8b0c850440d800       | inc                 ebx
            //   8b542410             | cmp                 eax, 0x7f

        $sequence_71 = { 48 895c2450 90 8b0f 48 8d15b71f0000 }
            // n = 6, score = 100
            //   48                   | cmp                 eax, 3
            //   895c2450             | je                  7
            //   90                   | cmp                 eax, 2
            //   8b0f                 | jne                 0x25
            //   48                   | test                al, al
            //   8d15b71f0000         | jne                 0x1b

        $sequence_72 = { 0f28ca f20f11942480000000 f20f114c2458 89442454 }
            // n = 4, score = 100
            //   0f28ca               | lea                 esp, [esp]
            //   f20f11942480000000     | shr    eax, 7
            //   f20f114c2458         | shr                 eax, 7
            //   89442454             | inc                 edi

        $sequence_73 = { 48 8d0d73440000 48 8bd3 48 83c440 }
            // n = 6, score = 100
            //   48                   | push                eax
            //   8d0d73440000         | push                ecx
            //   48                   | push                eax
            //   8bd3                 | push                0
            //   48                   | push                1
            //   83c440               | push                0

        $sequence_74 = { 83c101 8b542414 83c228 8b742468 }
            // n = 4, score = 100
            //   83c101               | push                edx
            //   8b542414             | push                edx
            //   83c228               | cmp                 eax, 0x7f
            //   8b742468             | jbe                 0x12

        $sequence_75 = { 0f84c0000000 488d542430 488bc8 4889742470 e8???????? 488bf0 }
            // n = 6, score = 100
            //   0f84c0000000         | ja                  0xfffffffd
            //   488d542430           | shr                 eax, 7
            //   488bc8               | inc                 ebx
            //   4889742470           | cmp                 eax, 0x7f
            //   e8????????           |                     
            //   488bf0               | ja                  0xfffffffd

    condition:
        7 of them and filesize < 733184
}
