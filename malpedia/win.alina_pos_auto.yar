rule win_alina_pos_auto {

    meta:
        id = "5Ymq0MHhVNxl1G4EkzIBMM"
        fingerprint = "v1_sha256_1bc8cb28e44f1be9219bfc61a255da516796bfdb3e5bfff9005b27db534f7774"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.alina_pos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alina_pos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7439 6828010000 8d85d0feffff 6a00 50 e8???????? 83c40c }
            // n = 7, score = 2400
            //   7439                 | je                  0x3b
            //   6828010000           | push                0x128
            //   8d85d0feffff         | lea                 eax, [ebp - 0x130]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { 2bc8 51 03fe 03f8 }
            // n = 4, score = 2000
            //   2bc8                 | sub                 ecx, eax
            //   51                   | push                ecx
            //   03fe                 | add                 edi, esi
            //   03f8                 | add                 edi, eax

        $sequence_2 = { 39410c 7305 8b4908 eb04 8bd1 8b09 }
            // n = 6, score = 2000
            //   39410c               | cmp                 dword ptr [ecx + 0xc], eax
            //   7305                 | jae                 7
            //   8b4908               | mov                 ecx, dword ptr [ecx + 8]
            //   eb04                 | jmp                 6
            //   8bd1                 | mov                 edx, ecx
            //   8b09                 | mov                 ecx, dword ptr [ecx]

        $sequence_3 = { 3975e8 720c 8b45d4 50 e8???????? 83c404 32c0 }
            // n = 7, score = 2000
            //   3975e8               | cmp                 dword ptr [ebp - 0x18], esi
            //   720c                 | jb                  0xe
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   32c0                 | xor                 al, al

        $sequence_4 = { 53 ff15???????? 85c0 75cd 56 e8???????? }
            // n = 6, score = 2000
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   75cd                 | jne                 0xffffffcf
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_5 = { 3bc1 7763 83ceff 3bc8 }
            // n = 4, score = 2000
            //   3bc1                 | cmp                 eax, ecx
            //   7763                 | ja                  0x65
            //   83ceff               | or                  esi, 0xffffffff
            //   3bc8                 | cmp                 ecx, eax

        $sequence_6 = { 8bd1 2bd0 83faff 7306 8bf2 85f6 }
            // n = 6, score = 2000
            //   8bd1                 | mov                 edx, ecx
            //   2bd0                 | sub                 edx, eax
            //   83faff               | cmp                 edx, -1
            //   7306                 | jae                 8
            //   8bf2                 | mov                 esi, edx
            //   85f6                 | test                esi, esi

        $sequence_7 = { 03fe 03f8 03d0 57 52 }
            // n = 5, score = 2000
            //   03fe                 | add                 edi, esi
            //   03f8                 | add                 edi, eax
            //   03d0                 | add                 edx, eax
            //   57                   | push                edi
            //   52                   | push                edx

        $sequence_8 = { 8a0e 8845c8 884dd4 7562 8d7ddc 8bc3 e8???????? }
            // n = 7, score = 1800
            //   8a0e                 | mov                 cl, byte ptr [esi]
            //   8845c8               | mov                 byte ptr [ebp - 0x38], al
            //   884dd4               | mov                 byte ptr [ebp - 0x2c], cl
            //   7562                 | jne                 0x64
            //   8d7ddc               | lea                 edi, [ebp - 0x24]
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_9 = { 8d85f0feffff 50 6805010000 ff15???????? }
            // n = 4, score = 1600
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   50                   | push                eax
            //   6805010000           | push                0x105
            //   ff15????????         |                     

        $sequence_10 = { 6800000080 50 ff15???????? 85c0 }
            // n = 4, score = 1600
            //   6800000080           | push                0x80000000
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_11 = { 8bf0 8d45ec 50 6800040000 }
            // n = 4, score = 1400
            //   8bf0                 | mov                 esi, eax
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   6800040000           | push                0x400

        $sequence_12 = { 85c9 7406 c70100000000 6a00 6a00 6a00 }
            // n = 6, score = 1400
            //   85c9                 | test                ecx, ecx
            //   7406                 | je                  8
            //   c70100000000         | mov                 dword ptr [ecx], 0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_13 = { ff15???????? 50 6a73 68???????? }
            // n = 4, score = 1400
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a73                 | push                0x73
            //   68????????           |                     

        $sequence_14 = { 8b45ec 85c0 7464 03f8 }
            // n = 4, score = 1400
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   85c0                 | test                eax, eax
            //   7464                 | je                  0x66
            //   03f8                 | add                 edi, eax

        $sequence_15 = { 6a13 53 c645f000 c745d00a000000 }
            // n = 4, score = 1400
            //   6a13                 | push                0x13
            //   53                   | push                ebx
            //   c645f000             | mov                 byte ptr [ebp - 0x10], 0
            //   c745d00a000000       | mov                 dword ptr [ebp - 0x30], 0xa

        $sequence_16 = { ff15???????? 50 6a70 68???????? }
            // n = 4, score = 1400
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a70                 | push                0x70
            //   68????????           |                     

        $sequence_17 = { ff15???????? 85c0 0f95c0 eb02 b001 }
            // n = 5, score = 1300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f95c0               | setne               al
            //   eb02                 | jmp                 4
            //   b001                 | mov                 al, 1

        $sequence_18 = { 64a300000000 6800100000 e8???????? 8b5d08 }
            // n = 4, score = 1200
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   6800100000           | push                0x1000
            //   e8????????           |                     
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]

        $sequence_19 = { ff15???????? 50 6a5f 68???????? }
            // n = 4, score = 1200
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a5f                 | push                0x5f
            //   68????????           |                     

        $sequence_20 = { 6810270000 ff15???????? 6a00 6a0f }
            // n = 4, score = 1200
            //   6810270000           | push                0x2710
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a0f                 | push                0xf

        $sequence_21 = { e8???????? 83c418 6860ea0000 ff15???????? }
            // n = 4, score = 1000
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   6860ea0000           | push                0xea60
            //   ff15????????         |                     

        $sequence_22 = { 6a00 6800000080 6a00 6a00 68???????? 68???????? 68???????? }
            // n = 7, score = 1000
            //   6a00                 | push                0
            //   6800000080           | push                0x80000000
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   68????????           |                     
            //   68????????           |                     

        $sequence_23 = { 83c418 e8???????? 8b3d???????? 8bf0 }
            // n = 4, score = 1000
            //   83c418               | add                 esp, 0x18
            //   e8????????           |                     
            //   8b3d????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_24 = { 8d4720 50 ff15???????? 8b4718 }
            // n = 4, score = 1000
            //   8d4720               | lea                 eax, [edi + 0x20]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4718               | mov                 eax, dword ptr [edi + 0x18]

        $sequence_25 = { 57 6800040000 52 8d85fcfbffff }
            // n = 4, score = 800
            //   57                   | push                edi
            //   6800040000           | push                0x400
            //   52                   | push                edx
            //   8d85fcfbffff         | lea                 eax, [ebp - 0x404]

        $sequence_26 = { 85f6 743e 83feff 7439 }
            // n = 4, score = 800
            //   85f6                 | test                esi, esi
            //   743e                 | je                  0x40
            //   83feff               | cmp                 esi, -1
            //   7439                 | je                  0x3b

        $sequence_27 = { d1e8 352083b8ed eb02 d1e8 8901 }
            // n = 5, score = 700
            //   d1e8                 | shr                 eax, 1
            //   352083b8ed           | xor                 eax, 0xedb88320
            //   eb02                 | jmp                 4
            //   d1e8                 | shr                 eax, 1
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_28 = { c7850cffffff00000000 8b450c 50 8d4dd8 51 }
            // n = 5, score = 600
            //   c7850cffffff00000000     | mov    dword ptr [ebp - 0xf4], 0
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   51                   | push                ecx

        $sequence_29 = { 81ec1c010000 53 56 57 51 }
            // n = 5, score = 600
            //   81ec1c010000         | sub                 esp, 0x11c
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   51                   | push                ecx

        $sequence_30 = { 83e004 0f8412000000 83a50cfffffffb 8d8de4feffff e9???????? }
            // n = 5, score = 600
            //   83e004               | and                 eax, 4
            //   0f8412000000         | je                  0x18
            //   83a50cfffffffb       | and                 dword ptr [ebp - 0xf4], 0xfffffffb
            //   8d8de4feffff         | lea                 ecx, [ebp - 0x11c]
            //   e9????????           |                     

        $sequence_31 = { b947000000 b8cccccccc f3ab 59 }
            // n = 4, score = 600
            //   b947000000           | mov                 ecx, 0x47
            //   b8cccccccc           | mov                 eax, 0xcccccccc
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   59                   | pop                 ecx

        $sequence_32 = { 8b45e8 8b7018 d1ee 8b4de8 e8???????? }
            // n = 5, score = 600
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8b7018               | mov                 esi, dword ptr [eax + 0x18]
            //   d1ee                 | shr                 esi, 1
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   e8????????           |                     

        $sequence_33 = { 8b4508 8945dc eb52 8b45dc 33d2 }
            // n = 5, score = 600
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   eb52                 | jmp                 0x54
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   33d2                 | xor                 edx, edx

        $sequence_34 = { 56 57 8dbdc8fcffff b9cb000000 }
            // n = 4, score = 600
            //   56                   | jmp                 0x1f
            //   57                   | dec                 eax
            //   8dbdc8fcffff         | lea                 eax, [0x21d97]
            //   b9cb000000           | dec                 eax

        $sequence_35 = { e9???????? c3 8b542408 8d420c 8b8a94feffff 33c8 }
            // n = 6, score = 600
            //   e9????????           |                     
            //   c3                   | ret                 
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   8d420c               | lea                 eax, [edx + 0xc]
            //   8b8a94feffff         | mov                 ecx, dword ptr [edx - 0x16c]
            //   33c8                 | xor                 ecx, eax

        $sequence_36 = { e8???????? 488d154f270200 488d4c2420 e8???????? cc 48895c2410 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   488d154f270200       | dec                 eax
            //   488d4c2420           | mov                 ecx, 0x80000001
            //   e8????????           |                     
            //   cc                   | push                esi
            //   48895c2410           | push                edi

        $sequence_37 = { 4533c9 c74424283f000f00 4533c0 894c2420 48c7c101000080 ff15???????? }
            // n = 6, score = 100
            //   4533c9               | mov                 ecx, dword ptr [edi + esi*8 + 0x2e870]
            //   c74424283f000f00     | dec                 eax
            //   4533c0               | or                  edi, 0xffffffff
            //   894c2420             | inc                 ecx
            //   48c7c101000080       | mov                 eax, edx
            //   ff15????????         |                     

        $sequence_38 = { 56 57 4156 4883ec40 48c7442438feffffff 48895c2468 48896c2470 }
            // n = 7, score = 100
            //   56                   | dec                 ecx
            //   57                   | mov                 edx, edx
            //   4156                 | dec                 eax
            //   4883ec40             | xor                 edx, ecx
            //   48c7442438feffffff     | inc    ebp
            //   48895c2468           | xor                 ecx, ecx
            //   48896c2470           | mov                 dword ptr [esp + 0x28], 0xf003f

        $sequence_39 = { 4c8bea 4b8b8cf770e80200 4c8b15???????? 4883cfff 418bc2 498bd2 4833d1 }
            // n = 7, score = 100
            //   4c8bea               | lea                 eax, [0x24b84]
            //   4b8b8cf770e80200     | dec                 eax
            //   4c8b15????????       |                     
            //   4883cfff             | lea                 ecx, [esp + 0x28]
            //   418bc2               | dec                 esp
            //   498bd2               | mov                 ebp, edx
            //   4833d1               | dec                 ebx

        $sequence_40 = { ba7c000000 41b901000000 4c8d05844b0200 488d4c2428 e8???????? }
            // n = 5, score = 100
            //   ba7c000000           | mov                 edx, 0x7c
            //   41b901000000         | inc                 ecx
            //   4c8d05844b0200       | mov                 ecx, 1
            //   488d4c2428           | dec                 esp
            //   e8????????           |                     

        $sequence_41 = { 4883ec20 8b1d???????? eb1d 488d05971d0200 }
            // n = 4, score = 100
            //   4883ec20             | inc                 ebp
            //   8b1d????????         |                     
            //   eb1d                 | xor                 eax, eax
            //   488d05971d0200       | mov                 dword ptr [esp + 0x20], ecx

    condition:
        7 of them and filesize < 2498560
}
