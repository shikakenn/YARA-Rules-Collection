rule win_yty_auto {

    meta:
        id = "3BZPGjOgSBpeI1PGBnpM60"
        fingerprint = "v1_sha256_24d2496487d3e8a74d1838cfbb75ce014466580ad0212ac1fc21d0ad856e5f75"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.yty."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yty"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b45d8 83e001 0f840c000000 8365d8fe 8b7508 e9???????? c3 }
            // n = 7, score = 500
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   83e001               | and                 eax, 1
            //   0f840c000000         | je                  0x12
            //   8365d8fe             | and                 dword ptr [ebp - 0x28], 0xfffffffe
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   e9????????           |                     
            //   c3                   | ret                 

        $sequence_1 = { 8d45f4 64a300000000 8b7508 33ff 897dd8 }
            // n = 5, score = 500
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33ff                 | xor                 edi, edi
            //   897dd8               | mov                 dword ptr [ebp - 0x28], edi

        $sequence_2 = { 8a1402 2ad1 8bfe 80ea04 b901000000 e9???????? }
            // n = 6, score = 400
            //   8a1402               | mov                 dl, byte ptr [edx + eax]
            //   2ad1                 | sub                 dl, cl
            //   8bfe                 | mov                 edi, esi
            //   80ea04               | sub                 dl, 4
            //   b901000000           | mov                 ecx, 1
            //   e9????????           |                     

        $sequence_3 = { 7303 8d5508 8b4e10 397e14 7204 8b3e }
            // n = 6, score = 400
            //   7303                 | jae                 5
            //   8d5508               | lea                 edx, [ebp + 8]
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   397e14               | cmp                 dword ptr [esi + 0x14], edi
            //   7204                 | jb                  6
            //   8b3e                 | mov                 edi, dword ptr [esi]

        $sequence_4 = { 50 e8???????? 83c40c 8d8de8fdffff 51 53 }
            // n = 6, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d8de8fdffff         | lea                 ecx, [ebp - 0x218]
            //   51                   | push                ecx
            //   53                   | push                ebx

        $sequence_5 = { 52 50 8b410c ffd0 8d4f08 51 }
            // n = 6, score = 400
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b410c               | mov                 eax, dword ptr [ecx + 0xc]
            //   ffd0                 | call                eax
            //   8d4f08               | lea                 ecx, [edi + 8]
            //   51                   | push                ecx

        $sequence_6 = { 8bfe 80ea13 b902000000 e9???????? 8b5508 397d1c 7303 }
            // n = 7, score = 400
            //   8bfe                 | mov                 edi, esi
            //   80ea13               | sub                 dl, 0x13
            //   b902000000           | mov                 ecx, 2
            //   e9????????           |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   397d1c               | cmp                 dword ptr [ebp + 0x1c], edi
            //   7303                 | jae                 5

        $sequence_7 = { 8b35???????? 85c0 52 0f95c3 ffd6 }
            // n = 5, score = 400
            //   8b35????????         |                     
            //   85c0                 | test                eax, eax
            //   52                   | push                edx
            //   0f95c3               | setne               bl
            //   ffd6                 | call                esi

        $sequence_8 = { 50 ffd2 ff15???????? 8a857bffffff 8b4df4 }
            // n = 5, score = 400
            //   50                   | push                eax
            //   ffd2                 | call                edx
            //   ff15????????         |                     
            //   8a857bffffff         | mov                 al, byte ptr [ebp - 0x85]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_9 = { 8bfe 80ea04 b904000000 eb23 8b5508 397d1c 7303 }
            // n = 7, score = 400
            //   8bfe                 | mov                 edi, esi
            //   80ea04               | sub                 dl, 4
            //   b904000000           | mov                 ecx, 4
            //   eb23                 | jmp                 0x25
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   397d1c               | cmp                 dword ptr [ebp + 0x1c], edi
            //   7303                 | jae                 5

        $sequence_10 = { 8d8de8fdffff 51 53 53 6a28 53 ff15???????? }
            // n = 7, score = 400
            //   8d8de8fdffff         | lea                 ecx, [ebp - 0x218]
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   6a28                 | push                0x28
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_11 = { 807def00 8b5de8 7503 83cb02 8b16 }
            // n = 5, score = 400
            //   807def00             | cmp                 byte ptr [ebp - 0x11], 0
            //   8b5de8               | mov                 ebx, dword ptr [ebp - 0x18]
            //   7503                 | jne                 5
            //   83cb02               | or                  ebx, 2
            //   8b16                 | mov                 edx, dword ptr [esi]

        $sequence_12 = { 33c0 8945f0 8906 894604 894608 8945fc 56 }
            // n = 7, score = 400
            //   33c0                 | xor                 eax, eax
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8906                 | mov                 dword ptr [esi], eax
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi

        $sequence_13 = { 8975e0 85c9 7407 8b11 8b4204 }
            // n = 5, score = 400
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   85c9                 | test                ecx, ecx
            //   7407                 | je                  9
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]

        $sequence_14 = { 668910 8bc6 5b 8be5 5d c20400 }
            // n = 6, score = 400
            //   668910               | mov                 word ptr [eax], dx
            //   8bc6                 | mov                 eax, esi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4

        $sequence_15 = { 33db 895de8 885def 8975e0 }
            // n = 4, score = 400
            //   33db                 | xor                 ebx, ebx
            //   895de8               | mov                 dword ptr [ebp - 0x18], ebx
            //   885def               | mov                 byte ptr [ebp - 0x11], bl
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi

        $sequence_16 = { 397e14 7214 8a1402 8b3e 2ad1 80ea13 b902000000 }
            // n = 7, score = 400
            //   397e14               | cmp                 dword ptr [esi + 0x14], edi
            //   7214                 | jb                  0x16
            //   8a1402               | mov                 dl, byte ptr [edx + eax]
            //   8b3e                 | mov                 edi, dword ptr [esi]
            //   2ad1                 | sub                 dl, cl
            //   80ea13               | sub                 dl, 0x13
            //   b902000000           | mov                 ecx, 2

        $sequence_17 = { 80ea04 b901000000 e9???????? 8a1402 2ad1 8bfe }
            // n = 6, score = 400
            //   80ea04               | sub                 dl, 4
            //   b901000000           | mov                 ecx, 1
            //   e9????????           |                     
            //   8a1402               | mov                 dl, byte ptr [edx + eax]
            //   2ad1                 | sub                 dl, cl
            //   8bfe                 | mov                 edi, esi

        $sequence_18 = { 6a01 8bcf e8???????? 8b0e 8b5104 8b443238 c645ef01 }
            // n = 7, score = 400
            //   6a01                 | push                1
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   8b443238             | mov                 eax, dword ptr [edx + esi + 0x38]
            //   c645ef01             | mov                 byte ptr [ebp - 0x11], 1

        $sequence_19 = { 85d2 0f8425010000 83f904 0f8712010000 }
            // n = 4, score = 400
            //   85d2                 | test                edx, edx
            //   0f8425010000         | je                  0x12b
            //   83f904               | cmp                 ecx, 4
            //   0f8712010000         | ja                  0x118

        $sequence_20 = { 33c9 33c0 8d7910 85d2 }
            // n = 4, score = 400
            //   33c9                 | xor                 ecx, ecx
            //   33c0                 | xor                 eax, eax
            //   8d7910               | lea                 edi, [ecx + 0x10]
            //   85d2                 | test                edx, edx

        $sequence_21 = { 8b07 eb02 8bc7 8b4de0 }
            // n = 4, score = 300
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   eb02                 | jmp                 4
            //   8bc7                 | mov                 eax, edi
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]

        $sequence_22 = { 8ad1 c0ea02 8ac4 80e20f c0e004 }
            // n = 5, score = 300
            //   8ad1                 | mov                 dl, cl
            //   c0ea02               | shr                 dl, 2
            //   8ac4                 | mov                 al, ah
            //   80e20f               | and                 dl, 0xf
            //   c0e004               | shl                 al, 4

        $sequence_23 = { 8b4c1938 895dd4 85c9 7405 8b01 ff5004 c745fc00000000 }
            // n = 7, score = 200
            //   8b4c1938             | mov                 ecx, dword ptr [ecx + ebx + 0x38]
            //   895dd4               | mov                 dword ptr [ebp - 0x2c], ebx
            //   85c9                 | test                ecx, ecx
            //   7405                 | je                  7
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   ff5004               | call                dword ptr [eax + 4]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_24 = { e8???????? 83c420 3ac3 7459 8b9dc4f5ffff 39bdd8f5ffff }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20
            //   3ac3                 | cmp                 al, bl
            //   7459                 | je                  0x5b
            //   8b9dc4f5ffff         | mov                 ebx, dword ptr [ebp - 0xa3c]
            //   39bdd8f5ffff         | cmp                 dword ptr [ebp - 0xa28], edi

        $sequence_25 = { 83e908 8d7608 660fd60f 8d7f08 8b048d24f94000 ffe0 f7c703000000 }
            // n = 7, score = 100
            //   83e908               | sub                 ecx, 8
            //   8d7608               | lea                 esi, [esi + 8]
            //   660fd60f             | movq                qword ptr [edi], xmm1
            //   8d7f08               | lea                 edi, [edi + 8]
            //   8b048d24f94000       | mov                 eax, dword ptr [ecx*4 + 0x40f924]
            //   ffe0                 | jmp                 eax
            //   f7c703000000         | test                edi, 3

        $sequence_26 = { 8b4604 33c9 668908 8bce }
            // n = 4, score = 100
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   33c9                 | xor                 ecx, ecx
            //   668908               | mov                 word ptr [eax], cx
            //   8bce                 | mov                 ecx, esi

        $sequence_27 = { 3bf4 e8???????? 8bf4 8b4594 50 ff15???????? }
            // n = 6, score = 100
            //   3bf4                 | cmp                 esi, esp
            //   e8????????           |                     
            //   8bf4                 | mov                 esi, esp
            //   8b4594               | mov                 eax, dword ptr [ebp - 0x6c]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_28 = { 8bc7 33c9 668908 8b5d08 894dfc c745f001000000 }
            // n = 6, score = 100
            //   8bc7                 | mov                 eax, edi
            //   33c9                 | xor                 ecx, ecx
            //   668908               | mov                 word ptr [eax], cx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1

        $sequence_29 = { e8???????? 8945e8 8d45e8 50 8955ec e8???????? 8bf0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_30 = { 83c404 c645fc19 8b85a4bcf0ff c705????????01000000 83f810 7245 }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   c645fc19             | mov                 byte ptr [ebp - 4], 0x19
            //   8b85a4bcf0ff         | mov                 eax, dword ptr [ebp - 0xf435c]
            //   c705????????01000000     |     
            //   83f810               | cmp                 eax, 0x10
            //   7245                 | jb                  0x47

        $sequence_31 = { 8b048dc4f14000 ffe0 f7c703000000 7413 8a06 }
            // n = 5, score = 100
            //   8b048dc4f14000       | mov                 eax, dword ptr [ecx*4 + 0x40f1c4]
            //   ffe0                 | jmp                 eax
            //   f7c703000000         | test                edi, 3
            //   7413                 | je                  0x15
            //   8a06                 | mov                 al, byte ptr [esi]

        $sequence_32 = { c74410e05c584600 8b42e0 8b4804 8d41e8 }
            // n = 4, score = 100
            //   c74410e05c584600     | mov                 dword ptr [eax + edx - 0x20], 0x46585c
            //   8b42e0               | mov                 eax, dword ptr [edx - 0x20]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   8d41e8               | lea                 eax, [ecx - 0x18]

        $sequence_33 = { c7858cfcffff00000000 6a40 6a00 8d8590fcffff 50 e8???????? }
            // n = 6, score = 100
            //   c7858cfcffff00000000     | mov    dword ptr [ebp - 0x374], 0
            //   6a40                 | push                0x40
            //   6a00                 | push                0
            //   8d8590fcffff         | lea                 eax, [ebp - 0x370]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_34 = { 8b0d???????? 83c408 2b0d???????? 8bf0 }
            // n = 4, score = 100
            //   8b0d????????         |                     
            //   83c408               | add                 esp, 8
            //   2b0d????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_35 = { 85c9 743f ff75f4 8b15???????? 51 }
            // n = 5, score = 100
            //   85c9                 | test                ecx, ecx
            //   743f                 | je                  0x41
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   8b15????????         |                     
            //   51                   | push                ecx

        $sequence_36 = { c745f32e747874 c645f700 c7458b00000000 8d458f b960000000 bb00000000 }
            // n = 6, score = 100
            //   c745f32e747874       | mov                 dword ptr [ebp - 0xd], 0x7478742e
            //   c645f700             | mov                 byte ptr [ebp - 9], 0
            //   c7458b00000000       | mov                 dword ptr [ebp - 0x75], 0
            //   8d458f               | lea                 eax, [ebp - 0x71]
            //   b960000000           | mov                 ecx, 0x60
            //   bb00000000           | mov                 ebx, 0

        $sequence_37 = { c745e000000000 8b45f8 5f 5e 5b 81c4e4000000 3bec }
            // n = 7, score = 100
            //   c745e000000000       | mov                 dword ptr [ebp - 0x20], 0
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   81c4e4000000         | add                 esp, 0xe4
            //   3bec                 | cmp                 ebp, esp

        $sequence_38 = { 8b0c8d00b04600 807c012900 7407 32c0 e9???????? 837d1400 }
            // n = 6, score = 100
            //   8b0c8d00b04600       | mov                 ecx, dword ptr [ecx*4 + 0x46b000]
            //   807c012900           | cmp                 byte ptr [ecx + eax + 0x29], 0
            //   7407                 | je                  9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     
            //   837d1400             | cmp                 dword ptr [ebp + 0x14], 0

        $sequence_39 = { c6041800 6a10 68???????? 8bce e8???????? 6aff }
            // n = 6, score = 100
            //   c6041800             | mov                 byte ptr [eax + ebx], 0
            //   6a10                 | push                0x10
            //   68????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   6aff                 | push                -1

        $sequence_40 = { 8b0485a0244300 c644080401 57 e8???????? }
            // n = 4, score = 100
            //   8b0485a0244300       | mov                 eax, dword ptr [eax*4 + 0x4324a0]
            //   c644080401           | mov                 byte ptr [eax + ecx + 4], 1
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_41 = { 6bc930 8975e0 8db190f94200 8975e4 eb2b 8a4601 }
            // n = 6, score = 100
            //   6bc930               | imul                ecx, ecx, 0x30
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   8db190f94200         | lea                 esi, [ecx + 0x42f990]
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   eb2b                 | jmp                 0x2d
            //   8a4601               | mov                 al, byte ptr [esi + 1]

        $sequence_42 = { 660f56fa 25ff000000 83c001 25fe010000 f20f593c85c0014600 660f122c85c0014600 }
            // n = 6, score = 100
            //   660f56fa             | orpd                xmm7, xmm2
            //   25ff000000           | and                 eax, 0xff
            //   83c001               | add                 eax, 1
            //   25fe010000           | and                 eax, 0x1fe
            //   f20f593c85c0014600     | mulsd    xmm7, qword ptr [eax*4 + 0x4601c0]
            //   660f122c85c0014600     | movlpd    xmm5, qword ptr [eax*4 + 0x4601c0]

        $sequence_43 = { c7465c28c14200 83660800 33ff 47 }
            // n = 4, score = 100
            //   c7465c28c14200       | mov                 dword ptr [esi + 0x5c], 0x42c128
            //   83660800             | and                 dword ptr [esi + 8], 0
            //   33ff                 | xor                 edi, edi
            //   47                   | inc                 edi

        $sequence_44 = { 8b5df0 33ff 8945dc 8b1c9d60cb4300 895de0 f6441a2848 8b5d08 }
            // n = 7, score = 100
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]
            //   33ff                 | xor                 edi, edi
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8b1c9d60cb4300       | mov                 ebx, dword ptr [ebx*4 + 0x43cb60]
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx
            //   f6441a2848           | test                byte ptr [edx + ebx + 0x28], 0x48
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]

        $sequence_45 = { 0f87a4030000 ff24bda7714200 8bc6 e9???????? 8b50e4 3b51e4 7469 }
            // n = 7, score = 100
            //   0f87a4030000         | ja                  0x3aa
            //   ff24bda7714200       | jmp                 dword ptr [edi*4 + 0x4271a7]
            //   8bc6                 | mov                 eax, esi
            //   e9????????           |                     
            //   8b50e4               | mov                 edx, dword ptr [eax - 0x1c]
            //   3b51e4               | cmp                 edx, dword ptr [ecx - 0x1c]
            //   7469                 | je                  0x6b

        $sequence_46 = { 1d1d1d1d1d 1d1d1d1d1d 1d1d1d1d1d 1213 }
            // n = 4, score = 100
            //   1d1d1d1d1d           | sbb                 eax, 0x1d1d1d1d
            //   1d1d1d1d1d           | sbb                 eax, 0x1d1d1d1d
            //   1d1d1d1d1d           | sbb                 eax, 0x1d1d1d1d
            //   1213                 | adc                 dl, byte ptr [ebx]

        $sequence_47 = { ff15???????? 3bf4 e8???????? 8d85e8feffff 50 68???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   3bf4                 | cmp                 esi, esp
            //   e8????????           |                     
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_48 = { eb24 a1???????? 8944240c c744240801000000 c744240401000000 8d45f3 890424 }
            // n = 7, score = 100
            //   eb24                 | jmp                 0x26
            //   a1????????           |                     
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   c744240801000000     | mov                 dword ptr [esp + 8], 1
            //   c744240401000000     | mov                 dword ptr [esp + 4], 1
            //   8d45f3               | lea                 eax, [ebp - 0xd]
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_49 = { 89542404 890424 e8???????? e8???????? a1???????? 890424 }
            // n = 6, score = 100
            //   89542404             | mov                 dword ptr [esp + 4], edx
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   a1????????           |                     
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_50 = { 85c0 0f8430010000 a1???????? 890424 }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   0f8430010000         | je                  0x136
            //   a1????????           |                     
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_51 = { a1???????? 8b5de4 895c2418 894c2414 89542410 8974240c 8b5508 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   8b5de4               | mov                 ebx, dword ptr [ebp - 0x1c]
            //   895c2418             | mov                 dword ptr [esp + 0x18], ebx
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
            //   89542410             | mov                 dword ptr [esp + 0x10], edx
            //   8974240c             | mov                 dword ptr [esp + 0xc], esi
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_52 = { 890424 e8???????? 3b45f4 77dd }
            // n = 4, score = 100
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   3b45f4               | cmp                 eax, dword ptr [ebp - 0xc]
            //   77dd                 | ja                  0xffffffdf

        $sequence_53 = { eb3d a1???????? 8b0d???????? 8b15???????? 01ca }
            // n = 5, score = 100
            //   eb3d                 | jmp                 0x3f
            //   a1????????           |                     
            //   8b0d????????         |                     
            //   8b15????????         |                     
            //   01ca                 | add                 edx, ecx

        $sequence_54 = { 890424 e8???????? 8945dc 817ddce0070000 0f8ece030000 c70424???????? e8???????? }
            // n = 7, score = 100
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   817ddce0070000       | cmp                 dword ptr [ebp - 0x24], 0x7e0
            //   0f8ece030000         | jle                 0x3d4
            //   c70424????????       |                     
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1097728
}
