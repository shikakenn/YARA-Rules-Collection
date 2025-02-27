rule win_andromeda_auto {

    meta:
        id = "2L3BB8BAdS7EaZw37ki9vF"
        fingerprint = "v1_sha256_9e39961b4372e3bc922b40be7e1f53c18cfcecc85e79e89fe6975047795ee278"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.andromeda."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.andromeda"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ebcf 33c0 33db 33c9 33d2 }
            // n = 5, score = 800
            //   ebcf                 | jmp                 0xffffffd1
            //   33c0                 | xor                 eax, eax
            //   33db                 | xor                 ebx, ebx
            //   33c9                 | xor                 ecx, ecx
            //   33d2                 | xor                 edx, edx

        $sequence_1 = { 368a942800ffffff 02da 368ab42b00ffffff 3688b42800ffffff }
            // n = 4, score = 800
            //   368a942800ffffff     | mov                 dl, byte ptr ss:[eax + ebp - 0x100]
            //   02da                 | add                 bl, dl
            //   368ab42b00ffffff     | mov                 dh, byte ptr ss:[ebx + ebp - 0x100]
            //   3688b42800ffffff     | mov                 byte ptr ss:[eax + ebp - 0x100], dh

        $sequence_2 = { fc 33c0 8b7508 33db 368a942900ffffff 02c2 }
            // n = 6, score = 800
            //   fc                   | cld                 
            //   33c0                 | xor                 eax, eax
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33db                 | xor                 ebx, ebx
            //   368a942900ffffff     | mov                 dl, byte ptr ss:[ecx + ebp - 0x100]
            //   02c2                 | add                 al, dl

        $sequence_3 = { 3688b42800ffffff 3688942b00ffffff 02d6 81e2ff000000 }
            // n = 4, score = 800
            //   3688b42800ffffff     | mov                 byte ptr ss:[eax + ebp - 0x100], dh
            //   3688942b00ffffff     | mov                 byte ptr ss:[ebx + ebp - 0x100], dl
            //   02d6                 | add                 dl, dh
            //   81e2ff000000         | and                 edx, 0xff

        $sequence_4 = { 41 3b4d14 75c3 61 }
            // n = 4, score = 800
            //   41                   | inc                 ecx
            //   3b4d14               | cmp                 ecx, dword ptr [ebp + 0x14]
            //   75c3                 | jne                 0xffffffc5
            //   61                   | popal               

        $sequence_5 = { 8d7dfc b8fcfdfeff fd ab 2d04040404 e2f8 fc }
            // n = 7, score = 800
            //   8d7dfc               | lea                 edi, [ebp - 4]
            //   b8fcfdfeff           | mov                 eax, 0xfffefdfc
            //   fd                   | std                 
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   2d04040404           | sub                 eax, 0x4040404
            //   e2f8                 | loop                0xfffffffa
            //   fc                   | cld                 

        $sequence_6 = { 368a942900ffffff 02c2 020433 368ab42800ffffff 3688b42900ffffff 3688942800ffffff fec1 }
            // n = 7, score = 800
            //   368a942900ffffff     | mov                 dl, byte ptr ss:[ecx + ebp - 0x100]
            //   02c2                 | add                 al, dl
            //   020433               | add                 al, byte ptr [ebx + esi]
            //   368ab42800ffffff     | mov                 dh, byte ptr ss:[eax + ebp - 0x100]
            //   3688b42900ffffff     | mov                 byte ptr ss:[ecx + ebp - 0x100], dh
            //   3688942800ffffff     | mov                 byte ptr ss:[eax + ebp - 0x100], dl
            //   fec1                 | inc                 cl

        $sequence_7 = { 81c400ffffff 60 b940000000 8d7dfc b8fcfdfeff fd }
            // n = 6, score = 800
            //   81c400ffffff         | add                 esp, 0xffffff00
            //   60                   | pushal              
            //   b940000000           | mov                 ecx, 0x40
            //   8d7dfc               | lea                 edi, [ebp - 4]
            //   b8fcfdfeff           | mov                 eax, 0xfffefdfc
            //   fd                   | std                 

        $sequence_8 = { 60 e8???????? 5d 81ed???????? 33c9 }
            // n = 5, score = 700
            //   60                   | pushal              
            //   e8????????           |                     
            //   5d                   | pop                 ebp
            //   81ed????????         |                     
            //   33c9                 | xor                 ecx, ecx

        $sequence_9 = { 50 e8???????? 83c40c 6800000100 e8???????? }
            // n = 5, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6800000100           | push                0x10000
            //   e8????????           |                     

        $sequence_10 = { 85ca 7404 0420 8806 }
            // n = 4, score = 400
            //   85ca                 | test                edx, ecx
            //   7404                 | je                  6
            //   0420                 | add                 al, 0x20
            //   8806                 | mov                 byte ptr [esi], al

        $sequence_11 = { 0f9ec1 33d2 3c41 0f9dc2 85ca 7404 }
            // n = 6, score = 400
            //   0f9ec1               | setle               cl
            //   33d2                 | xor                 edx, edx
            //   3c41                 | cmp                 al, 0x41
            //   0f9dc2               | setge               dl
            //   85ca                 | test                edx, ecx
            //   7404                 | je                  6

        $sequence_12 = { 8a06 33c9 3c5a 0f9ec1 33d2 }
            // n = 5, score = 400
            //   8a06                 | mov                 al, byte ptr [esi]
            //   33c9                 | xor                 ecx, ecx
            //   3c5a                 | cmp                 al, 0x5a
            //   0f9ec1               | setle               cl
            //   33d2                 | xor                 edx, edx

        $sequence_13 = { 0fb64601 84c0 7905 0d00ffffff }
            // n = 4, score = 400
            //   0fb64601             | movzx               eax, byte ptr [esi + 1]
            //   84c0                 | test                al, al
            //   7905                 | jns                 7
            //   0d00ffffff           | or                  eax, 0xffffff00

        $sequence_14 = { 6a30 8d45d0 50 6a01 ff7508 }
            // n = 5, score = 400
            //   6a30                 | push                0x30
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   50                   | push                eax
            //   6a01                 | push                1
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_15 = { 56 6800010400 56 56 56 ff750c }
            // n = 6, score = 300
            //   56                   | push                esi
            //   6800010400           | push                0x40100
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_16 = { e8???????? 8945fc 83f800 0f8476010000 6804010000 6a00 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   83f800               | cmp                 eax, 0
            //   0f8476010000         | je                  0x17c
            //   6804010000           | push                0x104
            //   6a00                 | push                0

        $sequence_17 = { ff35???????? e8???????? 8945f8 83f800 0f8458010000 6804010000 ff75f8 }
            // n = 7, score = 200
            //   ff35????????         |                     
            //   e8????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   83f800               | cmp                 eax, 0
            //   0f8458010000         | je                  0x15e
            //   6804010000           | push                0x104
            //   ff75f8               | push                dword ptr [ebp - 8]

        $sequence_18 = { f3aa 6a00 6a00 ff75f0 e8???????? c7459c44000000 }
            // n = 6, score = 200
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   c7459c44000000       | mov                 dword ptr [ebp - 0x64], 0x44

        $sequence_19 = { a3???????? 6804010000 6a00 ff35???????? e8???????? }
            // n = 5, score = 200
            //   a3????????           |                     
            //   6804010000           | push                0x104
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   e8????????           |                     

        $sequence_20 = { 68???????? 6801000080 e8???????? 83f800 }
            // n = 4, score = 200
            //   68????????           |                     
            //   6801000080           | push                0x80000001
            //   e8????????           |                     
            //   83f800               | cmp                 eax, 0

        $sequence_21 = { ff75fc 6a00 e8???????? 6a00 ff75f8 ff75fc e8???????? }
            // n = 7, score = 200
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   6a00                 | push                0
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     

        $sequence_22 = { e8???????? 6a06 ff75f8 e8???????? 8d45f4 50 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   6a06                 | push                6
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax

        $sequence_23 = { 83f8ff 7457 33c0 8d7d9c }
            // n = 4, score = 200
            //   83f8ff               | cmp                 eax, -1
            //   7457                 | je                  0x59
            //   33c0                 | xor                 eax, eax
            //   8d7d9c               | lea                 edi, [ebp - 0x64]

        $sequence_24 = { 8b45ec 8b55fc 8b0490 81f683073af8 81e7d889e666 8945f8 }
            // n = 6, score = 100
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b0490               | mov                 eax, dword ptr [eax + edx*4]
            //   81f683073af8         | xor                 esi, 0xf83a0783
            //   81e7d889e666         | and                 edi, 0x66e689d8
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_25 = { 81fe50f639e3 0f84a2f7ffff 81455886080000 69ffc520db89 ff5518 }
            // n = 5, score = 100
            //   81fe50f639e3         | cmp                 esi, 0xe339f650
            //   0f84a2f7ffff         | je                  0xfffff7a8
            //   81455886080000       | add                 dword ptr [ebp + 0x58], 0x886
            //   69ffc520db89         | imul                edi, edi, 0x89db20c5
            //   ff5518               | call                dword ptr [ebp + 0x18]

        $sequence_26 = { 69f676ce078f 81ef4b9d0e76 81ff901d63a9 0f84f1010000 8b4544 }
            // n = 5, score = 100
            //   69f676ce078f         | imul                esi, esi, 0x8f07ce76
            //   81ef4b9d0e76         | sub                 edi, 0x760e9d4b
            //   81ff901d63a9         | cmp                 edi, 0xa9631d90
            //   0f84f1010000         | je                  0x1f7
            //   8b4544               | mov                 eax, dword ptr [ebp + 0x44]

        $sequence_27 = { 0f856afeffff e9???????? 55 8bec 83ec24 53 56 }
            // n = 7, score = 100
            //   0f856afeffff         | jne                 0xfffffe70
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec24               | sub                 esp, 0x24
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_28 = { 8bd8 ff5630 8bf8 ff560c 23d8 ff5638 }
            // n = 6, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   ff5630               | call                dword ptr [esi + 0x30]
            //   8bf8                 | mov                 edi, eax
            //   ff560c               | call                dword ptr [esi + 0xc]
            //   23d8                 | and                 ebx, eax
            //   ff5638               | call                dword ptr [esi + 0x38]

        $sequence_29 = { 69ffbb3de4b4 d1e8 81f679b291d1 894544 3d80000000 7363 }
            // n = 6, score = 100
            //   69ffbb3de4b4         | imul                edi, edi, 0xb4e43dbb
            //   d1e8                 | shr                 eax, 1
            //   81f679b291d1         | xor                 esi, 0xd191b279
            //   894544               | mov                 dword ptr [ebp + 0x44], eax
            //   3d80000000           | cmp                 eax, 0x80
            //   7363                 | jae                 0x65

        $sequence_30 = { 03c1 8b4df0 0fb609 03ca 81e1ff000000 }
            // n = 5, score = 100
            //   03c1                 | add                 eax, ecx
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   0fb609               | movzx               ecx, byte ptr [ecx]
            //   03ca                 | add                 ecx, edx
            //   81e1ff000000         | and                 ecx, 0xff

        $sequence_31 = { 8b456c 8b4018 894560 81c3b6dd7f19 ff5634 0faff8 }
            // n = 6, score = 100
            //   8b456c               | mov                 eax, dword ptr [ebp + 0x6c]
            //   8b4018               | mov                 eax, dword ptr [eax + 0x18]
            //   894560               | mov                 dword ptr [ebp + 0x60], eax
            //   81c3b6dd7f19         | add                 ebx, 0x197fddb6
            //   ff5634               | call                dword ptr [esi + 0x34]
            //   0faff8               | imul                edi, eax

    condition:
        7 of them and filesize < 204800
}
