rule win_red_gambler_auto {

    meta:
        id = "49xCtDeH0ckRAirC4qxCq6"
        fingerprint = "v1_sha256_5df98b37982fcd6fe80d2e1e665e4de08feffa39ad75db51ff52df159597061f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.red_gambler."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.red_gambler"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7418 8b95f0feffff 52 8d85f8feffff 50 ff15???????? }
            // n = 6, score = 400
            //   7418                 | je                  0x1a
            //   8b95f0feffff         | mov                 edx, dword ptr [ebp - 0x110]
            //   52                   | push                edx
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_1 = { 75eb 891e 57 6a00 ff15???????? 50 ff15???????? }
            // n = 7, score = 400
            //   75eb                 | jne                 0xffffffed
            //   891e                 | mov                 dword ptr [esi], ebx
            //   57                   | push                edi
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_2 = { 8d5605 56 c645ece9 894ded }
            // n = 4, score = 400
            //   8d5605               | lea                 edx, [esi + 5]
            //   56                   | push                esi
            //   c645ece9             | mov                 byte ptr [ebp - 0x14], 0xe9
            //   894ded               | mov                 dword ptr [ebp - 0x13], ecx

        $sequence_3 = { 803e20 753b 807e01a2 7535 807e02c3 }
            // n = 5, score = 400
            //   803e20               | cmp                 byte ptr [esi], 0x20
            //   753b                 | jne                 0x3d
            //   807e01a2             | cmp                 byte ptr [esi + 1], 0xa2
            //   7535                 | jne                 0x37
            //   807e02c3             | cmp                 byte ptr [esi + 2], 0xc3

        $sequence_4 = { ff15???????? 6800010000 56 68???????? e8???????? a1???????? 83c40c }
            // n = 7, score = 400
            //   ff15????????         |                     
            //   6800010000           | push                0x100
            //   56                   | push                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   a1????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_5 = { 807801c3 7523 6800010000 50 }
            // n = 4, score = 400
            //   807801c3             | cmp                 byte ptr [eax + 1], 0xc3
            //   7523                 | jne                 0x25
            //   6800010000           | push                0x100
            //   50                   | push                eax

        $sequence_6 = { 61 8b35???????? 81c6201a0000 ffd6 }
            // n = 4, score = 400
            //   61                   | popal               
            //   8b35????????         |                     
            //   81c6201a0000         | add                 esi, 0x1a20
            //   ffd6                 | call                esi

        $sequence_7 = { 668985f0f8ffff ffd6 50 8d95f2f8ffff }
            // n = 4, score = 400
            //   668985f0f8ffff       | mov                 word ptr [ebp - 0x710], ax
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   8d95f2f8ffff         | lea                 edx, [ebp - 0x70e]

        $sequence_8 = { 0e 6706 7e0e 2829 dc03 dc692c 64f33c87 }
            // n = 7, score = 300
            //   0e                   | push                cs
            //   6706                 | push                es
            //   7e0e                 | jle                 0x10
            //   2829                 | sub                 byte ptr [ecx], ch
            //   dc03                 | fadd                qword ptr [ebx]
            //   dc692c               | fsubr               qword ptr [ecx + 0x2c]
            //   64f33c87             | cmp                 al, 0x87

        $sequence_9 = { 93 ee b4ed 2f 2326 50 0f41631c }
            // n = 7, score = 300
            //   93                   | xchg                eax, ebx
            //   ee                   | out                 dx, al
            //   b4ed                 | mov                 ah, 0xed
            //   2f                   | das                 
            //   2326                 | and                 esp, dword ptr [esi]
            //   50                   | push                eax
            //   0f41631c             | cmovno              esp, dword ptr [ebx + 0x1c]

        $sequence_10 = { 9e 54 50 4c 48 44 }
            // n = 6, score = 300
            //   9e                   | sahf                
            //   54                   | push                esp
            //   50                   | push                eax
            //   4c                   | dec                 esp
            //   48                   | dec                 eax
            //   44                   | inc                 esp

        $sequence_11 = { 8d8598fdffff 50 68???????? 8d8d98fbffff 68???????? }
            // n = 5, score = 300
            //   8d8598fdffff         | lea                 eax, [ebp - 0x268]
            //   50                   | push                eax
            //   68????????           |                     
            //   8d8d98fbffff         | lea                 ecx, [ebp - 0x468]
            //   68????????           |                     

        $sequence_12 = { 6800010000 8d8dfcfdffff 51 6a00 }
            // n = 4, score = 300
            //   6800010000           | push                0x100
            //   8d8dfcfdffff         | lea                 ecx, [ebp - 0x204]
            //   51                   | push                ecx
            //   6a00                 | push                0

        $sequence_13 = { ff15???????? 8d8594fbffff 50 8d4d98 51 ff15???????? }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   8d8594fbffff         | lea                 eax, [ebp - 0x46c]
            //   50                   | push                eax
            //   8d4d98               | lea                 ecx, [ebp - 0x68]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_14 = { 8d8d98fbffff 68???????? 51 ff15???????? 83c414 6a00 }
            // n = 6, score = 300
            //   8d8d98fbffff         | lea                 ecx, [ebp - 0x468]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   6a00                 | push                0

        $sequence_15 = { 7364 42 e5e1 5f }
            // n = 4, score = 300
            //   7364                 | jae                 0x66
            //   42                   | inc                 edx
            //   e5e1                 | in                  eax, 0xe1
            //   5f                   | pop                 edi

        $sequence_16 = { e600 3e3e25162f062d 2b2a bee7eee947 }
            // n = 4, score = 300
            //   e600                 | out                 0, al
            //   3e3e25162f062d       | and                 eax, 0x2d062f16
            //   2b2a                 | sub                 ebp, dword ptr [edx]
            //   bee7eee947           | mov                 esi, 0x47e9eee7

        $sequence_17 = { 09afba55a367 59 2f 74be }
            // n = 4, score = 300
            //   09afba55a367         | or                  dword ptr [edi + 0x67a355ba], ebp
            //   59                   | pop                 ecx
            //   2f                   | das                 
            //   74be                 | je                  0xffffffc0

        $sequence_18 = { ff15???????? 83c414 6a00 6a00 8d9598fbffff 52 68???????? }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d9598fbffff         | lea                 edx, [ebp - 0x468]
            //   52                   | push                edx
            //   68????????           |                     

        $sequence_19 = { 6800010000 8d85fcfeffff 50 6a00 ff15???????? }
            // n = 5, score = 300
            //   6800010000           | push                0x100
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_20 = { 7bce 07 93 60 58 0e 4c }
            // n = 7, score = 300
            //   7bce                 | jnp                 0xffffffd0
            //   07                   | pop                 es
            //   93                   | xchg                eax, ebx
            //   60                   | pushal              
            //   58                   | pop                 eax
            //   0e                   | push                cs
            //   4c                   | dec                 esp

        $sequence_21 = { cd50 d46e c8603b8d 6e }
            // n = 4, score = 300
            //   cd50                 | int                 0x50
            //   d46e                 | aam                 0x6e
            //   c8603b8d             | enter               0x3b60, -0x73
            //   6e                   | outsb               dx, byte ptr [esi]

        $sequence_22 = { 8d9598fbffff 52 68???????? 6a00 6a00 ff15???????? 8b4dfc }
            // n = 7, score = 300
            //   8d9598fbffff         | lea                 edx, [ebp - 0x468]
            //   52                   | push                edx
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_23 = { ff15???????? 6800010000 8d8d98fdffff 51 8d9598feffff 52 ff15???????? }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   6800010000           | push                0x100
            //   8d8d98fdffff         | lea                 ecx, [ebp - 0x268]
            //   51                   | push                ecx
            //   8d9598feffff         | lea                 edx, [ebp - 0x168]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_24 = { 8d4d98 51 ff15???????? 8d5598 52 8d8598fdffff }
            // n = 6, score = 300
            //   8d4d98               | lea                 ecx, [ebp - 0x68]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d5598               | lea                 edx, [ebp - 0x68]
            //   52                   | push                edx
            //   8d8598fdffff         | lea                 eax, [ebp - 0x268]

        $sequence_25 = { 8d8c05fcfeffff 51 8d95fcfeffff 52 }
            // n = 4, score = 100
            //   8d8c05fcfeffff       | lea                 ecx, [ebp + eax - 0x104]
            //   51                   | push                ecx
            //   8d95fcfeffff         | lea                 edx, [ebp - 0x104]
            //   52                   | push                edx

        $sequence_26 = { 6a5c 8d8dfcfeffff 51 ff15???????? 8d9405fcfeffff }
            // n = 5, score = 100
            //   6a5c                 | push                0x5c
            //   8d8dfcfeffff         | lea                 ecx, [ebp - 0x104]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d9405fcfeffff       | lea                 edx, [ebp + eax - 0x104]

        $sequence_27 = { 8b4508 ff34c5d0814000 ff15???????? 5d c3 6a0c }
            // n = 6, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff34c5d0814000       | push                dword ptr [eax*8 + 0x4081d0]
            //   ff15????????         |                     
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   6a0c                 | push                0xc

        $sequence_28 = { e8???????? 68???????? ff15???????? 8b7508 c7465c486b4000 83660800 33ff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   c7465c486b4000       | mov                 dword ptr [esi + 0x5c], 0x406b48
            //   83660800             | and                 dword ptr [esi + 8], 0
            //   33ff                 | xor                 edi, edi

        $sequence_29 = { 8945e4 83f805 7d10 668b4c4310 66890c4580974000 }
            // n = 5, score = 100
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   83f805               | cmp                 eax, 5
            //   7d10                 | jge                 0x12
            //   668b4c4310           | mov                 cx, word ptr [ebx + eax*2 + 0x10]
            //   66890c4580974000     | mov                 word ptr [eax*2 + 0x409780], cx

        $sequence_30 = { 55 8bec 8b4508 33c9 3b04cd10804000 7413 41 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   33c9                 | xor                 ecx, ecx
            //   3b04cd10804000       | cmp                 eax, dword ptr [ecx*8 + 0x408010]
            //   7413                 | je                  0x15
            //   41                   | inc                 ecx

        $sequence_31 = { 8bd8 ffd7 8b3d???????? 6aff ffd7 ffd3 }
            // n = 6, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   ffd7                 | call                edi
            //   8b3d????????         |                     
            //   6aff                 | push                -1
            //   ffd7                 | call                edi
            //   ffd3                 | call                ebx

    condition:
        7 of them and filesize < 327680
}
