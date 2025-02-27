rule win_microcin_auto {

    meta:
        id = "2tineP5dQTSNzvz0gOEIuT"
        fingerprint = "v1_sha256_ce937d5b0febb8a0ef0b69b389b9ac6e2a402988a44ce06e021321112f9c236c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.microcin."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.microcin"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 48895c2410 55 488dac2440feffff 4881ecc0020000 488b05???????? 4833c4 }
            // n = 6, score = 400
            //   48895c2410           | push                0x80000001
            //   55                   | test                eax, eax
            //   488dac2440feffff     | push                0x1005
            //   4881ecc0020000       | push                0xffff
            //   488b05????????       |                     
            //   4833c4               | push                esi

        $sequence_1 = { 8d45ac 50 6801000080 ff15???????? }
            // n = 4, score = 400
            //   8d45ac               | jle                 0x1a
            //   50                   | cmp                 byte ptr [ebp + esi - 0x158], 0x3a
            //   6801000080           | je                  0x29
            //   ff15????????         |                     

        $sequence_2 = { ff15???????? 4863c8 c6840d8002000075 488d8d80020000 }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   4863c8               | jle                 0x1e
            //   c6840d8002000075     | call                ebx
            //   488d8d80020000       | test                eax, eax

        $sequence_3 = { 7515 c74424484c773373 c744244c31674d5a e9???????? c744244849734541 }
            // n = 5, score = 400
            //   7515                 | call                ebx
            //   c74424484c773373     | push                eax
            //   c744244c31674d5a     | call                ebx
            //   e9????????           |                     
            //   c744244849734541     | test                eax, eax

        $sequence_4 = { 4533c9 33d2 498d4e70 ff15???????? 85c0 }
            // n = 5, score = 400
            //   4533c9               | jle                 0x1c
            //   33d2                 | cmp                 byte ptr [ebp + esi - 0x158], 0x3a
            //   498d4e70             | je                  0x2d
            //   ff15????????         |                     
            //   85c0                 | lea                 eax, [ebp - 0x158]

        $sequence_5 = { 85c0 0f8599000000 33d2 41b810020000 }
            // n = 4, score = 400
            //   85c0                 | cmovne              esi, edi
            //   0f8599000000         | push                0x1005
            //   33d2                 | push                0xffff
            //   41b810020000         | push                esi

        $sequence_6 = { b9ff030000 2bc8 4863d1 4883ea02 }
            // n = 4, score = 400
            //   b9ff030000           | jle                 0x21
            //   2bc8                 | jle                 0x1a
            //   4863d1               | cmp                 byte ptr [ebp + esi - 0x158], 0x3a
            //   4883ea02             | je                  0x29

        $sequence_7 = { 897e04 5b 5f 5e 5d c20400 55 }
            // n = 7, score = 400
            //   897e04               | mov                 ecx, dword ptr [ebp - 0x10]
            //   5b                   | lea                 eax, [ebp - 8]
            //   5f                   | push                eax
            //   5e                   | push                0
            //   5d                   | call                eax
            //   c20400               | ret                 
            //   55                   | push                0

        $sequence_8 = { 7e18 80bc35a8feffff3a 741f 8d85a8feffff 46 }
            // n = 5, score = 400
            //   7e18                 | xor                 eax, eax
            //   80bc35a8feffff3a     | cmp                 dword ptr [eax + 0x413a28], edi
            //   741f                 | je                  0x9d
            //   8d85a8feffff         | inc                 dword ptr [ebp - 0x1c]
            //   46                   | add                 eax, 0x30

        $sequence_9 = { c6840d7002000062 488d8d70020000 ff15???????? 4863c8 }
            // n = 4, score = 400
            //   c6840d7002000062     | lea                 eax, [ebp - 0x158]
            //   488d8d70020000       | inc                 esi
            //   ff15????????         |                     
            //   4863c8               | push                eax

        $sequence_10 = { 8d85f8feffff 6804010000 50 ff15???????? 8d85f8feffff }
            // n = 5, score = 400
            //   8d85f8feffff         | dec                 eax
            //   6804010000           | mov                 ecx, ebp
            //   50                   | test                eax, eax
            //   ff15????????         |                     
            //   8d85f8feffff         | jne                 0x21

        $sequence_11 = { 6a10 50 56 ff15???????? 85c0 0f45f7 }
            // n = 6, score = 400
            //   6a10                 | jne                 0xf
            //   50                   | cmp                 dword ptr [ebp + edx*4 - 0x188], 0
            //   56                   | jge                 0x3e
            //   ff15????????         |                     
            //   85c0                 | mov                 eax, dword ptr [ebp - 0x84]
            //   0f45f7               | mov                 ecx, dword ptr [ebp + eax*4 - 0x188]

        $sequence_12 = { 894620 c7462406000000 33c0 48894638 48894630 }
            // n = 5, score = 400
            //   894620               | call                esi
            //   c7462406000000       | push                eax
            //   33c0                 | push                0x1005
            //   48894638             | push                0xffff
            //   48894630             | push                esi

        $sequence_13 = { 68ffff0000 56 8b35???????? ffd6 6a04 }
            // n = 5, score = 400
            //   68ffff0000           | mov                 edx, esp
            //   56                   | xor                 ecx, ecx
            //   8b35????????         |                     
            //   ffd6                 | test                eax, eax
            //   6a04                 | dec                 esp

        $sequence_14 = { ff75d4 e8???????? 83c40c 8bc7 }
            // n = 4, score = 400
            //   ff75d4               | call                ebx
            //   e8????????           |                     
            //   83c40c               | test                eax, eax
            //   8bc7                 | jle                 0x1f

        $sequence_15 = { 50 ffd3 85c0 7e18 80bc35a8feffff3a }
            // n = 5, score = 400
            //   50                   | lea                 edx, [0x10c73]
            //   ffd3                 | dec                 eax
            //   85c0                 | mov                 ecx, eax
            //   7e18                 | dec                 eax
            //   80bc35a8feffff3a     | test                eax, eax

        $sequence_16 = { 752a 4c8d0502130100 8bd7 498bcd e8???????? 85c0 7415 }
            // n = 7, score = 200
            //   752a                 | jne                 0x2c
            //   4c8d0502130100       | dec                 esp
            //   8bd7                 | lea                 eax, [0x11302]
            //   498bcd               | mov                 edx, edi
            //   e8????????           |                     
            //   85c0                 | dec                 ecx
            //   7415                 | mov                 ecx, ebp

        $sequence_17 = { 4c8d0535120100 33c0 498bd0 3b0a 740e ffc0 }
            // n = 6, score = 200
            //   4c8d0535120100       | mov                 edx, esp
            //   33c0                 | dec                 eax
            //   498bd0               | mov                 ecx, ebp
            //   3b0a                 | dec                 eax
            //   740e                 | cmp                 eax, 0x3c
            //   ffc0                 | jbe                 0x49

        $sequence_18 = { 41bc14030000 4c8d0574130100 488bcd 418bd4 e8???????? }
            // n = 5, score = 200
            //   41bc14030000         | lea                 ecx, [ebp + eax*2 - 0x44]
            //   4c8d0574130100       | dec                 eax
            //   488bcd               | mov                 eax, ecx
            //   418bd4               | dec                 eax
            //   e8????????           |                     

        $sequence_19 = { 83bc9578feffff00 7d34 8b857cffffff 8b8c8578feffff 83c104 8b957cffffff 898c9578feffff }
            // n = 7, score = 200
            //   83bc9578feffff00     | mov                 ecx, ebp
            //   7d34                 | test                eax, eax
            //   8b857cffffff         | dec                 esp
            //   8b8c8578feffff       | lea                 eax, [0x11374]
            //   83c104               | dec                 eax
            //   8b957cffffff         | mov                 ecx, ebp
            //   898c9578feffff       | inc                 ecx

        $sequence_20 = { 4053 4883ec20 8bd9 488d0d950c0100 }
            // n = 4, score = 200
            //   4053                 | test                eax, eax
            //   4883ec20             | je                  0x1b
            //   8bd9                 | dec                 eax
            //   488d0d950c0100       | lea                 edx, [0x10c73]

        $sequence_21 = { b905000000 f7f1 85d2 750b ff15???????? }
            // n = 5, score = 200
            //   b905000000           | dec                 esp
            //   f7f1                 | lea                 eax, [0x11302]
            //   85d2                 | mov                 edx, edi
            //   750b                 | dec                 ecx
            //   ff15????????         |                     

        $sequence_22 = { fa fa fa fa fa fa }
            // n = 6, score = 200
            //   fa                   | mov                 eax, 0x12010
            //   fa                   | inc                 ecx
            //   fa                   | lea                 edi, [esp - 0x19]
            //   fa                   | test                eax, eax
            //   fa                   | jne                 0x2e
            //   fa                   | dec                 esp

        $sequence_23 = { 53 53 56 43 }
            // n = 4, score = 200
            //   53                   | lea                 eax, [0x11302]
            //   53                   | mov                 edx, edi
            //   56                   | cmp                 eax, 0x31
            //   43                   | jge                 0x5e

        $sequence_24 = { 83f831 7d5c 8b4df4 034df8 }
            // n = 4, score = 200
            //   83f831               | dec                 esp
            //   7d5c                 | lea                 eax, [0x1126c]
            //   8b4df4               | dec                 ecx
            //   034df8               | mov                 edx, esp

        $sequence_25 = { 89857cffffff 83bd7cffffff20 0f8daf000000 8b8d7cffffff 8b957cffffff 8b448d80 2b8495f8feffff }
            // n = 7, score = 200
            //   89857cffffff         | inc                 eax
            //   83bd7cffffff20       | dec                 eax
            //   0f8daf000000         | sub                 esp, 0x20
            //   8b8d7cffffff         | mov                 ebx, ecx
            //   8b957cffffff         | dec                 eax
            //   8b448d80             | lea                 ecx, [0x10c95]
            //   2b8495f8feffff       | dec                 eax

        $sequence_26 = { 636373 7673 6873742e65 7865 }
            // n = 4, score = 200
            //   636373               | mov                 ecx, dword ptr [ebp - 0x10]
            //   7673                 | lea                 eax, [ebp - 8]
            //   6873742e65           | push                eax
            //   7865                 | push                0

        $sequence_27 = { 751a 488d15f8110100 41b810200100 488bcd e8???????? }
            // n = 5, score = 200
            //   751a                 | dec                 eax
            //   488d15f8110100       | mov                 ecx, eax
            //   41b810200100         | inc                 ecx
            //   488bcd               | mov                 esp, 0x314
            //   e8????????           |                     

        $sequence_28 = { 7370 696465726167656e 742e 657865 }
            // n = 4, score = 200
            //   7370                 | div                 ecx
            //   696465726167656e     | test                edx, edx
            //   742e                 | jne                 0x11
            //   657865               | cmp                 dword ptr [ebp + edx*4 - 0x188], 0

        $sequence_29 = { 8b8d78dfffff 83c103 8b9578dfffff 890c95003c4100 }
            // n = 4, score = 200
            //   8b8d78dfffff         | dec                 eax
            //   83c103               | mov                 ecx, ebp
            //   8b9578dfffff         | test                eax, eax
            //   890c95003c4100       | jne                 0x2c

        $sequence_30 = { 33c0 39b8283a4100 0f8491000000 ff45e4 83c030 }
            // n = 5, score = 200
            //   33c0                 | xor                 eax, eax
            //   39b8283a4100         | dec                 ecx
            //   0f8491000000         | mov                 edx, eax
            //   ff45e4               | cmp                 ecx, dword ptr [edx]
            //   83c030               | je                  0x17

        $sequence_31 = { 0fb645fb 99 b903000000 f7f9 85d2 751d }
            // n = 6, score = 200
            //   0fb645fb             | mov                 edx, esp
            //   99                   | xor                 ecx, ecx
            //   b903000000           | test                eax, eax
            //   f7f9                 | jne                 0x124
            //   85d2                 | dec                 esp
            //   751d                 | lea                 eax, [0x11235]

        $sequence_32 = { 4889742420 e8???????? cc 4c8d056c120100 498bd4 488bcd }
            // n = 6, score = 200
            //   4889742420           | mov                 edx, esp
            //   e8????????           |                     
            //   cc                   | inc                 eax
            //   4c8d056c120100       | push                ebx
            //   498bd4               | dec                 eax
            //   488bcd               | sub                 esp, 0x20

        $sequence_33 = { 6828010000 8d85ccfeffff 6a00 50 }
            // n = 4, score = 200
            //   6828010000           | outsb               dx, byte ptr [esi]
            //   8d85ccfeffff         | jbe                 0x6c
            //   6a00                 | jb                  0x71
            //   50                   | outsb               dx, byte ptr [esi]

        $sequence_34 = { 498bcd e8???????? 4c8d05b7120100 41b903000000 488d4c45bc 488bc1 }
            // n = 6, score = 200
            //   498bcd               | test                eax, eax
            //   e8????????           |                     
            //   4c8d05b7120100       | je                  0x17
            //   41b903000000         | dec                 ecx
            //   488d4c45bc           | mov                 ecx, ebp
            //   488bc1               | dec                 esp

        $sequence_35 = { 6e 7669 726f 6e 6d 656e 7400 }
            // n = 7, score = 200
            //   6e                   | mov                 ecx, dword ptr [ebp - 0xc]
            //   7669                 | add                 ecx, dword ptr [ebp - 8]
            //   726f                 | mov                 ecx, dword ptr [ebp - 0x2088]
            //   6e                   | add                 ecx, 3
            //   6d                   | mov                 edx, dword ptr [ebp - 0x2088]
            //   656e                 | mov                 dword ptr [edx*4 + 0x413c00], ecx
            //   7400                 | mov                 ecx, 5

        $sequence_36 = { 4885c0 7419 488d15730c0100 488bc8 }
            // n = 4, score = 200
            //   4885c0               | lea                 eax, [0x112b7]
            //   7419                 | inc                 ecx
            //   488d15730c0100       | mov                 ecx, 3
            //   488bc8               | dec                 eax

        $sequence_37 = { 33c0 eb42 8b4df0 e8???????? 8d45f8 50 6a00 }
            // n = 7, score = 200
            //   33c0                 | test                eax, eax
            //   eb42                 | dec                 ecx
            //   8b4df0               | mov                 edx, esp
            //   e8????????           |                     
            //   8d45f8               | dec                 eax
            //   50                   | mov                 ecx, ebp
            //   6a00                 | test                eax, eax

        $sequence_38 = { 0fb785d4f4ffff 50 8d85e8f4ffff 68???????? 50 }
            // n = 5, score = 100
            //   0fb785d4f4ffff       | lea                 esp, [ebp + 0x70]
            //   50                   | pop                 ebp
            //   8d85e8f4ffff         | ret                 
            //   68????????           |                     
            //   50                   | pop                 ebx

        $sequence_39 = { 50 ff15???????? 8d85c8feffff 6a00 6880000000 6a04 }
            // n = 6, score = 100
            //   50                   | jbe                 0x75
            //   ff15????????         |                     
            //   8d85c8feffff         | push                0x652e7473
            //   6a00                 | js                  0x6e
            //   6880000000           | push                ebx
            //   6a04                 | push                ebx

        $sequence_40 = { ffd3 f7d8 1bc0 f7d8 5f 5e 5b }
            // n = 7, score = 100
            //   ffd3                 | je                  0x38
            //   f7d8                 | js                  0x72
            //   1bc0                 | jbe                 0x6b
            //   f7d8                 | jb                  0x71
            //   5f                   | outsb               dx, byte ptr [esi]
            //   5e                   | insd                dword ptr es:[edi], dx
            //   5b                   | outsb               dx, byte ptr gs:[esi]

        $sequence_41 = { e8???????? 8d442464 83c40c 89442434 8d44240c }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8d442464             | push                esi
            //   83c40c               | inc                 ebx
            //   89442434             | outsb               dx, byte ptr [esi]
            //   8d44240c             | jbe                 0x6b

        $sequence_42 = { 8b9504010000 48 63d2 48 03c2 8b9504010000 48 }
            // n = 7, score = 100
            //   8b9504010000         | jb                  0x71
            //   48                   | outsb               dx, byte ptr [esi]
            //   63d2                 | insd                dword ptr es:[edi], dx
            //   48                   | outsb               dx, byte ptr gs:[esi]
            //   03c2                 | je                  6
            //   8b9504010000         | cli                 
            //   48                   | cli                 

        $sequence_43 = { 89d5 ba67676767 45 89cf 45 89c6 49 }
            // n = 7, score = 100
            //   89d5                 | push                esi
            //   ba67676767           | cli                 
            //   45                   | cli                 
            //   89cf                 | cli                 
            //   45                   | cli                 
            //   89c6                 | cli                 
            //   49                   | cli                 

        $sequence_44 = { 6a00 57 ff15???????? 8b1d???????? c705????????01000000 6a00 6a00 }
            // n = 7, score = 100
            //   6a00                 | cli                 
            //   57                   | cli                 
            //   ff15????????         |                     
            //   8b1d????????         |                     
            //   c705????????01000000     |     
            //   6a00                 | cli                 
            //   6a00                 | dec                 eax

        $sequence_45 = { 8b55e4 83c40c 6bd230 8d82c0d34000 }
            // n = 4, score = 100
            //   8b55e4               | cli                 
            //   83c40c               | cli                 
            //   6bd230               | cli                 
            //   8d82c0d34000         | arpl                word ptr [ebx + 0x73], sp

        $sequence_46 = { 75e4 56 ffd3 33c0 }
            // n = 4, score = 100
            //   75e4                 | cli                 
            //   56                   | cli                 
            //   ffd3                 | cli                 
            //   33c0                 | cli                 

        $sequence_47 = { 85c0 0f84ed000000 8b3d???????? 50 6a08 ffd7 8b1d???????? }
            // n = 7, score = 100
            //   85c0                 | jb                  0x73
            //   0f84ed000000         | outsb               dx, byte ptr [esi]
            //   8b3d????????         |                     
            //   50                   | insd                dword ptr es:[edi], dx
            //   6a08                 | outsb               dx, byte ptr gs:[esi]
            //   ffd7                 | je                  0xa
            //   8b1d????????         |                     

        $sequence_48 = { e9???????? 48 8d6570 5d c3 5b 48 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   48                   | imul                esp, dword ptr [ebp + 0x72], 0x6e656761
            //   8d6570               | je                  0x38
            //   5d                   | js                  0x72
            //   c3                   | dec                 ecx
            //   5b                   | push                ebx
            //   48                   | push                ebx

        $sequence_49 = { 8b5664 8d4c1105 8908 68ebeeebee ff7658 e8???????? }
            // n = 6, score = 100
            //   8b5664               | insd                dword ptr es:[edi], dx
            //   8d4c1105             | outsb               dx, byte ptr gs:[esi]
            //   8908                 | je                  8
            //   68ebeeebee           | jae                 0x72
            //   ff7658               | imul                esp, dword ptr [ebp + 0x72], 0x6e656761
            //   e8????????           |                     

    condition:
        7 of them and filesize < 417792
}
