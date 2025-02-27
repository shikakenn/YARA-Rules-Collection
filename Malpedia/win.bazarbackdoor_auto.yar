rule win_bazarbackdoor_auto {

    meta:
        id = "2PJNLHmgk9wb0sXD0MHaQT"
        fingerprint = "v1_sha256_fa8de6b24d77371b268d10b4378b94df76c1989be3511c0a0f6cfa11ec9c195b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.bazarbackdoor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bazarbackdoor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff15???????? 85c0 780a 4898 }
            // n = 4, score = 1500
            //   ff15????????         |                     
            //   85c0                 | dec                 eax
            //   780a                 | mov                 dword ptr [esp + 0x20], eax
            //   4898                 | test                eax, eax

        $sequence_1 = { 41b80f100000 488bce 4889442420 ff15???????? }
            // n = 4, score = 1500
            //   41b80f100000         | inc                 ecx
            //   488bce               | mov                 eax, 0x100f
            //   4889442420           | dec                 eax
            //   ff15????????         |                     

        $sequence_2 = { e8???????? 4885c0 740a 488bcf ffd0 }
            // n = 5, score = 1300
            //   e8????????           |                     
            //   4885c0               | test                dl, dl
            //   740a                 | je                  7
            //   488bcf               | cmp                 dl, 0x2e
            //   ffd0                 | jne                 0x16

        $sequence_3 = { 488d4d80 e8???????? 498bd6 488d4d80 }
            // n = 4, score = 1100
            //   488d4d80             | js                  0xe
            //   e8????????           |                     
            //   498bd6               | dec                 eax
            //   488d4d80             | cwde                

        $sequence_4 = { 0fb70f ff15???????? 0fb74f02 0fb7d8 }
            // n = 4, score = 1100
            //   0fb70f               | dec                 eax
            //   ff15????????         |                     
            //   0fb74f02             | mov                 ecx, esi
            //   0fb7d8               | dec                 eax

        $sequence_5 = { 0fb74f02 0fb7d8 ff15???????? 0fb74f08 }
            // n = 4, score = 1100
            //   0fb74f02             | dec                 eax
            //   0fb7d8               | sub                 ecx, 0xc0
            //   ff15????????         |                     
            //   0fb74f08             | dec                 eax

        $sequence_6 = { 7507 33c0 e9???????? b8ff000000 }
            // n = 4, score = 1000
            //   7507                 | jne                 9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   b8ff000000           | mov                 eax, 0xff

        $sequence_7 = { ff15???????? 0fb74f08 440fb7e8 ff15???????? }
            // n = 4, score = 1000
            //   ff15????????         |                     
            //   0fb74f08             | dec                 eax
            //   440fb7e8             | mov                 dword ptr [esp + 0x28], eax
            //   ff15????????         |                     

        $sequence_8 = { c3 0fb74c0818 b80b010000 663bc8 }
            // n = 4, score = 900
            //   c3                   | mov                 dword ptr [esp + 0x20], eax
            //   0fb74c0818           | test                eax, eax
            //   b80b010000           | js                  0x16
            //   663bc8               | test                eax, eax

        $sequence_9 = { cc e8???????? cc 4053 4883ec20 b902000000 }
            // n = 6, score = 900
            //   cc                   | mov                 ecx, esi
            //   e8????????           |                     
            //   cc                   | dec                 eax
            //   4053                 | mov                 dword ptr [esp + 0x20], eax
            //   4883ec20             | test                eax, eax
            //   b902000000           | js                  0xc

        $sequence_10 = { 4885c9 7406 488b11 ff5210 ff15???????? }
            // n = 5, score = 900
            //   4885c9               | dec                 eax
            //   7406                 | mov                 ecx, esi
            //   488b11               | dec                 eax
            //   ff5210               | mov                 dword ptr [esp + 0x20], eax
            //   ff15????????         |                     

        $sequence_11 = { e8???????? 4c89e1 e8???????? 8b05???????? }
            // n = 4, score = 800
            //   e8????????           |                     
            //   4c89e1               | dec                 eax
            //   e8????????           |                     
            //   8b05????????         |                     

        $sequence_12 = { 4889f1 e8???????? 8b05???????? 8b0d???????? }
            // n = 4, score = 800
            //   4889f1               | dec                 eax
            //   e8????????           |                     
            //   8b05????????         |                     
            //   8b0d????????         |                     

        $sequence_13 = { 48c1e108 4803c8 8bc1 488d94059f070000 }
            // n = 4, score = 800
            //   48c1e108             | inc                 ebp
            //   4803c8               | xor                 ecx, ecx
            //   8bc1                 | dec                 eax
            //   488d94059f070000     | mov                 dword ptr [esp + 0x28], eax

        $sequence_14 = { ff15???????? ff15???????? 4d8bc5 33d2 }
            // n = 4, score = 800
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   4d8bc5               | mov                 ecx, esi
            //   33d2                 | dec                 eax

        $sequence_15 = { e8???????? 4889c7 8b05???????? 8b0d???????? }
            // n = 4, score = 800
            //   e8????????           |                     
            //   4889c7               | test                eax, eax
            //   8b05????????         |                     
            //   8b0d????????         |                     

        $sequence_16 = { 31ff 4889c1 31d2 4989f0 }
            // n = 4, score = 800
            //   31ff                 | dec                 eax
            //   4889c1               | arpl                word ptr [esp + 0x30], ax
            //   31d2                 | dec                 eax
            //   4989f0               | imul                eax, eax, 0x10

        $sequence_17 = { ff15???????? 4889c1 31d2 4d89e0 }
            // n = 4, score = 800
            //   ff15????????         |                     
            //   4889c1               | dec                 eax
            //   31d2                 | lea                 ecx, [0x238e3]
            //   4d89e0               | dec                 eax

        $sequence_18 = { 488d95a0070000 488d442470 41b80f100000 488bce }
            // n = 4, score = 800
            //   488d95a0070000       | js                  0x16
            //   488d442470           | dec                 eax
            //   41b80f100000         | cwde                
            //   488bce               | dec                 eax

        $sequence_19 = { 4c89742440 4c89742438 4489742430 4c89742428 }
            // n = 4, score = 800
            //   4c89742440           | mov                 eax, 0x100f
            //   4c89742438           | dec                 eax
            //   4489742430           | mov                 ecx, esi
            //   4c89742428           | dec                 eax

        $sequence_20 = { 418d5508 488bc8 ff15???????? 488bd8 4885c0 }
            // n = 5, score = 800
            //   418d5508             | mov                 dword ptr [esp + 0x20], eax
            //   488bc8               | dec                 eax
            //   ff15????????         |                     
            //   488bd8               | mov                 dword ptr [esp + 0x28], eax
            //   4885c0               | dec                 eax

        $sequence_21 = { 488d9590050000 488bce ff15???????? 85c0 }
            // n = 4, score = 800
            //   488d9590050000       | dec                 eax
            //   488bce               | cwde                
            //   ff15????????         |                     
            //   85c0                 | dec                 eax

        $sequence_22 = { 4533c9 4889442428 488d95a0070000 488d442470 }
            // n = 4, score = 800
            //   4533c9               | mov                 ecx, esi
            //   4889442428           | dec                 eax
            //   488d95a0070000       | mov                 dword ptr [esp + 0x20], eax
            //   488d442470           | test                eax, eax

        $sequence_23 = { 4889c1 31d2 4989f8 41ffd6 }
            // n = 4, score = 700
            //   4889c1               | je                  0x62
            //   31d2                 | dec                 eax
            //   4989f8               | mov                 eax, dword ptr [esp + 0x30]
            //   41ffd6               | dec                 eax

        $sequence_24 = { 488bd3 e8???????? ff15???????? 4c8bc3 33d2 488bc8 }
            // n = 6, score = 700
            //   488bd3               | lea                 eax, [esp + 0x70]
            //   e8????????           |                     
            //   ff15????????         |                     
            //   4c8bc3               | inc                 ecx
            //   33d2                 | mov                 eax, 0x100f
            //   488bc8               | dec                 eax

        $sequence_25 = { 85c8 0f94c0 833d????????0a 0f9cc1 84c1 7508 30c1 }
            // n = 7, score = 700
            //   85c8                 | cwde                
            //   0f94c0               | mov                 eax, 6
            //   833d????????0a       |                     
            //   0f9cc1               | inc                 esp
            //   84c1                 | mov                 ecx, dword ptr [edi + 0x54]
            //   7508                 | dec                 esp
            //   30c1                 | mov                 eax, esi

        $sequence_26 = { c744242800000001 4533c9 4533c0 c744242002000000 }
            // n = 4, score = 700
            //   c744242800000001     | jne                 6
            //   4533c9               | movzx               edx, byte ptr [ebx + 5]
            //   4533c0               | xor                 eax, eax
            //   c744242002000000     | cmp                 cl, 0x73

        $sequence_27 = { c744242880000000 c744242003000000 4889f9 ba00000080 41b801000000 }
            // n = 5, score = 700
            //   c744242880000000     | je                  0xc
            //   c744242003000000     | mov                 edx, 2
            //   4889f9               | dec                 eax
            //   ba00000080           | mov                 ecx, esi
            //   41b801000000         | call                eax

        $sequence_28 = { 0fb65305 33c0 80f973 0f94c0 }
            // n = 4, score = 700
            //   0fb65305             | dec                 eax
            //   33c0                 | mov                 ecx, esi
            //   80f973               | dec                 eax
            //   0f94c0               | mov                 dword ptr [esp + 0x20], eax

        $sequence_29 = { 08c1 80f101 7502 ebfe }
            // n = 4, score = 700
            //   08c1                 | inc                 ebp
            //   80f101               | xor                 ecx, ecx
            //   7502                 | dec                 eax
            //   ebfe                 | mov                 dword ptr [esp + 0x30], 0

        $sequence_30 = { 08ca 80f201 7502 ebfe }
            // n = 4, score = 700
            //   08ca                 | mov                 ecx, edi
            //   80f201               | mov                 edx, 0x80000000
            //   7502                 | inc                 ecx
            //   ebfe                 | mov                 eax, 1

        $sequence_31 = { 0f9fc1 38d3 7507 08c1 80f101 744d }
            // n = 6, score = 700
            //   0f9fc1               | xor                 edx, edx
            //   38d3                 | dec                 ecx
            //   7507                 | mov                 eax, ebx
            //   08c1                 | xor                 ebp, ebp
            //   80f101               | dec                 eax
            //   744d                 | mov                 ecx, eax

        $sequence_32 = { 89d1 83f1fe 85d1 0f95c2 833d????????09 0f9fc1 89cb }
            // n = 7, score = 700
            //   89d1                 | js                  0x16
            //   83f1fe               | inc                 ecx
            //   85d1                 | mov                 eax, 0x100f
            //   0f95c2               | dec                 eax
            //   833d????????09       |                     
            //   0f9fc1               | mov                 ecx, esi
            //   89cb                 | dec                 eax

        $sequence_33 = { ff15???????? 488bf8 4885c0 7533 }
            // n = 4, score = 700
            //   ff15????????         |                     
            //   488bf8               | jne                 0xc
            //   4885c0               | movzx               edx, cl
            //   7533                 | cmp                 cl, 0x73

        $sequence_34 = { 89c1 83f1fe 85c1 0f94c0 }
            // n = 4, score = 700
            //   89c1                 | dec                 eax
            //   83f1fe               | mov                 ecx, dword ptr [esp + 0x50]
            //   85c1                 | inc                 ebp
            //   0f94c0               | xor                 eax, eax

        $sequence_35 = { 89d1 83f1fe 85d1 0f94c2 833d????????0a 0f9cc1 89cb }
            // n = 7, score = 700
            //   89d1                 | mov                 dword ptr [esp + 0x20], eax
            //   83f1fe               | test                eax, eax
            //   85d1                 | dec                 eax
            //   0f94c2               | mov                 ecx, esi
            //   833d????????0a       |                     
            //   0f9cc1               | dec                 eax
            //   89cb                 | mov                 dword ptr [esp + 0x20], eax

        $sequence_36 = { ff15???????? 31ed 4889c1 31d2 }
            // n = 4, score = 700
            //   ff15????????         |                     
            //   31ed                 | add                 ecx, eax
            //   4889c1               | dec                 eax
            //   31d2                 | mov                 eax, ecx

        $sequence_37 = { 0fb64b04 0fb6d1 80f973 7504 0fb65305 33c0 }
            // n = 6, score = 700
            //   0fb64b04             | dec                 eax
            //   0fb6d1               | mov                 dword ptr [esp + 0x20], eax
            //   80f973               | test                eax, eax
            //   7504                 | js                  0xe
            //   0fb65305             | dec                 eax
            //   33c0                 | cwde                

        $sequence_38 = { 0f9fc1 83fa0a 0f9cc2 30da 7512 08c1 80f101 }
            // n = 7, score = 700
            //   0f9fc1               | mov                 ecx, edi
            //   83fa0a               | mov                 edx, 0x80000000
            //   0f9cc2               | inc                 ecx
            //   30da                 | mov                 eax, 1
            //   7512                 | xor                 ebp, ebp
            //   08c1                 | dec                 eax
            //   80f101               | mov                 ecx, eax

        $sequence_39 = { 4889c1 31d2 4989e8 ff15???????? }
            // n = 4, score = 600
            //   4889c1               | arpl                word ptr [esp + 0x30], ax
            //   31d2                 | dec                 eax
            //   4989e8               | imul                eax, eax, 0x10
            //   ff15????????         |                     

        $sequence_40 = { 4889c1 31d2 4d89f8 ffd3 }
            // n = 4, score = 600
            //   4889c1               | lea                 eax, [0x202a]
            //   31d2                 | dec                 eax
            //   4d89f8               | mov                 edx, dword ptr [esp + 0x28]
            //   ffd3                 | dec                 eax

        $sequence_41 = { e8???????? 4c897c2420 4889d9 89fa }
            // n = 4, score = 600
            //   e8????????           |                     
            //   4c897c2420           | dec                 eax
            //   4889d9               | add                 ecx, eax
            //   89fa                 | dec                 eax

        $sequence_42 = { 7405 80fa2e 750f 0fb6c1 }
            // n = 4, score = 600
            //   7405                 | test                eax, eax
            //   80fa2e               | js                  0x1c
            //   750f                 | dec                 eax
            //   0fb6c1               | sub                 ecx, 0xc0

        $sequence_43 = { 488d4c2428 e8???????? 4889f1 4889c2 }
            // n = 4, score = 500
            //   488d4c2428           | cmovg               eax, ecx
            //   e8????????           |                     
            //   4889f1               | cdq                 
            //   4889c2               | sub                 eax, edx

        $sequence_44 = { c744242880000000 c744242003000000 4889f1 ba00000080 }
            // n = 4, score = 500
            //   c744242880000000     | dec                 esp
            //   c744242003000000     | lea                 eax, [0x202a]
            //   4889f1               | dec                 eax
            //   ba00000080           | mov                 edx, dword ptr [esp + 0x28]

        $sequence_45 = { 4889fa 4189f0 4d89f1 ffd0 }
            // n = 4, score = 500
            //   4889fa               | mov                 eax, 0x10b
            //   4189f0               | cmp                 cx, ax
            //   4d89f1               | mov                 ecx, 0xe10
            //   ffd0                 | cmp                 eax, ecx

        $sequence_46 = { 6689442470 8d4833 ff15???????? c744242810000000 }
            // n = 4, score = 400
            //   6689442470           | je                  0xc
            //   8d4833               | dec                 eax
            //   ff15????????         |                     
            //   c744242810000000     | mov                 ecx, edi

        $sequence_47 = { 33d2 6a09 68fe6a7a69 42 e8???????? }
            // n = 5, score = 400
            //   33d2                 | xor                 edx, edx
            //   6a09                 | push                9
            //   68fe6a7a69           | push                0x697a6afe
            //   42                   | inc                 edx
            //   e8????????           |                     

        $sequence_48 = { 7506 8b0e 894c2460 0fb7c0 }
            // n = 4, score = 400
            //   7506                 | dec                 eax
            //   8b0e                 | cwde                
            //   894c2460             | dec                 eax
            //   0fb7c0               | test                eax, eax

        $sequence_49 = { 7512 83fe40 730d 896c846c 8b742468 46 }
            // n = 6, score = 400
            //   7512                 | jne                 0x14
            //   83fe40               | cmp                 esi, 0x40
            //   730d                 | jae                 0xf
            //   896c846c             | mov                 dword ptr [esp + eax*4 + 0x6c], ebp
            //   8b742468             | mov                 esi, dword ptr [esp + 0x68]
            //   46                   | inc                 esi

        $sequence_50 = { 0fb745e8 50 68???????? e8???????? }
            // n = 4, score = 400
            //   0fb745e8             | movzx               eax, word ptr [ebp - 0x18]
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_51 = { 50 e8???????? 83c404 33c0 33d2 40 8bc8 }
            // n = 7, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   33d2                 | xor                 edx, edx
            //   40                   | inc                 eax
            //   8bc8                 | mov                 ecx, eax

        $sequence_52 = { 66890d???????? 0fb7ca ff15???????? b901000000 66c746020100 }
            // n = 5, score = 400
            //   66890d????????       |                     
            //   0fb7ca               | js                  0x13
            //   ff15????????         |                     
            //   b901000000           | dec                 eax
            //   66c746020100         | cwde                

        $sequence_53 = { 75ef 21542440 6890010000 686a72995d 6a04 }
            // n = 5, score = 400
            //   75ef                 | jne                 0xfffffff1
            //   21542440             | and                 dword ptr [esp + 0x40], edx
            //   6890010000           | push                0x190
            //   686a72995d           | push                0x5d99726a
            //   6a04                 | push                4

        $sequence_54 = { 51 8bd6 e8???????? 59 59 85c0 }
            // n = 6, score = 400
            //   51                   | push                ecx
            //   8bd6                 | mov                 edx, esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_55 = { 33ff 32db 885c2410 c70601000000 eb35 81ffff030000 }
            // n = 6, score = 400
            //   33ff                 | xor                 edi, edi
            //   32db                 | xor                 bl, bl
            //   885c2410             | mov                 byte ptr [esp + 0x10], bl
            //   c70601000000         | mov                 dword ptr [esi], 1
            //   eb35                 | jmp                 0x37
            //   81ffff030000         | cmp                 edi, 0x3ff

        $sequence_56 = { 6a01 6a04 68???????? ff15???????? 8bf8 83ffff }
            // n = 6, score = 300
            //   6a01                 | push                1
            //   6a04                 | push                4
            //   68????????           |                     
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   83ffff               | cmp                 edi, -1

        $sequence_57 = { 81feff030000 733c 8a02 3cc0 721e }
            // n = 5, score = 300
            //   81feff030000         | cmp                 esi, 0x3ff
            //   733c                 | jae                 0x3e
            //   8a02                 | mov                 al, byte ptr [edx]
            //   3cc0                 | cmp                 al, 0xc0
            //   721e                 | jb                  0x20

        $sequence_58 = { 88041a 8bd1 41 3bcf }
            // n = 4, score = 300
            //   88041a               | mov                 byte ptr [edx + ebx], al
            //   8bd1                 | mov                 edx, ecx
            //   41                   | inc                 ecx
            //   3bcf                 | cmp                 ecx, edi

        $sequence_59 = { 0fb6c9 51 8bca c1f910 0fb6c1 50 8bc2 }
            // n = 7, score = 300
            //   0fb6c9               | movzx               ecx, cl
            //   51                   | push                ecx
            //   8bca                 | mov                 ecx, edx
            //   c1f910               | sar                 ecx, 0x10
            //   0fb6c1               | movzx               eax, cl
            //   50                   | push                eax
            //   8bc2                 | mov                 eax, edx

        $sequence_60 = { 2ac2 fec8 88041a 8bd1 }
            // n = 4, score = 300
            //   2ac2                 | sub                 al, dl
            //   fec8                 | dec                 al
            //   88041a               | mov                 byte ptr [edx + ebx], al
            //   8bd1                 | mov                 edx, ecx

        $sequence_61 = { 3cc0 721e 0fb6c8 0fb64201 }
            // n = 4, score = 300
            //   3cc0                 | cmp                 al, 0xc0
            //   721e                 | jb                  0x20
            //   0fb6c8               | movzx               ecx, al
            //   0fb64201             | movzx               eax, byte ptr [edx + 1]

        $sequence_62 = { 8d7001 8d4610 50 6a08 }
            // n = 4, score = 300
            //   8d7001               | lea                 esi, [eax + 1]
            //   8d4610               | lea                 eax, [esi + 0x10]
            //   50                   | push                eax
            //   6a08                 | push                8

        $sequence_63 = { 0fb70d???????? 83c40c 8d4101 51 66a3???????? }
            // n = 5, score = 300
            //   0fb70d????????       |                     
            //   83c40c               | add                 esp, 0xc
            //   8d4101               | lea                 eax, [ecx + 1]
            //   51                   | push                ecx
            //   66a3????????         |                     

        $sequence_64 = { 89442438 4863442430 486bc010 488d0de3380200 4803c8 488bc1 }
            // n = 6, score = 100
            //   89442438             | js                  0x16
            //   4863442430           | dec                 eax
            //   486bc010             | cwde                
            //   488d0de3380200       | dec                 eax
            //   4803c8               | mov                 ecx, esi
            //   488bc1               | dec                 eax

        $sequence_65 = { 7460 488b442430 488b00 8b4028 488b4c2440 4803c8 488bc1 }
            // n = 7, score = 100
            //   7460                 | cwde                
            //   488b442430           | inc                 ecx
            //   488b00               | mov                 eax, 0x100f
            //   8b4028               | dec                 eax
            //   488b4c2440           | mov                 ecx, esi
            //   4803c8               | dec                 eax
            //   488bc1               | mov                 dword ptr [esp + 0x20], eax

        $sequence_66 = { 4c8d052a200000 488b542428 488d4c2420 e8???????? 4889442430 ff542430 }
            // n = 6, score = 100
            //   4c8d052a200000       | mov                 dword ptr [esp + 0x20], eax
            //   488b542428           | test                eax, eax
            //   488d4c2420           | inc                 ecx
            //   e8????????           |                     
            //   4889442430           | mov                 eax, 0x100f
            //   ff542430             | dec                 eax

        $sequence_67 = { 48894c2408 4883ec48 8b442458 89442424 48c744242800000000 41b800100200 }
            // n = 6, score = 100
            //   48894c2408           | mov                 eax, ebx
            //   4883ec48             | dec                 eax
            //   8b442458             | mov                 ecx, esi
            //   89442424             | dec                 eax
            //   48c744242800000000     | mov    dword ptr [esp + 0x20], eax
            //   41b800100200         | test                eax, eax

        $sequence_68 = { 0f848c000000 488b442430 83782000 7460 488b442430 }
            // n = 5, score = 100
            //   0f848c000000         | inc                 ecx
            //   488b442430           | mov                 eax, 0x100f
            //   83782000             | dec                 eax
            //   7460                 | mov                 ecx, esi
            //   488b442430           | dec                 eax

        $sequence_69 = { 4533c0 ba01000000 488b4c2440 ff9424a0000000 89842480000000 }
            // n = 5, score = 100
            //   4533c0               | dec                 eax
            //   ba01000000           | mov                 ecx, esi
            //   488b4c2440           | dec                 eax
            //   ff9424a0000000       | mov                 dword ptr [esp + 0x20], eax
            //   89842480000000       | test                eax, eax

        $sequence_70 = { 488b442430 488b00 83782800 0f848c000000 488b442430 }
            // n = 5, score = 100
            //   488b442430           | js                  0x13
            //   488b00               | dec                 eax
            //   83782800             | cwde                
            //   0f848c000000         | inc                 ecx
            //   488b442430           | mov                 eax, 0x100f

        $sequence_71 = { 488d0de3380200 4803c8 488bc1 48634c2434 488d04c8 48634c2438 8b0488 }
            // n = 7, score = 100
            //   488d0de3380200       | cwde                
            //   4803c8               | dec                 eax
            //   488bc1               | mov                 ecx, esi
            //   48634c2434           | dec                 eax
            //   488d04c8             | mov                 dword ptr [esp + 0x20], eax
            //   48634c2438           | test                eax, eax
            //   8b0488               | js                  0x13

    condition:
        7 of them and filesize < 2088960
}
