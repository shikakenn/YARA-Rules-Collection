rule win_zloader_auto {

    meta:
        id = "4fSB97ZelM911S9t7VvX74"
        fingerprint = "v1_sha256_f3602cbba95531e02ba22e89ac5b5e6174a07dbda34c6d28cb18aded5d257e41"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.zloader."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zloader"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0fb7c0 57 50 53 e8???????? 83c40c }
            // n = 6, score = 2000
            //   0fb7c0               | xor                 ebx, ebx
            //   57                   | mov                 eax, ebx
            //   50                   | add                 esp, 0xc
            //   53                   | pop                 esi
            //   e8????????           |                     
            //   83c40c               | pop                 ebx

        $sequence_1 = { 6aff ff7514 e8???????? 83c40c 84c0 7424 }
            // n = 6, score = 2000
            //   6aff                 | pop                 esi
            //   ff7514               | pop                 edi
            //   e8????????           |                     
            //   83c40c               | je                  0x22
            //   84c0                 | test                al, al
            //   7424                 | je                  0x19

        $sequence_2 = { 0fb7450c 8d9df0feffff 53 50 ff7508 e8???????? 83c40c }
            // n = 7, score = 2000
            //   0fb7450c             | movzx               eax, ax
            //   8d9df0feffff         | push                edi
            //   53                   | push                eax
            //   50                   | push                ebx
            //   ff7508               | add                 esp, 0xc
            //   e8????????           |                     
            //   83c40c               | movzx               eax, word ptr [ebp + 0xc]

        $sequence_3 = { 31db 89d8 83c40c 5e 5b }
            // n = 5, score = 2000
            //   31db                 | mov                 eax, ebx
            //   89d8                 | add                 esp, 0x104
            //   83c40c               | xor                 ebx, ebx
            //   5e                   | lea                 ecx, [ebp - 0x110]
            //   5b                   | mov                 eax, ebx

        $sequence_4 = { 6a00 e8???????? 83c408 ff75f0 }
            // n = 4, score = 2000
            //   6a00                 | push                dword ptr [ebp + 0x14]
            //   e8????????           |                     
            //   83c408               | add                 esp, 0xc
            //   ff75f0               | test                al, al

        $sequence_5 = { 7420 e8???????? 84c0 7417 e8???????? }
            // n = 5, score = 2000
            //   7420                 | lea                 ecx, [ebp - 0x110]
            //   e8????????           |                     
            //   84c0                 | mov                 eax, ebx
            //   7417                 | add                 esp, 0x104
            //   e8????????           |                     

        $sequence_6 = { 31db 8d8df0feffff e8???????? 89d8 81c404010000 }
            // n = 5, score = 2000
            //   31db                 | mov                 dword ptr [esp], esi
            //   8d8df0feffff         | mov                 edi, ecx
            //   e8????????           |                     
            //   89d8                 | lea                 eax, [esi + esi*2]
            //   81c404010000         | mov                 dword ptr [ebp - 0x14], eax

        $sequence_7 = { 50 ff7508 53 e8???????? 83c40c 66c7047b0000 }
            // n = 6, score = 2000
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   53                   | add                 esp, 0xc
            //   e8????????           |                     
            //   83c40c               | push                ebx
            //   66c7047b0000         | push                edi

        $sequence_8 = { 56 50 a1???????? 89c1 }
            // n = 4, score = 1300
            //   56                   | push                eax
            //   50                   | mov                 eax, dword ptr [ebp + 8]
            //   a1????????           |                     
            //   89c1                 | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_9 = { e8???????? 89c1 89f0 99 f7f9 }
            // n = 5, score = 1100
            //   e8????????           |                     
            //   89c1                 | mov                 ecx, eax
            //   89f0                 | mov                 eax, esi
            //   99                   | cdq                 
            //   f7f9                 | idiv                ecx

        $sequence_10 = { e8???????? eb00 eb00 eb00 eb00 eb00 eb00 }
            // n = 7, score = 800
            //   e8????????           |                     
            //   eb00                 | jmp                 2
            //   eb00                 | jmp                 2
            //   eb00                 | jmp                 2
            //   eb00                 | jmp                 2
            //   eb00                 | jmp                 2
            //   eb00                 | jmp                 2

        $sequence_11 = { e8???????? 83f800 0f94c0 2401 }
            // n = 4, score = 800
            //   e8????????           |                     
            //   83f800               | cmp                 eax, 0
            //   0f94c0               | sete                al
            //   2401                 | and                 al, 1

        $sequence_12 = { e8???????? a801 7502 eb0f }
            // n = 4, score = 800
            //   e8????????           |                     
            //   a801                 | test                al, 1
            //   7502                 | jne                 4
            //   eb0f                 | jmp                 0x11

        $sequence_13 = { e8???????? 0fb700 3d64860000 0f94c0 2401 }
            // n = 5, score = 800
            //   e8????????           |                     
            //   0fb700               | movzx               eax, word ptr [eax]
            //   3d64860000           | cmp                 eax, 0x8664
            //   0f94c0               | sete                al
            //   2401                 | and                 al, 1

        $sequence_14 = { e8???????? ffd0 488905???????? b001 2401 0fb6c0 }
            // n = 6, score = 800
            //   e8????????           |                     
            //   ffd0                 | call                eax
            //   488905????????       |                     
            //   b001                 | mov                 al, 1
            //   2401                 | and                 al, 1
            //   0fb6c0               | movzx               eax, al

        $sequence_15 = { e8???????? 88c1 31c0 f6c101 }
            // n = 4, score = 800
            //   e8????????           |                     
            //   88c1                 | mov                 cl, al
            //   31c0                 | xor                 eax, eax
            //   f6c101               | test                cl, 1

        $sequence_16 = { 41b802000000 e8???????? a801 7505 e9???????? }
            // n = 5, score = 800
            //   41b802000000         | push                eax
            //   e8????????           |                     
            //   a801                 | inc                 ecx
            //   7505                 | mov                 eax, 2
            //   e9????????           |                     

        $sequence_17 = { e8???????? 59 84c0 7432 68???????? }
            // n = 5, score = 700
            //   e8????????           |                     
            //   59                   | push                dword ptr [esp + 8]
            //   84c0                 | pop                 ecx
            //   7432                 | test                al, al
            //   68????????           |                     

        $sequence_18 = { 84c0 7432 68???????? ff742408 e8???????? 59 }
            // n = 6, score = 700
            //   84c0                 | cmp                 eax, -1
            //   7432                 | test                al, al
            //   68????????           |                     
            //   ff742408             | je                  0x34
            //   e8????????           |                     
            //   59                   | push                dword ptr [esp + 8]

        $sequence_19 = { 8bc3 5b c3 8b44240c 83f8ff 750a }
            // n = 6, score = 700
            //   8bc3                 | movzx               eax, al
            //   5b                   | mov                 eax, ebx
            //   c3                   | pop                 ebx
            //   8b44240c             | ret                 
            //   83f8ff               | mov                 eax, dword ptr [esp + 0xc]
            //   750a                 | cmp                 eax, -1

        $sequence_20 = { 57 56 50 8b4510 31db }
            // n = 5, score = 700
            //   57                   | mov                 edx, dword ptr [ebp + 0x10]
            //   56                   | lea                 esi, [ebp + 0x14]
            //   50                   | push                esi
            //   8b4510               | push                eax
            //   31db                 | mov                 ecx, eax

        $sequence_21 = { 89542444 e8???????? 03c0 6689442438 8b442438 }
            // n = 5, score = 600
            //   89542444             | push                eax
            //   e8????????           |                     
            //   03c0                 | mov                 dword ptr [esp + 0x44], edx
            //   6689442438           | add                 eax, eax
            //   8b442438             | mov                 word ptr [esp + 0x38], ax

        $sequence_22 = { 6aff 50 e8???????? 8d857cffffff 50 }
            // n = 5, score = 600
            //   6aff                 | mov                 word ptr [esp + 0x38], ax
            //   50                   | push                -1
            //   e8????????           |                     
            //   8d857cffffff         | push                eax
            //   50                   | lea                 eax, [ebp - 0x84]

        $sequence_23 = { 50 56 56 56 ff7514 }
            // n = 5, score = 600
            //   50                   | cmp                 edi, -1
            //   56                   | push                eax
            //   56                   | push                esi
            //   56                   | push                esi
            //   ff7514               | push                esi

        $sequence_24 = { 5f c6043000 5e c3 56 57 8b7c2414 }
            // n = 7, score = 600
            //   5f                   | add                 esp, 0x24
            //   c6043000             | pop                 edi
            //   5e                   | mov                 byte ptr [eax + esi], 0
            //   c3                   | pop                 esi
            //   56                   | ret                 
            //   57                   | push                esi
            //   8b7c2414             | push                edi

        $sequence_25 = { 6689442438 8b442438 83c002 668944243a }
            // n = 4, score = 600
            //   6689442438           | add                 eax, 2
            //   8b442438             | mov                 word ptr [esp + 0x38], ax
            //   83c002               | mov                 eax, dword ptr [esp + 0x38]
            //   668944243a           | add                 eax, 2

        $sequence_26 = { e8???????? 83c414 c3 56 ff742410 }
            // n = 5, score = 600
            //   e8????????           |                     
            //   83c414               | mov                 word ptr [esp + 0x3a], ax
            //   c3                   | add                 esp, 0x14
            //   56                   | ret                 
            //   ff742410             | push                esi

        $sequence_27 = { 50 8d44243c 99 52 50 }
            // n = 5, score = 600
            //   50                   | push                dword ptr [esp + 8]
            //   8d44243c             | push                eax
            //   99                   | lea                 eax, [esp + 0x3c]
            //   52                   | cdq                 
            //   50                   | push                edx

        $sequence_28 = { 83c410 84c0 741f 8b45c8 3b4604 7617 }
            // n = 6, score = 500
            //   83c410               | push                dword ptr [esp + 0x10]
            //   84c0                 | add                 esp, 0x10
            //   741f                 | test                al, al
            //   8b45c8               | je                  0x21
            //   3b4604               | mov                 eax, dword ptr [ebp - 0x38]
            //   7617                 | cmp                 eax, dword ptr [esi + 4]

        $sequence_29 = { 81c614010000 8dbd78feffff f3a5 8d8578feffff 50 ff75fc 66a5 }
            // n = 7, score = 500
            //   81c614010000         | jbe                 0x19
            //   8dbd78feffff         | add                 esi, 0x114
            //   f3a5                 | lea                 edi, [ebp - 0x188]
            //   8d8578feffff         | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   50                   | lea                 eax, [ebp - 0x188]
            //   ff75fc               | push                eax
            //   66a5                 | push                dword ptr [ebp - 4]

        $sequence_30 = { 89e5 53 57 56 81eca8020000 }
            // n = 5, score = 500
            //   89e5                 | add                 esp, 0x2a8
            //   53                   | pop                 esi
            //   57                   | pop                 edi
            //   56                   | pop                 ebx
            //   81eca8020000         | mov                 ebp, esp

        $sequence_31 = { c7460488130000 c7462401000000 c7462800004001 e8???????? }
            // n = 4, score = 500
            //   c7460488130000       | mov                 edx, dword ptr [esp + 4]
            //   c7462401000000       | mov                 dword ptr [esi + 4], 0x1388
            //   c7462800004001       | mov                 dword ptr [esi + 0x24], 1
            //   e8????????           |                     

        $sequence_32 = { 57 56 83ec18 89d6 89cf }
            // n = 5, score = 400
            //   57                   | push                ebx
            //   56                   | push                edi
            //   83ec18               | push                esi
            //   89d6                 | sub                 esp, 0x2a8
            //   89cf                 | push                edi

        $sequence_33 = { 890424 c74424041c010000 e8???????? c74424101c010000 893424 }
            // n = 5, score = 400
            //   890424               | mov                 dword ptr [esp], eax
            //   c74424041c010000     | mov                 dword ptr [ebp - 0x14], eax
            //   e8????????           |                     
            //   c74424101c010000     | mov                 dword ptr [esp], eax
            //   893424               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_34 = { 8d742410 89b42430010000 8b842430010000 8b842430010000 890424 }
            // n = 5, score = 400
            //   8d742410             | ret                 
            //   89b42430010000       | push                ecx
            //   8b842430010000       | mov                 eax, dword ptr fs:[0x30]
            //   8b842430010000       | mov                 dword ptr [esp], eax
            //   890424               | lea                 esi, [esp + 0x10]

        $sequence_35 = { 8945ec 890424 e8???????? 8945f0 }
            // n = 4, score = 400
            //   8945ec               | mov                 dword ptr [esp + 0x130], esi
            //   890424               | mov                 eax, dword ptr [esp + 0x130]
            //   e8????????           |                     
            //   8945f0               | mov                 eax, dword ptr [esp + 0x130]

        $sequence_36 = { 57 50 e8???????? 68???????? 56 e8???????? }
            // n = 6, score = 300
            //   57                   | push                eax
            //   50                   | push                edi
            //   e8????????           |                     
            //   68????????           |                     
            //   56                   | push                eax
            //   e8????????           |                     

        $sequence_37 = { 56 57 ff750c 33db 68???????? 6880000000 }
            // n = 6, score = 300
            //   56                   | je                  0x34
            //   57                   | push                esi
            //   ff750c               | push                edi
            //   33db                 | push                dword ptr [ebp + 0xc]
            //   68????????           |                     
            //   6880000000           | xor                 ebx, ebx

        $sequence_38 = { c3 8bc2 ebf7 8d442410 50 ff742410 }
            // n = 6, score = 300
            //   c3                   | mov                 ebx, dword ptr [esp + 0xc]
            //   8bc2                 | ret                 
            //   ebf7                 | mov                 eax, edx
            //   8d442410             | jmp                 0xfffffff9
            //   50                   | lea                 eax, [esp + 0x10]
            //   ff742410             | push                eax

        $sequence_39 = { 33db 68???????? 6880000000 50 e8???????? 83c410 8d4580 }
            // n = 7, score = 300
            //   33db                 | xor                 ebx, ebx
            //   68????????           |                     
            //   6880000000           | xor                 ebx, ebx
            //   50                   | push                0x80
            //   e8????????           |                     
            //   83c410               | push                eax
            //   8d4580               | add                 esp, 0x10

        $sequence_40 = { 68???????? ff742410 e8???????? 6823af2930 56 ff742410 }
            // n = 6, score = 300
            //   68????????           |                     
            //   ff742410             | push                0x80
            //   e8????????           |                     
            //   6823af2930           | push                dword ptr [esp + 0x10]
            //   56                   | push                0x3029af23
            //   ff742410             | push                esi

        $sequence_41 = { e8???????? ff7508 8d85f0fdffff 68???????? 6804010000 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   ff7508               | push                dword ptr [esp + 0x10]
            //   8d85f0fdffff         | push                dword ptr [ebp + 8]
            //   68????????           |                     
            //   6804010000           | lea                 eax, [ebp - 0x210]

        $sequence_42 = { e8???????? 83c40c 5e 8bc3 5b c3 8b4c2404 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   83c40c               | push                dword ptr [esp + 0x10]
            //   5e                   | add                 esp, 0xc
            //   8bc3                 | pop                 esi
            //   5b                   | mov                 eax, ebx
            //   c3                   | pop                 ebx
            //   8b4c2404             | ret                 

        $sequence_43 = { c3 56 8b742408 6804010000 68???????? }
            // n = 5, score = 300
            //   c3                   | push                eax
            //   56                   | ret                 
            //   8b742408             | push                esi
            //   6804010000           | mov                 esi, dword ptr [esp + 8]
            //   68????????           |                     

        $sequence_44 = { c3 8bc2 ebf8 53 8b5c240c }
            // n = 5, score = 300
            //   c3                   | pop                 ecx
            //   8bc2                 | ret                 
            //   ebf8                 | mov                 eax, edx
            //   53                   | jmp                 0xfffffffa
            //   8b5c240c             | push                ebx

        $sequence_45 = { 50 6a72 e8???????? 59 59 }
            // n = 5, score = 300
            //   50                   | mov                 edx, dword ptr [esp + 4]
            //   6a72                 | push                eax
            //   e8????????           |                     
            //   59                   | push                0x72
            //   59                   | pop                 ecx

        $sequence_46 = { 894c2424 890b 56 8944241c }
            // n = 4, score = 200
            //   894c2424             | cmp                 word ptr [ebx], bp
            //   890b                 | mov                 dword ptr [esp + 0x24], ecx
            //   56                   | mov                 dword ptr [ebx], ecx
            //   8944241c             | push                esi

    condition:
        7 of them and filesize < 5360640
}
