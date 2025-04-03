rule win_vidar_auto {

    meta:
        id = "35Vgb41Th5cKpkdPoFAuLa"
        fingerprint = "v1_sha256_78072c96fd4e60233539f368a83645e6e3c45bf8d23ede4d4f8a97936d6b546c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.vidar."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 05c39e2600 894114 c1e810 25ff7f0000 c3 e8???????? 8b486c }
            // n = 7, score = 2600
            //   05c39e2600           | add                 eax, 0x269ec3
            //   894114               | mov                 dword ptr [ecx + 0x14], eax
            //   c1e810               | shr                 eax, 0x10
            //   25ff7f0000           | and                 eax, 0x7fff
            //   c3                   | ret                 
            //   e8????????           |                     
            //   8b486c               | mov                 ecx, dword ptr [eax + 0x6c]

        $sequence_1 = { 7202 8b00 8d8d68fdffff 51 50 }
            // n = 5, score = 2500
            //   7202                 | jb                  4
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8d8d68fdffff         | lea                 ecx, [ebp - 0x298]
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_2 = { 8b7508 33db 895dd0 c746140f000000 895e10 8975cc }
            // n = 6, score = 2400
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33db                 | xor                 ebx, ebx
            //   895dd0               | mov                 dword ptr [ebp - 0x30], ebx
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   895e10               | mov                 dword ptr [esi + 0x10], ebx
            //   8975cc               | mov                 dword ptr [ebp - 0x34], esi

        $sequence_3 = { 8b8648af0100 c1e803 038644af0100 5e 5d c3 }
            // n = 6, score = 2400
            //   8b8648af0100         | mov                 eax, dword ptr [esi + 0x1af48]
            //   c1e803               | shr                 eax, 3
            //   038644af0100         | add                 eax, dword ptr [esi + 0x1af44]
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_4 = { 5f c6043300 8bc6 5e 5b c20400 }
            // n = 6, score = 2400
            //   5f                   | pop                 edi
            //   c6043300             | mov                 byte ptr [ebx + esi], 0
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c20400               | ret                 4

        $sequence_5 = { 89b55cfdffff 89bd60fdffff 8d450c 50 }
            // n = 4, score = 2400
            //   89b55cfdffff         | mov                 dword ptr [ebp - 0x2a4], esi
            //   89bd60fdffff         | mov                 dword ptr [ebp - 0x2a0], edi
            //   8d450c               | lea                 eax, [ebp + 0xc]
            //   50                   | push                eax

        $sequence_6 = { d9e0 d99d00ffffff d98500ffffff d91c24 }
            // n = 4, score = 2400
            //   d9e0                 | fchs                
            //   d99d00ffffff         | fstp                dword ptr [ebp - 0x100]
            //   d98500ffffff         | fld                 dword ptr [ebp - 0x100]
            //   d91c24               | fstp                dword ptr [esp]

        $sequence_7 = { 740a b800000500 e9???????? 57 }
            // n = 4, score = 2400
            //   740a                 | je                  0xc
            //   b800000500           | mov                 eax, 0x50000
            //   e9????????           |                     
            //   57                   | push                edi

        $sequence_8 = { 895dfc e8???????? 83781408 c645fc01 }
            // n = 4, score = 2400
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   e8????????           |                     
            //   83781408             | cmp                 dword ptr [eax + 0x14], 8
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1

        $sequence_9 = { 8b7508 33ff 89b55cfdffff 89bd60fdffff }
            // n = 4, score = 2400
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33ff                 | xor                 edi, edi
            //   89b55cfdffff         | mov                 dword ptr [ebp - 0x2a4], esi
            //   89bd60fdffff         | mov                 dword ptr [ebp - 0x2a0], edi

        $sequence_10 = { 56 8b742408 8b865caf0100 57 }
            // n = 4, score = 2400
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   8b865caf0100         | mov                 eax, dword ptr [esi + 0x1af5c]
            //   57                   | push                edi

        $sequence_11 = { 5e c20400 ff742408 e8???????? 59 83f8ff 7503 }
            // n = 7, score = 2300
            //   5e                   | pop                 esi
            //   c20400               | ret                 4
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   83f8ff               | cmp                 eax, -1
            //   7503                 | jne                 5

        $sequence_12 = { c9 c3 8b542408 85d2 7503 33c0 c3 }
            // n = 7, score = 2300
            //   c9                   | leave               
            //   c3                   | ret                 
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   85d2                 | test                edx, edx
            //   7503                 | jne                 5
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 

        $sequence_13 = { 83781410 7202 8b00 50 8b45a0 }
            // n = 5, score = 2300
            //   83781410             | cmp                 dword ptr [eax + 0x14], 0x10
            //   7202                 | jb                  4
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   50                   | push                eax
            //   8b45a0               | mov                 eax, dword ptr [ebp - 0x60]

        $sequence_14 = { 50 ff15???????? 8b4da0 8901 }
            // n = 4, score = 2300
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4da0               | mov                 ecx, dword ptr [ebp - 0x60]
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_15 = { 53 68???????? 6802000080 ff15???????? 85c0 751b }
            // n = 6, score = 2300
            //   53                   | push                ebx
            //   68????????           |                     
            //   6802000080           | push                0x80000002
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   751b                 | jne                 0x1d

        $sequence_16 = { c1e004 8bf0 0fbe4301 50 }
            // n = 4, score = 2300
            //   c1e004               | shl                 eax, 4
            //   8bf0                 | mov                 esi, eax
            //   0fbe4301             | movsx               eax, byte ptr [ebx + 1]
            //   50                   | push                eax

        $sequence_17 = { 68???????? e8???????? 59 83f820 }
            // n = 4, score = 2200
            //   68????????           |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   83f820               | cmp                 eax, 0x20

        $sequence_18 = { 50 6a09 53 68???????? }
            // n = 4, score = 2200
            //   50                   | push                eax
            //   6a09                 | push                9
            //   53                   | push                ebx
            //   68????????           |                     

        $sequence_19 = { 50 0fb605???????? 50 6a01 }
            // n = 4, score = 2200
            //   50                   | push                eax
            //   0fb605????????       |                     
            //   50                   | push                eax
            //   6a01                 | push                1

        $sequence_20 = { 399e70af0600 7514 c78678af060001000000 c78670af060000000100 68fcff0100 8d8670af0400 }
            // n = 6, score = 2100
            //   399e70af0600         | cmp                 dword ptr [esi + 0x6af70], ebx
            //   7514                 | jne                 0x16
            //   c78678af060001000000     | mov    dword ptr [esi + 0x6af78], 1
            //   c78670af060000000100     | mov    dword ptr [esi + 0x6af70], 0x10000
            //   68fcff0100           | push                0x1fffc
            //   8d8670af0400         | lea                 eax, [esi + 0x4af70]

        $sequence_21 = { 53 50 899e6caf0600 e8???????? }
            // n = 4, score = 2100
            //   53                   | push                ebx
            //   50                   | push                eax
            //   899e6caf0600         | mov                 dword ptr [esi + 0x6af6c], ebx
            //   e8????????           |                     

        $sequence_22 = { 895df0 8d45f0 50 6a09 }
            // n = 4, score = 2100
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   6a09                 | push                9

        $sequence_23 = { 0fbe4301 50 8bc1 50 }
            // n = 4, score = 2100
            //   0fbe4301             | movsx               eax, byte ptr [ebx + 1]
            //   50                   | push                eax
            //   8bc1                 | mov                 eax, ecx
            //   50                   | push                eax

        $sequence_24 = { 53 68???????? 8d8da8000000 e8???????? }
            // n = 4, score = 2100
            //   53                   | push                ebx
            //   68????????           |                     
            //   8d8da8000000         | lea                 ecx, [ebp + 0xa8]
            //   e8????????           |                     

        $sequence_25 = { 741d ff75f0 ff15???????? 895df0 395df0 740c }
            // n = 6, score = 2100
            //   741d                 | je                  0x1f
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff15????????         |                     
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   395df0               | cmp                 dword ptr [ebp - 0x10], ebx
            //   740c                 | je                  0xe

        $sequence_26 = { 68fcff0100 8d8670af0400 53 50 }
            // n = 4, score = 2100
            //   68fcff0100           | push                0x1fffc
            //   8d8670af0400         | lea                 eax, [esi + 0x4af70]
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_27 = { c3 55 8bec 83ec0c 8365fc00 8365f400 8365f800 }
            // n = 7, score = 1900
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec0c               | sub                 esp, 0xc
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   8365f400             | and                 dword ptr [ebp - 0xc], 0
            //   8365f800             | and                 dword ptr [ebp - 8], 0

        $sequence_28 = { 8910 8b4120 8910 8b4130 8910 c3 56 }
            // n = 7, score = 1800
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b4120               | mov                 eax, dword ptr [ecx + 0x20]
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b4130               | mov                 eax, dword ptr [ecx + 0x30]
            //   8910                 | mov                 dword ptr [eax], edx
            //   c3                   | ret                 
            //   56                   | push                esi

        $sequence_29 = { 8d852cffffff 50 8d459c 50 }
            // n = 4, score = 1800
            //   8d852cffffff         | lea                 eax, [ebp - 0xd4]
            //   50                   | push                eax
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   50                   | push                eax

        $sequence_30 = { c20400 56 8bf1 e8???????? 6a00 ff74240c 8bce }
            // n = 7, score = 1800
            //   c20400               | ret                 4
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   8bce                 | mov                 ecx, esi

        $sequence_31 = { 0faf450c 50 e8???????? 59 }
            // n = 4, score = 1800
            //   0faf450c             | imul                eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_32 = { 8b4508 8906 8b450c 894608 8b4510 }
            // n = 5, score = 1800
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_33 = { e8???????? c9 c3 55 8bec 83ec18 8b450c }
            // n = 7, score = 1800
            //   e8????????           |                     
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec18               | sub                 esp, 0x18
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_34 = { 50 ff15???????? 6a1a e8???????? }
            // n = 4, score = 800
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a1a                 | push                0x1a
            //   e8????????           |                     

        $sequence_35 = { 6860ea0000 6a00 ff15???????? 50 ff15???????? }
            // n = 5, score = 800
            //   6860ea0000           | push                0xea60
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_36 = { ff15???????? 59 59 50 6a06 }
            // n = 5, score = 700
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   6a06                 | push                6

        $sequence_37 = { 5f c21000 8bff 55 8bec 6a0a 6a00 }
            // n = 7, score = 700
            //   5f                   | pop                 edi
            //   c21000               | ret                 0x10
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   6a0a                 | push                0xa
            //   6a00                 | push                0

        $sequence_38 = { e8???????? 83c410 85c0 7404 6a99 ebcc }
            // n = 6, score = 600
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   7404                 | je                  6
            //   6a99                 | push                -0x67
            //   ebcc                 | jmp                 0xffffffce

        $sequence_39 = { 83e03f 03d2 897110 894104 8911 5e c3 }
            // n = 7, score = 500
            //   83e03f               | and                 eax, 0x3f
            //   03d2                 | add                 edx, edx
            //   897110               | mov                 dword ptr [ecx + 0x10], esi
            //   894104               | mov                 dword ptr [ecx + 4], eax
            //   8911                 | mov                 dword ptr [ecx], edx
            //   5e                   | pop                 esi
            //   c3                   | ret                 

        $sequence_40 = { 80780800 7404 33c0 40 c3 33c0 }
            // n = 6, score = 500
            //   80780800             | cmp                 byte ptr [eax + 8], 0
            //   7404                 | je                  6
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax

        $sequence_41 = { dd1c24 83ec08 dd4508 dd1c24 6a0b 6a10 e8???????? }
            // n = 7, score = 200
            //   dd1c24               | fstp                qword ptr [esp]
            //   83ec08               | sub                 esp, 8
            //   dd4508               | fld                 qword ptr [ebp + 8]
            //   dd1c24               | fstp                qword ptr [esp]
            //   6a0b                 | push                0xb
            //   6a10                 | push                0x10
            //   e8????????           |                     

        $sequence_42 = { dd4508 dd1c24 6a0b 6a08 e8???????? 83c41c }
            // n = 6, score = 200
            //   dd4508               | fld                 qword ptr [ebp + 8]
            //   dd1c24               | fstp                qword ptr [esp]
            //   6a0b                 | push                0xb
            //   6a08                 | push                8
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c

        $sequence_43 = { eb0b 8b45f4 0500040000 8945f4 }
            // n = 4, score = 200
            //   eb0b                 | jmp                 0xd
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   0500040000           | add                 eax, 0x400
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

        $sequence_44 = { 8bc6 5e c3 56 8bf1 6a08 }
            // n = 6, score = 100
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   6a08                 | push                8

        $sequence_45 = { 8bc6 5e c20800 8b3f 85ff 7426 }
            // n = 6, score = 100
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c20800               | ret                 8
            //   8b3f                 | mov                 edi, dword ptr [edi]
            //   85ff                 | test                edi, edi
            //   7426                 | je                  0x28

        $sequence_46 = { 8bc6 5e c3 8b0a 80790d00 750c }
            // n = 6, score = 100
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   80790d00             | cmp                 byte ptr [ecx + 0xd], 0
            //   750c                 | jne                 0xe

    condition:
        7 of them and filesize < 4751360
}
