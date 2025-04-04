rule win_silence_auto {

    meta:
        id = "64oI8CqW8H8vADfrdltYvp"
        fingerprint = "v1_sha256_20bb026c801a434e63744ede6d8b88ca9db1780c69681a4497ad49040c78c67b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.silence."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.silence"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 740a 8a4801 40 84c9 75f4 eb05 803800 }
            // n = 7, score = 1800
            //   740a                 | je                  0xc
            //   8a4801               | mov                 cl, byte ptr [eax + 1]
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75f4                 | jne                 0xfffffff6
            //   eb05                 | jmp                 7
            //   803800               | cmp                 byte ptr [eax], 0

        $sequence_1 = { e8???????? cc 8325????????00 c3 6a08 }
            // n = 5, score = 1800
            //   e8????????           |                     
            //   cc                   | int3                
            //   8325????????00       |                     
            //   c3                   | ret                 
            //   6a08                 | push                8

        $sequence_2 = { 6a00 8d45fc 50 6a00 6a00 68???????? c745fc00000000 }
            // n = 7, score = 1800
            //   6a00                 | push                0
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_3 = { 683f020f00 6a00 68???????? 6801000080 ff15???????? 68???????? }
            // n = 6, score = 1700
            //   683f020f00           | push                0xf023f
            //   6a00                 | push                0
            //   68????????           |                     
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_4 = { ff15???????? 6a00 6800000004 6a00 }
            // n = 4, score = 1600
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6800000004           | push                0x4000000
            //   6a00                 | push                0

        $sequence_5 = { 46 56 8d85f8feffff 50 }
            // n = 4, score = 1600
            //   46                   | inc                 esi
            //   56                   | push                esi
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax

        $sequence_6 = { f3c3 e9???????? e8???????? e9???????? 6a14 68???????? e8???????? }
            // n = 7, score = 1600
            //   f3c3                 | ret                 
            //   e9????????           |                     
            //   e8????????           |                     
            //   e9????????           |                     
            //   6a14                 | push                0x14
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_7 = { 68???????? ffd6 8b45fc 85c0 }
            // n = 4, score = 1600
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   85c0                 | test                eax, eax

        $sequence_8 = { 6801000080 ff15???????? 56 8d85f8feffff }
            // n = 4, score = 1600
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   56                   | push                esi
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]

        $sequence_9 = { 7408 8a5a01 42 84db }
            // n = 4, score = 1400
            //   7408                 | je                  0xa
            //   8a5a01               | mov                 bl, byte ptr [edx + 1]
            //   42                   | inc                 edx
            //   84db                 | test                bl, bl

        $sequence_10 = { 57 6800000004 6a00 6a00 }
            // n = 4, score = 1400
            //   57                   | push                edi
            //   6800000004           | push                0x4000000
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_11 = { 6a00 8bf8 6a00 57 ff15???????? 8d45fc }
            // n = 6, score = 1400
            //   6a00                 | push                0
            //   8bf8                 | mov                 edi, eax
            //   6a00                 | push                0
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8d45fc               | lea                 eax, [ebp - 4]

        $sequence_12 = { 5e 5b 5d c3 c60200 }
            // n = 5, score = 1400
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   c60200               | mov                 byte ptr [edx], 0

        $sequence_13 = { 84c9 75f4 eb0d 803800 7408 8a5a01 }
            // n = 6, score = 1400
            //   84c9                 | test                cl, cl
            //   75f4                 | jne                 0xfffffff6
            //   eb0d                 | jmp                 0xf
            //   803800               | cmp                 byte ptr [eax], 0
            //   7408                 | je                  0xa
            //   8a5a01               | mov                 bl, byte ptr [edx + 1]

        $sequence_14 = { ff30 c745fc00000000 57 ff15???????? }
            // n = 4, score = 1400
            //   ff30                 | push                dword ptr [eax]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_15 = { 6a00 8d8db4f7ffff 51 50 }
            // n = 4, score = 1200
            //   6a00                 | push                0
            //   8d8db4f7ffff         | lea                 ecx, [ebp - 0x84c]
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_16 = { ff15???????? 8d85b8f7ffff 50 6800080000 }
            // n = 4, score = 1200
            //   ff15????????         |                     
            //   8d85b8f7ffff         | lea                 eax, [ebp - 0x848]
            //   50                   | push                eax
            //   6800080000           | push                0x800

        $sequence_17 = { 03d7 3b56f0 7611 8b46ec 8d4eec }
            // n = 5, score = 1100
            //   03d7                 | add                 edx, edi
            //   3b56f0               | cmp                 edx, dword ptr [esi - 0x10]
            //   7611                 | jbe                 0x13
            //   8b46ec               | mov                 eax, dword ptr [esi - 0x14]
            //   8d4eec               | lea                 ecx, [esi - 0x14]

        $sequence_18 = { ff5004 8b46f8 0346f4 57 ff7508 }
            // n = 5, score = 1100
            //   ff5004               | call                dword ptr [eax + 4]
            //   8b46f8               | mov                 eax, dword ptr [esi - 8]
            //   0346f4               | add                 eax, dword ptr [esi - 0xc]
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_19 = { 7412 8b01 52 8d95f0fdffff 52 ff10 8b95ecfdffff }
            // n = 7, score = 1100
            //   7412                 | je                  0x14
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   52                   | push                edx
            //   8d95f0fdffff         | lea                 edx, [ebp - 0x210]
            //   52                   | push                edx
            //   ff10                 | call                dword ptr [eax]
            //   8b95ecfdffff         | mov                 edx, dword ptr [ebp - 0x214]

        $sequence_20 = { ff76f8 e8???????? 83c41c 895ef8 897ef0 5b 5f }
            // n = 7, score = 1100
            //   ff76f8               | push                dword ptr [esi - 8]
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   895ef8               | mov                 dword ptr [esi - 8], ebx
            //   897ef0               | mov                 dword ptr [esi - 0x10], edi
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi

        $sequence_21 = { ffd6 ff7704 ffd6 ff770c ffd6 ff7708 ffd6 }
            // n = 7, score = 1100
            //   ffd6                 | call                esi
            //   ff7704               | push                dword ptr [edi + 4]
            //   ffd6                 | call                esi
            //   ff770c               | push                dword ptr [edi + 0xc]
            //   ffd6                 | call                esi
            //   ff7708               | push                dword ptr [edi + 8]
            //   ffd6                 | call                esi

        $sequence_22 = { 50 e8???????? ff76f8 e8???????? }
            // n = 4, score = 1100
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff76f8               | push                dword ptr [esi - 8]
            //   e8????????           |                     

        $sequence_23 = { 8b17 8bcf ff5210 8b17 8bcf ff5208 }
            // n = 6, score = 1100
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   8bcf                 | mov                 ecx, edi
            //   ff5210               | call                dword ptr [edx + 0x10]
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   8bcf                 | mov                 ecx, edi
            //   ff5208               | call                dword ptr [edx + 8]

        $sequence_24 = { 898df8fbffff 8d8dfcfbffff 51 ffb5f0fbffff 8bcb ff5038 85c0 }
            // n = 7, score = 1100
            //   898df8fbffff         | mov                 dword ptr [ebp - 0x408], ecx
            //   8d8dfcfbffff         | lea                 ecx, [ebp - 0x404]
            //   51                   | push                ecx
            //   ffb5f0fbffff         | push                dword ptr [ebp - 0x410]
            //   8bcb                 | mov                 ecx, ebx
            //   ff5038               | call                dword ptr [eax + 0x38]
            //   85c0                 | test                eax, eax

        $sequence_25 = { ff15???????? ba180c0000 b940000000 ff15???????? }
            // n = 4, score = 500
            //   ff15????????         |                     
            //   ba180c0000           | dec                 eax
            //   b940000000           | lea                 ecx, [esp + 0x240]
            //   ff15????????         |                     

        $sequence_26 = { ff15???????? 488d542430 488d8c2440020000 ff15???????? }
            // n = 4, score = 500
            //   ff15????????         |                     
            //   488d542430           | dec                 eax
            //   488d8c2440020000     | lea                 edx, [esp + 0x30]
            //   ff15????????         |                     

        $sequence_27 = { e8???????? ba00040000 b940000000 ff15???????? }
            // n = 4, score = 500
            //   e8????????           |                     
            //   ba00040000           | shl                 eax, cl
            //   b940000000           | test                eax, eax
            //   ff15????????         |                     

        $sequence_28 = { 99 83e203 03c2 c1f802 89442440 }
            // n = 5, score = 500
            //   99                   | mov                 edx, 0xc18
            //   83e203               | mov                 ecx, 0x40
            //   03c2                 | cdq                 
            //   c1f802               | and                 edx, 3
            //   89442440             | add                 eax, edx

        $sequence_29 = { d3f8 0fb60d???????? d3e0 85c0 }
            // n = 4, score = 500
            //   d3f8                 | shl                 eax, cl
            //   0fb60d????????       |                     
            //   d3e0                 | add                 ecx, eax
            //   85c0                 | sar                 eax, cl

        $sequence_30 = { d3e8 0fb6c8 8b05???????? d3e0 }
            // n = 4, score = 500
            //   d3e8                 | sar                 eax, 2
            //   0fb6c8               | mov                 dword ptr [esp + 0x48], eax
            //   8b05????????         |                     
            //   d3e0                 | shr                 eax, cl

        $sequence_31 = { 8b05???????? d3e0 8b0d???????? 03c8 }
            // n = 4, score = 500
            //   8b05????????         |                     
            //   d3e0                 | movzx               ecx, al
            //   8b0d????????         |                     
            //   03c8                 | shl                 eax, cl

        $sequence_32 = { ff15???????? 41b804010000 488d542430 488d4c2430 ff15???????? 85c0 }
            // n = 6, score = 500
            //   ff15????????         |                     
            //   41b804010000         | mov                 edx, 0x400
            //   488d542430           | mov                 ecx, 0x40
            //   488d4c2430           | inc                 ecx
            //   ff15????????         |                     
            //   85c0                 | mov                 eax, 0x104

        $sequence_33 = { 55 8bec ff4d08 755d 833d????????04 }
            // n = 5, score = 400
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   ff4d08               | dec                 dword ptr [ebp + 8]
            //   755d                 | jne                 0x5f
            //   833d????????04       |                     

        $sequence_34 = { 85c0 750e 68???????? ff15???????? c20800 53 }
            // n = 6, score = 400
            //   85c0                 | test                eax, eax
            //   750e                 | jne                 0x10
            //   68????????           |                     
            //   ff15????????         |                     
            //   c20800               | ret                 8
            //   53                   | push                ebx

        $sequence_35 = { ff15???????? 68c0d40100 ff15???????? e9???????? }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   68c0d40100           | push                0x1d4c0
            //   ff15????????         |                     
            //   e9????????           |                     

        $sequence_36 = { 8b3d???????? 85c0 7507 68???????? ffd7 6a00 }
            // n = 6, score = 400
            //   8b3d????????         |                     
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   6a00                 | push                0

        $sequence_37 = { 8d0441 33d2 b905000000 f7f1 }
            // n = 4, score = 400
            //   8d0441               | lea                 eax, [ecx + eax*2]
            //   33d2                 | xor                 edx, edx
            //   b905000000           | mov                 ecx, 5
            //   f7f1                 | div                 ecx

        $sequence_38 = { c705????????00000000 c705????????03000000 c705????????00000000 c705????????04000000 ff15???????? 85c0 750b }
            // n = 7, score = 400
            //   c705????????00000000     |     
            //   c705????????03000000     |     
            //   c705????????00000000     |     
            //   c705????????04000000     |     
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750b                 | jne                 0xd

        $sequence_39 = { ff15???????? c20800 53 8b1d???????? 57 0f57c0 }
            // n = 6, score = 400
            //   ff15????????         |                     
            //   c20800               | ret                 8
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   57                   | push                edi
            //   0f57c0               | xorps               xmm0, xmm0

        $sequence_40 = { 750b 68???????? ff15???????? ff35???????? }
            // n = 4, score = 400
            //   750b                 | jne                 0xd
            //   68????????           |                     
            //   ff15????????         |                     
            //   ff35????????         |                     

        $sequence_41 = { 68???????? 68???????? ff15???????? a3???????? 85c0 750e }
            // n = 6, score = 400
            //   68????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   a3????????           |                     
            //   85c0                 | test                eax, eax
            //   750e                 | jne                 0x10

        $sequence_42 = { c705????????00000000 ffd3 8b3d???????? 85c0 }
            // n = 4, score = 400
            //   c705????????00000000     |     
            //   ffd3                 | call                ebx
            //   8b3d????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_43 = { 50 6a00 ff15???????? 6a00 6a00 68???????? }
            // n = 6, score = 200
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_44 = { 03048db0354200 50 ff15???????? 5d }
            // n = 4, score = 100
            //   03048db0354200       | add                 eax, dword ptr [ecx*4 + 0x4235b0]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   5d                   | pop                 ebp

        $sequence_45 = { 03048db0354200 eb05 b8???????? f6402820 }
            // n = 4, score = 100
            //   03048db0354200       | add                 eax, dword ptr [ecx*4 + 0x4235b0]
            //   eb05                 | jmp                 7
            //   b8????????           |                     
            //   f6402820             | test                byte ptr [eax + 0x28], 0x20

        $sequence_46 = { 03048db0354200 eb02 8bc6 80782900 }
            // n = 4, score = 100
            //   03048db0354200       | add                 eax, dword ptr [ecx*4 + 0x4235b0]
            //   eb02                 | jmp                 4
            //   8bc6                 | mov                 eax, esi
            //   80782900             | cmp                 byte ptr [eax + 0x29], 0

    condition:
        7 of them and filesize < 70128640
}
