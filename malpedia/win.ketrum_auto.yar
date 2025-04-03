rule win_ketrum_auto {

    meta:
        id = "2DRArJzzDwWrp9ZEMGLeb4"
        fingerprint = "v1_sha256_f6a51a224da39f596220ff41861daa2df80eaaa43f4fe6e9b132d503abfda3ac"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.ketrum."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ketrum"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 037de0 8bda 8d8407e6cde121 c1c005 03c6 }
            // n = 5, score = 200
            //   037de0               | add                 edi, dword ptr [ebp - 0x20]
            //   8bda                 | mov                 ebx, edx
            //   8d8407e6cde121       | lea                 eax, [edi + eax + 0x21e1cde6]
            //   c1c005               | rol                 eax, 5
            //   03c6                 | add                 eax, esi

        $sequence_1 = { 33c0 57 0fb7d0 8bc2 6a20 c1e210 }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   57                   | push                edi
            //   0fb7d0               | movzx               edx, ax
            //   8bc2                 | mov                 eax, edx
            //   6a20                 | push                0x20
            //   c1e210               | shl                 edx, 0x10

        $sequence_2 = { 53 53 ff15???????? 53 53 6a03 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   6a03                 | push                3

        $sequence_3 = { c1f905 83e01f c1e006 8b0c8da0bc6200 8d440104 8020fe ff36 }
            // n = 7, score = 200
            //   c1f905               | sar                 ecx, 5
            //   83e01f               | and                 eax, 0x1f
            //   c1e006               | shl                 eax, 6
            //   8b0c8da0bc6200       | mov                 ecx, dword ptr [ecx*4 + 0x62bca0]
            //   8d440104             | lea                 eax, [ecx + eax + 4]
            //   8020fe               | and                 byte ptr [eax], 0xfe
            //   ff36                 | push                dword ptr [esi]

        $sequence_4 = { 7407 6a01 e8???????? 8d8534fbffff 50 }
            // n = 5, score = 200
            //   7407                 | je                  9
            //   6a01                 | push                1
            //   e8????????           |                     
            //   8d8534fbffff         | lea                 eax, [ebp - 0x4cc]
            //   50                   | push                eax

        $sequence_5 = { 53 50 e8???????? 56 8d85fce7ffff }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d85fce7ffff         | lea                 eax, [ebp - 0x1804]

        $sequence_6 = { 59 be???????? 8dbd7cffffff f3a5 6a43 8d45b9 53 }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   be????????           |                     
            //   8dbd7cffffff         | lea                 edi, [ebp - 0x84]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   6a43                 | push                0x43
            //   8d45b9               | lea                 eax, [ebp - 0x47]
            //   53                   | push                ebx

        $sequence_7 = { 59 85c0 742f b9???????? 8bc1 8d7001 8a10 }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   742f                 | je                  0x31
            //   b9????????           |                     
            //   8bc1                 | mov                 eax, ecx
            //   8d7001               | lea                 esi, [eax + 1]
            //   8a10                 | mov                 dl, byte ptr [eax]

        $sequence_8 = { e8???????? 83600400 eb23 6a03 8bf7 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83600400             | and                 dword ptr [eax + 4], 0
            //   eb23                 | jmp                 0x25
            //   6a03                 | push                3
            //   8bf7                 | mov                 esi, edi

        $sequence_9 = { 8b44241c 83c40c 837c242408 7302 8bc6 }
            // n = 5, score = 100
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   83c40c               | add                 esp, 0xc
            //   837c242408           | cmp                 dword ptr [esp + 0x24], 8
            //   7302                 | jae                 4
            //   8bc6                 | mov                 eax, esi

        $sequence_10 = { 6a01 33ff 8db590efffff c645fc00 e8???????? 33f6 39b344010000 }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   33ff                 | xor                 edi, edi
            //   8db590efffff         | lea                 esi, [ebp - 0x1070]
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   e8????????           |                     
            //   33f6                 | xor                 esi, esi
            //   39b344010000         | cmp                 dword ptr [ebx + 0x144], esi

        $sequence_11 = { e8???????? 83c410 8d8594e9ffff 50 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8d8594e9ffff         | lea                 eax, [ebp - 0x166c]
            //   50                   | push                eax

        $sequence_12 = { 0f87e9030000 ff248519574000 ff35???????? e9???????? }
            // n = 4, score = 100
            //   0f87e9030000         | ja                  0x3ef
            //   ff248519574000       | jmp                 dword ptr [eax*4 + 0x405719]
            //   ff35????????         |                     
            //   e9????????           |                     

        $sequence_13 = { d1f8 8bf8 8bc6 8bd6 }
            // n = 4, score = 100
            //   d1f8                 | sar                 eax, 1
            //   8bf8                 | mov                 edi, eax
            //   8bc6                 | mov                 eax, esi
            //   8bd6                 | mov                 edx, esi

        $sequence_14 = { 837db801 7621 6aff 57 8d45a8 8d7dcc }
            // n = 6, score = 100
            //   837db801             | cmp                 dword ptr [ebp - 0x48], 1
            //   7621                 | jbe                 0x23
            //   6aff                 | push                -1
            //   57                   | push                edi
            //   8d45a8               | lea                 eax, [ebp - 0x58]
            //   8d7dcc               | lea                 edi, [ebp - 0x34]

        $sequence_15 = { 39b8c0f94100 0f8491000000 ff45e4 83c030 3df0000000 }
            // n = 5, score = 100
            //   39b8c0f94100         | cmp                 dword ptr [eax + 0x41f9c0], edi
            //   0f8491000000         | je                  0x97
            //   ff45e4               | inc                 dword ptr [ebp - 0x1c]
            //   83c030               | add                 eax, 0x30
            //   3df0000000           | cmp                 eax, 0xf0

    condition:
        7 of them and filesize < 4599808
}
