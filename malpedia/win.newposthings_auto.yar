rule win_newposthings_auto {

    meta:
        id = "3XLiZsV1XuWbk7eyUxRnis"
        fingerprint = "v1_sha256_fee15bf490538f6a36053584f37721547efa8e7cc1e683e754b3484ec8de6c80"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.newposthings."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newposthings"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 8bcf e8???????? 8bf0 c645fc04 68dcc40110 8d55d4 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   68dcc40110           | push                0x1001c4dc
            //   8d55d4               | lea                 edx, [ebp - 0x2c]

        $sequence_1 = { 83e11f 8b048538f34500 c1e106 0fbe440804 83e040 5d }
            // n = 6, score = 100
            //   83e11f               | and                 ecx, 0x1f
            //   8b048538f34500       | mov                 eax, dword ptr [eax*4 + 0x45f338]
            //   c1e106               | shl                 ecx, 6
            //   0fbe440804           | movsx               eax, byte ptr [eax + ecx + 4]
            //   83e040               | and                 eax, 0x40
            //   5d                   | pop                 ebp

        $sequence_2 = { ebb4 c745e4141d0210 a1???????? eb1a c745e4101d0210 a1???????? eb0c }
            // n = 7, score = 100
            //   ebb4                 | jmp                 0xffffffb6
            //   c745e4141d0210       | mov                 dword ptr [ebp - 0x1c], 0x10021d14
            //   a1????????           |                     
            //   eb1a                 | jmp                 0x1c
            //   c745e4101d0210       | mov                 dword ptr [ebp - 0x1c], 0x10021d10
            //   a1????????           |                     
            //   eb0c                 | jmp                 0xe

        $sequence_3 = { 50 baccc40110 8d8dd8feffff e8???????? 83c404 c645fc08 8d4d20 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   baccc40110           | mov                 edx, 0x1001c4cc
            //   8d8dd8feffff         | lea                 ecx, [ebp - 0x128]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8
            //   8d4d20               | lea                 ecx, [ebp + 0x20]

        $sequence_4 = { 8d8d40feffff e9???????? 8d8d24feffff e9???????? 8d8d24feffff }
            // n = 5, score = 100
            //   8d8d40feffff         | lea                 ecx, [ebp - 0x1c0]
            //   e9????????           |                     
            //   8d8d24feffff         | lea                 ecx, [ebp - 0x1dc]
            //   e9????????           |                     
            //   8d8d24feffff         | lea                 ecx, [ebp - 0x1dc]

        $sequence_5 = { 8d4dd8 e9???????? 8b8d04ffffff e9???????? 8b4d80 e9???????? 8d4d9c }
            // n = 7, score = 100
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e9????????           |                     
            //   8b8d04ffffff         | mov                 ecx, dword ptr [ebp - 0xfc]
            //   e9????????           |                     
            //   8b4d80               | mov                 ecx, dword ptr [ebp - 0x80]
            //   e9????????           |                     
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]

        $sequence_6 = { 33cd e8???????? 8be5 5d c21000 817e1800010000 }
            // n = 6, score = 100
            //   33cd                 | xor                 ecx, ebp
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c21000               | ret                 0x10
            //   817e1800010000       | cmp                 dword ptr [esi + 0x18], 0x100

        $sequence_7 = { 8d853cfeffff 50 6a01 6a00 }
            // n = 4, score = 100
            //   8d853cfeffff         | lea                 eax, [ebp - 0x1c4]
            //   50                   | push                eax
            //   6a01                 | push                1
            //   6a00                 | push                0

        $sequence_8 = { 8bf0 eb02 33f6 c7442428ffffffff 85f6 7506 56 }
            // n = 7, score = 100
            //   8bf0                 | mov                 esi, eax
            //   eb02                 | jmp                 4
            //   33f6                 | xor                 esi, esi
            //   c7442428ffffffff     | mov                 dword ptr [esp + 0x28], 0xffffffff
            //   85f6                 | test                esi, esi
            //   7506                 | jne                 8
            //   56                   | push                esi

        $sequence_9 = { c78500ffffff0f000000 c785fcfeffff00000000 c685ecfeffff00 c645fc0e 837d9810 }
            // n = 5, score = 100
            //   c78500ffffff0f000000     | mov    dword ptr [ebp - 0x100], 0xf
            //   c785fcfeffff00000000     | mov    dword ptr [ebp - 0x104], 0
            //   c685ecfeffff00       | mov                 byte ptr [ebp - 0x114], 0
            //   c645fc0e             | mov                 byte ptr [ebp - 4], 0xe
            //   837d9810             | cmp                 dword ptr [ebp - 0x68], 0x10

    condition:
        7 of them and filesize < 827392
}
