rule win_concealment_troy_auto {

    meta:
        id = "1UauZYtZl7dXavaEK05TMw"
        fingerprint = "v1_sha256_5ef8bd4e1cd35f7f8cc8bada75a137689ed8949f72f34f8e30aca42d1738a1ce"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.concealment_troy."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.concealment_troy"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 2bc2 50 8d942468050000 52 }
            // n = 4, score = 100
            //   2bc2                 | sub                 eax, edx
            //   50                   | push                eax
            //   8d942468050000       | lea                 edx, [esp + 0x568]
            //   52                   | push                edx

        $sequence_1 = { 83c410 8d542424 52 8d442438 50 6a00 6a00 }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   8d542424             | lea                 edx, [esp + 0x24]
            //   52                   | push                edx
            //   8d442438             | lea                 eax, [esp + 0x38]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_2 = { 8bc8 83e103 f3a4 8d542418 8d8c2430090000 e8???????? 85c0 }
            // n = 7, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   8d8c2430090000       | lea                 ecx, [esp + 0x930]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_3 = { 8d3c8da0774100 8b0f c1e606 833c0eff }
            // n = 4, score = 100
            //   8d3c8da0774100       | lea                 edi, [ecx*4 + 0x4177a0]
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   c1e606               | shl                 esi, 6
            //   833c0eff             | cmp                 dword ptr [esi + ecx], -1

        $sequence_4 = { 6800100000 8d84249c030000 6a00 50 e8???????? }
            // n = 5, score = 100
            //   6800100000           | push                0x1000
            //   8d84249c030000       | lea                 eax, [esp + 0x39c]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_5 = { 8d842420010000 e8???????? 8d542418 8d9b00000000 8a08 }
            // n = 5, score = 100
            //   8d842420010000       | lea                 eax, [esp + 0x120]
            //   e8????????           |                     
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   8d9b00000000         | lea                 ebx, [ebx]
            //   8a08                 | mov                 cl, byte ptr [eax]

        $sequence_6 = { 8b7588 8b7d8c b940000000 f3a5 }
            // n = 4, score = 100
            //   8b7588               | mov                 esi, dword ptr [ebp - 0x78]
            //   8b7d8c               | mov                 edi, dword ptr [ebp - 0x74]
            //   b940000000           | mov                 ecx, 0x40
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_7 = { 3acb 75f9 2bc2 807c041722 }
            // n = 4, score = 100
            //   3acb                 | cmp                 cl, bl
            //   75f9                 | jne                 0xfffffffb
            //   2bc2                 | sub                 eax, edx
            //   807c041722           | cmp                 byte ptr [esp + eax + 0x17], 0x22

        $sequence_8 = { e8???????? 83c414 807c24104d 0f85b1000000 807c24115a 0f85a6000000 53 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   807c24104d           | cmp                 byte ptr [esp + 0x10], 0x4d
            //   0f85b1000000         | jne                 0xb7
            //   807c24115a           | cmp                 byte ptr [esp + 0x11], 0x5a
            //   0f85a6000000         | jne                 0xac
            //   53                   | push                ebx

        $sequence_9 = { 57 ff15???????? 5d 5f 33c0 5e 8b8c2420010000 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   5d                   | pop                 ebp
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   8b8c2420010000       | mov                 ecx, dword ptr [esp + 0x120]

    condition:
        7 of them and filesize < 229376
}
