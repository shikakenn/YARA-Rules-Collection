rule win_taintedscribe_auto {

    meta:
        id = "2adT7ls2fH5UQVT1xF9fJZ"
        fingerprint = "v1_sha256_5d981495a3922cbb61b73e09b9b5becae7637fb3153cbba90f67db62eec8bfc1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.taintedscribe."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taintedscribe"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8916 8b4dfc 5e 33cd 33c0 5b }
            // n = 6, score = 500
            //   8916                 | mov                 dword ptr [esi], edx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   5e                   | pop                 esi
            //   33cd                 | xor                 ecx, ebp
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx

        $sequence_1 = { 668995e4f9ffff e8???????? 8b8590f7ffff 8d95e4f9ffff }
            // n = 4, score = 500
            //   668995e4f9ffff       | mov                 word ptr [ebp - 0x61c], dx
            //   e8????????           |                     
            //   8b8590f7ffff         | mov                 eax, dword ptr [ebp - 0x870]
            //   8d95e4f9ffff         | lea                 edx, [ebp - 0x61c]

        $sequence_2 = { 8bf8 f3a5 8b4b28 83c414 85c9 7518 5f }
            // n = 7, score = 500
            //   8bf8                 | mov                 edi, eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8b4b28               | mov                 ecx, dword ptr [ebx + 0x28]
            //   83c414               | add                 esp, 0x14
            //   85c9                 | test                ecx, ecx
            //   7518                 | jne                 0x1a
            //   5f                   | pop                 edi

        $sequence_3 = { d3e3 33c0 85db 7e22 8da42400000000 }
            // n = 5, score = 500
            //   d3e3                 | shl                 ebx, cl
            //   33c0                 | xor                 eax, eax
            //   85db                 | test                ebx, ebx
            //   7e22                 | jle                 0x24
            //   8da42400000000       | lea                 esp, [esp]

        $sequence_4 = { 8b4dcc 894308 8b45d0 50 51 89530c }
            // n = 6, score = 500
            //   8b4dcc               | mov                 ecx, dword ptr [ebp - 0x34]
            //   894308               | mov                 dword ptr [ebx + 8], eax
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   89530c               | mov                 dword ptr [ebx + 0xc], edx

        $sequence_5 = { 8b5358 898d88fbffff 8b4b50 0f94c0 807b1400 899584fbffff 898d8cfbffff }
            // n = 7, score = 500
            //   8b5358               | mov                 edx, dword ptr [ebx + 0x58]
            //   898d88fbffff         | mov                 dword ptr [ebp - 0x478], ecx
            //   8b4b50               | mov                 ecx, dword ptr [ebx + 0x50]
            //   0f94c0               | sete                al
            //   807b1400             | cmp                 byte ptr [ebx + 0x14], 0
            //   899584fbffff         | mov                 dword ptr [ebp - 0x47c], edx
            //   898d8cfbffff         | mov                 dword ptr [ebp - 0x474], ecx

        $sequence_6 = { 5b 5d c20c00 83f803 7574 }
            // n = 5, score = 500
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   83f803               | cmp                 eax, 3
            //   7574                 | jne                 0x76

        $sequence_7 = { 898da8fbffff 8d45e8 8985b4fcffff 8b433c 8bd0 8d4ddc }
            // n = 6, score = 500
            //   898da8fbffff         | mov                 dword ptr [ebp - 0x458], ecx
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   8985b4fcffff         | mov                 dword ptr [ebp - 0x34c], eax
            //   8b433c               | mov                 eax, dword ptr [ebx + 0x3c]
            //   8bd0                 | mov                 edx, eax
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]

        $sequence_8 = { 6a00 6a00 ff15???????? 85c0 7516 }
            // n = 5, score = 500
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7516                 | jne                 0x18

        $sequence_9 = { bb01000000 d3e3 33c0 85db 7e1e 8d4900 }
            // n = 6, score = 500
            //   bb01000000           | mov                 ebx, 1
            //   d3e3                 | shl                 ebx, cl
            //   33c0                 | xor                 eax, eax
            //   85db                 | test                ebx, ebx
            //   7e1e                 | jle                 0x20
            //   8d4900               | lea                 ecx, [ecx]

    condition:
        7 of them and filesize < 524288
}
