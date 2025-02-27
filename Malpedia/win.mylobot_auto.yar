rule win_mylobot_auto {

    meta:
        id = "4Km2jyHcTXpti8yguw2Kcr"
        fingerprint = "v1_sha256_a859373208876596e4d4c654a67f12e66a950382de85503fc39b74c533ee7259"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mylobot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mylobot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8a4c2413 84c9 888c04bc010000 8b442414 }
            // n = 4, score = 1000
            //   8a4c2413             | mov                 cl, byte ptr [esp + 0x13]
            //   84c9                 | test                cl, cl
            //   888c04bc010000       | mov                 byte ptr [esp + eax + 0x1bc], cl
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]

        $sequence_1 = { 50 e8???????? 83c424 8d7c2440 33c0 6a0a 59 }
            // n = 7, score = 1000
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   8d7c2440             | lea                 edi, [esp + 0x40]
            //   33c0                 | xor                 eax, eax
            //   6a0a                 | push                0xa
            //   59                   | pop                 ecx

        $sequence_2 = { 8b6e24 03c7 03ef 89442414 85c9 }
            // n = 5, score = 1000
            //   8b6e24               | mov                 ebp, dword ptr [esi + 0x24]
            //   03c7                 | add                 eax, edi
            //   03ef                 | add                 ebp, edi
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   85c9                 | test                ecx, ecx

        $sequence_3 = { 6810270000 ff15???????? 83bf0801000001 7509 5f 5e 33c0 }
            // n = 7, score = 1000
            //   6810270000           | push                0x2710
            //   ff15????????         |                     
            //   83bf0801000001       | cmp                 dword ptr [edi + 0x108], 1
            //   7509                 | jne                 0xb
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 50 e8???????? 59 8a4c2413 84c9 888c048c050000 }
            // n = 6, score = 1000
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8a4c2413             | mov                 cl, byte ptr [esp + 0x13]
            //   84c9                 | test                cl, cl
            //   888c048c050000       | mov                 byte ptr [esp + eax + 0x58c], cl

        $sequence_5 = { e8???????? 8b0d???????? 898170010000 a1???????? ffb070010000 }
            // n = 5, score = 1000
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   898170010000         | mov                 dword ptr [ecx + 0x170], eax
            //   a1????????           |                     
            //   ffb070010000         | push                dword ptr [eax + 0x170]

        $sequence_6 = { 8bd0 e8???????? e9???????? 3c13 0f858f000000 }
            // n = 5, score = 1000
            //   8bd0                 | mov                 edx, eax
            //   e8????????           |                     
            //   e9????????           |                     
            //   3c13                 | cmp                 al, 0x13
            //   0f858f000000         | jne                 0x95

        $sequence_7 = { 8364242000 8d8424bc000000 50 e8???????? 50 }
            // n = 5, score = 1000
            //   8364242000           | and                 dword ptr [esp + 0x20], 0
            //   8d8424bc000000       | lea                 eax, [esp + 0xbc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_8 = { ffd7 85c0 7517 a1???????? }
            // n = 4, score = 800
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   7517                 | jne                 0x19
            //   a1????????           |                     

        $sequence_9 = { ffd6 a1???????? 6aff 50 ff15???????? }
            // n = 5, score = 800
            //   ffd6                 | call                esi
            //   a1????????           |                     
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_10 = { 83c428 a3???????? a3???????? a3???????? a3???????? a1???????? }
            // n = 6, score = 800
            //   83c428               | add                 esp, 0x28
            //   a3????????           |                     
            //   a3????????           |                     
            //   a3????????           |                     
            //   a3????????           |                     
            //   a1????????           |                     

        $sequence_11 = { 8b0d???????? 6a01 6a00 6a00 6a00 }
            // n = 5, score = 800
            //   8b0d????????         |                     
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_12 = { 8b0f 8b5618 33db 898de0fdffff }
            // n = 4, score = 800
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   8b5618               | mov                 edx, dword ptr [esi + 0x18]
            //   33db                 | xor                 ebx, ebx
            //   898de0fdffff         | mov                 dword ptr [ebp - 0x220], ecx

        $sequence_13 = { e8???????? 8d95d0fdffff 52 b822b19818 }
            // n = 4, score = 800
            //   e8????????           |                     
            //   8d95d0fdffff         | lea                 edx, [ebp - 0x230]
            //   52                   | push                edx
            //   b822b19818           | mov                 eax, 0x1898b122

        $sequence_14 = { 7511 83c802 50 8d9558f5ffff 52 }
            // n = 5, score = 800
            //   7511                 | jne                 0x13
            //   83c802               | or                  eax, 2
            //   50                   | push                eax
            //   8d9558f5ffff         | lea                 edx, [ebp - 0xaa8]
            //   52                   | push                edx

        $sequence_15 = { 51 57 ff15???????? 8b35???????? 8d642400 8b5508 }
            // n = 6, score = 800
            //   51                   | push                ecx
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   8d642400             | lea                 esp, [esp]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 8028160
}
