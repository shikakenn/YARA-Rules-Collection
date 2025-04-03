rule win_asprox_auto {

    meta:
        id = "4EhBTJ822lsud4PKbHChqa"
        fingerprint = "v1_sha256_45002ecaaab3dadffe3aed1cfa4261799259027c0d201b2024f1681cd43bb771"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.asprox."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asprox"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff15???????? 898558ffffff 6a00 6a00 8b4580 50 ff15???????? }
            // n = 7, score = 1200
            //   ff15????????         |                     
            //   898558ffffff         | mov                 dword ptr [ebp - 0xa8], eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8b4580               | mov                 eax, dword ptr [ebp - 0x80]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_1 = { 8b4df8 898b54fa0000 8b4de4 898b58fa0000 8b4dac 898b5cfa0000 }
            // n = 6, score = 1200
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   898b54fa0000         | mov                 dword ptr [ebx + 0xfa54], ecx
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   898b58fa0000         | mov                 dword ptr [ebx + 0xfa58], ecx
            //   8b4dac               | mov                 ecx, dword ptr [ebp - 0x54]
            //   898b5cfa0000         | mov                 dword ptr [ebx + 0xfa5c], ecx

        $sequence_2 = { 8b4d08 51 6801000080 ff15???????? 85c0 0f85a7010000 c745e003000000 }
            // n = 7, score = 1200
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f85a7010000         | jne                 0x1ad
            //   c745e003000000       | mov                 dword ptr [ebp - 0x20], 3

        $sequence_3 = { c6458a00 8d4584 50 8b8d08ffffff 51 ff9538ffffff }
            // n = 6, score = 1200
            //   c6458a00             | mov                 byte ptr [ebp - 0x76], 0
            //   8d4584               | lea                 eax, [ebp - 0x7c]
            //   50                   | push                eax
            //   8b8d08ffffff         | mov                 ecx, dword ptr [ebp - 0xf8]
            //   51                   | push                ecx
            //   ff9538ffffff         | call                dword ptr [ebp - 0xc8]

        $sequence_4 = { ff15???????? 898558ffffff c78560ffffff00000000 8b4d0c 898d3cffffff 6a40 6a00 }
            // n = 7, score = 1200
            //   ff15????????         |                     
            //   898558ffffff         | mov                 dword ptr [ebp - 0xa8], eax
            //   c78560ffffff00000000     | mov    dword ptr [ebp - 0xa0], 0
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   898d3cffffff         | mov                 dword ptr [ebp - 0xc4], ecx
            //   6a40                 | push                0x40
            //   6a00                 | push                0

        $sequence_5 = { eb6a c743041c000000 eb37 8b03 83780400 0f840f0f0000 8b10 }
            // n = 7, score = 1200
            //   eb6a                 | jmp                 0x6c
            //   c743041c000000       | mov                 dword ptr [ebx + 4], 0x1c
            //   eb37                 | jmp                 0x39
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   83780400             | cmp                 dword ptr [eax + 4], 0
            //   0f840f0f0000         | je                  0xf15
            //   8b10                 | mov                 edx, dword ptr [eax]

        $sequence_6 = { 8bec 51 a1???????? 83c001 33d2 b900010000 f7f1 }
            // n = 7, score = 1200
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   a1????????           |                     
            //   83c001               | add                 eax, 1
            //   33d2                 | xor                 edx, edx
            //   b900010000           | mov                 ecx, 0x100
            //   f7f1                 | div                 ecx

        $sequence_7 = { 51 ff9538ffffff 8945bc c645c445 c645c578 c645c669 c645c774 }
            // n = 7, score = 1200
            //   51                   | push                ecx
            //   ff9538ffffff         | call                dword ptr [ebp - 0xc8]
            //   8945bc               | mov                 dword ptr [ebp - 0x44], eax
            //   c645c445             | mov                 byte ptr [ebp - 0x3c], 0x45
            //   c645c578             | mov                 byte ptr [ebp - 0x3b], 0x78
            //   c645c669             | mov                 byte ptr [ebp - 0x3a], 0x69
            //   c645c774             | mov                 byte ptr [ebp - 0x39], 0x74

        $sequence_8 = { 52 8b4508 50 6a02 ff55f0 85c0 7535 }
            // n = 7, score = 1200
            //   52                   | push                edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   6a02                 | push                2
            //   ff55f0               | call                dword ptr [ebp - 0x10]
            //   85c0                 | test                eax, eax
            //   7535                 | jne                 0x37

        $sequence_9 = { 52 8b85e8fbffff 50 e8???????? 83c40c 6a00 6a00 }
            // n = 7, score = 1200
            //   52                   | push                edx
            //   8b85e8fbffff         | mov                 eax, dword ptr [ebp - 0x418]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 155648
}
