rule win_mofksys_auto {

    meta:
        id = "39hR0UbvkejrLurIPLCjVF"
        fingerprint = "v1_sha256_8c9a7d93274bbf5d514b6dd91aa6e0270b7fa1be2a34ea8caa7a062178ba1dc3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mofksys."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mofksys"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a1c 68???????? 8b5588 52 8b4584 50 ff15???????? }
            // n = 7, score = 100
            //   6a1c                 | push                0x1c
            //   68????????           |                     
            //   8b5588               | mov                 edx, dword ptr [ebp - 0x78]
            //   52                   | push                edx
            //   8b4584               | mov                 eax, dword ptr [ebp - 0x7c]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_1 = { 56 ff5004 897de0 897ddc 897dd8 6a01 ff15???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff5004               | call                dword ptr [eax + 4]
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi
            //   897ddc               | mov                 dword ptr [ebp - 0x24], edi
            //   897dd8               | mov                 dword ptr [ebp - 0x28], edi
            //   6a01                 | push                1
            //   ff15????????         |                     

        $sequence_2 = { ff15???????? 8b8d5cffffff 89412c c745fc86000000 8d55d4 52 6a00 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b8d5cffffff         | mov                 ecx, dword ptr [ebp - 0xa4]
            //   89412c               | mov                 dword ptr [ecx + 0x2c], eax
            //   c745fc86000000       | mov                 dword ptr [ebp - 4], 0x86
            //   8d55d4               | lea                 edx, [ebp - 0x2c]
            //   52                   | push                edx
            //   6a00                 | push                0

        $sequence_3 = { ff15???????? 33c9 837db400 0f95c1 f7d9 66894db0 8d4dc8 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   33c9                 | xor                 ecx, ecx
            //   837db400             | cmp                 dword ptr [ebp - 0x4c], 0
            //   0f95c1               | setne               cl
            //   f7d9                 | neg                 ecx
            //   66894db0             | mov                 word ptr [ebp - 0x50], cx
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]

        $sequence_4 = { 8b4de0 ff15???????? 50 ff15???????? c785f4fcffff00000000 ff15???????? }
            // n = 6, score = 100
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   c785f4fcffff00000000     | mov    dword ptr [ebp - 0x30c], 0
            //   ff15????????         |                     

        $sequence_5 = { 8d4dc4 51 8b35???????? ffd6 50 57 }
            // n = 6, score = 100
            //   8d4dc4               | lea                 ecx, [ebp - 0x3c]
            //   51                   | push                ecx
            //   8b35????????         |                     
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_6 = { 8b4dd4 51 8d55dc 52 ff15???????? 8d45cc 50 }
            // n = 7, score = 100
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   51                   | push                ecx
            //   8d55dc               | lea                 edx, [ebp - 0x24]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   50                   | push                eax

        $sequence_7 = { ff15???????? 8b4dd0 8b8530ffffff c1e002 eb09 ff15???????? 8b4dd0 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b4dd0               | mov                 ecx, dword ptr [ebp - 0x30]
            //   8b8530ffffff         | mov                 eax, dword ptr [ebp - 0xd0]
            //   c1e002               | shl                 eax, 2
            //   eb09                 | jmp                 0xb
            //   ff15????????         |                     
            //   8b4dd0               | mov                 ecx, dword ptr [ebp - 0x30]

        $sequence_8 = { 6685f6 7413 668b0d???????? 51 ff15???????? e9???????? 668b15???????? }
            // n = 7, score = 100
            //   6685f6               | test                si, si
            //   7413                 | je                  0x15
            //   668b0d????????       |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   e9????????           |                     
            //   668b15????????       |                     

        $sequence_9 = { 8b5508 8b02 eb3a 8b4dd0 85c9 7424 66833901 }
            // n = 7, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   eb3a                 | jmp                 0x3c
            //   8b4dd0               | mov                 ecx, dword ptr [ebp - 0x30]
            //   85c9                 | test                ecx, ecx
            //   7424                 | je                  0x26
            //   66833901             | cmp                 word ptr [ecx], 1

    condition:
        7 of them and filesize < 401408
}
