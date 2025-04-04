rule win_eyservice_auto {

    meta:
        id = "4KmcjQpE8PT0LJJ4IfZnFr"
        fingerprint = "v1_sha256_9d569b1b4aa245beb2c0397a0750c9c20deb66d33a0ec235ace59e3da184607d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.eyservice."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.eyservice"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6aff 50 ff15???????? 85c0 757e 8b4624 }
            // n = 6, score = 100
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   757e                 | jne                 0x80
            //   8b4624               | mov                 eax, dword ptr [esi + 0x24]

        $sequence_1 = { e8???????? 83beac01000001 750d 8b8eec000000 51 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83beac01000001       | cmp                 dword ptr [esi + 0x1ac], 1
            //   750d                 | jne                 0xf
            //   8b8eec000000         | mov                 ecx, dword ptr [esi + 0xec]
            //   51                   | push                ecx

        $sequence_2 = { e8???????? 83c404 8bc8 e8???????? 8bf0 8bce e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_3 = { 51 668944244c ffd5 668b542446 8b4c2442 668954241e 8b542446 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   668944244c           | mov                 word ptr [esp + 0x4c], ax
            //   ffd5                 | call                ebp
            //   668b542446           | mov                 dx, word ptr [esp + 0x46]
            //   8b4c2442             | mov                 ecx, dword ptr [esp + 0x42]
            //   668954241e           | mov                 word ptr [esp + 0x1e], dx
            //   8b542446             | mov                 edx, dword ptr [esp + 0x46]

        $sequence_4 = { 0fbf8a883b4100 0fbf0c4dea3f4100 3bc8 7433 0fbf82c03c4100 3d94000000 7c0a }
            // n = 7, score = 100
            //   0fbf8a883b4100       | movsx               ecx, word ptr [edx + 0x413b88]
            //   0fbf0c4dea3f4100     | movsx               ecx, word ptr [ecx*2 + 0x413fea]
            //   3bc8                 | cmp                 ecx, eax
            //   7433                 | je                  0x35
            //   0fbf82c03c4100       | movsx               eax, word ptr [edx + 0x413cc0]
            //   3d94000000           | cmp                 eax, 0x94
            //   7c0a                 | jl                  0xc

        $sequence_5 = { 7509 b86e000000 5e c20800 8b06 034604 }
            // n = 6, score = 100
            //   7509                 | jne                 0xb
            //   b86e000000           | mov                 eax, 0x6e
            //   5e                   | pop                 esi
            //   c20800               | ret                 8
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   034604               | add                 eax, dword ptr [esi + 4]

        $sequence_6 = { 894614 ff86c0000000 83bec000000001 57 7513 ff15???????? 56 }
            // n = 7, score = 100
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   ff86c0000000         | inc                 dword ptr [esi + 0xc0]
            //   83bec000000001       | cmp                 dword ptr [esi + 0xc0], 1
            //   57                   | push                edi
            //   7513                 | jne                 0x15
            //   ff15????????         |                     
            //   56                   | push                esi

        $sequence_7 = { ff15???????? 8bc7 5f 8b8c246c020000 5b 5e }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   8b8c246c020000       | mov                 ecx, dword ptr [esp + 0x26c]
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi

        $sequence_8 = { 7426 8b4610 2bc7 c1f802 8d0c8500000000 8d2c11 }
            // n = 6, score = 100
            //   7426                 | je                  0x28
            //   8b4610               | mov                 eax, dword ptr [esi + 0x10]
            //   2bc7                 | sub                 eax, edi
            //   c1f802               | sar                 eax, 2
            //   8d0c8500000000       | lea                 ecx, [eax*4]
            //   8d2c11               | lea                 ebp, [ecx + edx]

        $sequence_9 = { 8b7704 2bf0 7424 3bf1 7602 8bf1 }
            // n = 6, score = 100
            //   8b7704               | mov                 esi, dword ptr [edi + 4]
            //   2bf0                 | sub                 esi, eax
            //   7424                 | je                  0x26
            //   3bf1                 | cmp                 esi, ecx
            //   7602                 | jbe                 4
            //   8bf1                 | mov                 esi, ecx

    condition:
        7 of them and filesize < 452608
}
