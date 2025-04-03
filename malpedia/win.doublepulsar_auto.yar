rule win_doublepulsar_auto {

    meta:
        id = "2dVViGm82rAXHmfFnuFqRF"
        fingerprint = "v1_sha256_2279c234c2a28c8a309faafd6821b4cb1af9e5365add72a62e549a791ef8e967"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.doublepulsar."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doublepulsar"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 31c9 39f9 744d 89d3 }
            // n = 4, score = 100
            //   31c9                 | xor                 ecx, ecx
            //   39f9                 | cmp                 ecx, edi
            //   744d                 | je                  0x4f
            //   89d3                 | mov                 ebx, edx

        $sequence_1 = { 8944243c 6689442440 88442442 e8???????? 8bf0 83c404 3bf5 }
            // n = 7, score = 100
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax
            //   6689442440           | mov                 word ptr [esp + 0x40], ax
            //   88442442             | mov                 byte ptr [esp + 0x42], al
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c404               | add                 esp, 4
            //   3bf5                 | cmp                 esi, ebp

        $sequence_2 = { 7405 bb03000000 8b9768010000 56 68???????? }
            // n = 5, score = 100
            //   7405                 | je                  7
            //   bb03000000           | mov                 ebx, 3
            //   8b9768010000         | mov                 edx, dword ptr [edi + 0x168]
            //   56                   | push                esi
            //   68????????           |                     

        $sequence_3 = { 03c0 8b8c0088b84000 8b94008cb84000 03c0 56 51 52 }
            // n = 7, score = 100
            //   03c0                 | add                 eax, eax
            //   8b8c0088b84000       | mov                 ecx, dword ptr [eax + eax + 0x40b888]
            //   8b94008cb84000       | mov                 edx, dword ptr [eax + eax + 0x40b88c]
            //   03c0                 | add                 eax, eax
            //   56                   | push                esi
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_4 = { ff5608 85c0 744b 894530 8b4620 8b7d65 83c703 }
            // n = 7, score = 100
            //   ff5608               | call                dword ptr [esi + 8]
            //   85c0                 | test                eax, eax
            //   744b                 | je                  0x4d
            //   894530               | mov                 dword ptr [ebp + 0x30], eax
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   8b7d65               | mov                 edi, dword ptr [ebp + 0x65]
            //   83c703               | add                 edi, 3

        $sequence_5 = { 48 8bd0 ff5728 85c0 7555 3933 }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   8bd0                 | mov                 edx, eax
            //   ff5728               | call                dword ptr [edi + 0x28]
            //   85c0                 | test                eax, eax
            //   7555                 | jne                 0x57
            //   3933                 | cmp                 dword ptr [ebx], esi

        $sequence_6 = { 53 55 51 ff15???????? 8bfb 83c9ff 33c0 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8bfb                 | mov                 edi, ebx
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 89742424 89742420 0f8ed8000000 8bf5 }
            // n = 4, score = 100
            //   89742424             | mov                 dword ptr [esp + 0x24], esi
            //   89742420             | mov                 dword ptr [esp + 0x20], esi
            //   0f8ed8000000         | jle                 0xde
            //   8bf5                 | mov                 esi, ebp

        $sequence_8 = { 83c428 83f802 0f85c4fdffff 8d542420 8d44241c 52 }
            // n = 6, score = 100
            //   83c428               | add                 esp, 0x28
            //   83f802               | cmp                 eax, 2
            //   0f85c4fdffff         | jne                 0xfffffdca
            //   8d542420             | lea                 edx, [esp + 0x20]
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   52                   | push                edx

        $sequence_9 = { 57 c744242808164000 c744242cfc154000 c7442430f4154000 c7442434e0154000 89742424 ff15???????? }
            // n = 7, score = 100
            //   57                   | push                edi
            //   c744242808164000     | mov                 dword ptr [esp + 0x28], 0x401608
            //   c744242cfc154000     | mov                 dword ptr [esp + 0x2c], 0x4015fc
            //   c7442430f4154000     | mov                 dword ptr [esp + 0x30], 0x4015f4
            //   c7442434e0154000     | mov                 dword ptr [esp + 0x34], 0x4015e0
            //   89742424             | mov                 dword ptr [esp + 0x24], esi
            //   ff15????????         |                     

        $sequence_10 = { 33c0 33db 56 57 89442430 89442434 }
            // n = 6, score = 100
            //   33c0                 | xor                 eax, eax
            //   33db                 | xor                 ebx, ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   89442430             | mov                 dword ptr [esp + 0x30], eax
            //   89442434             | mov                 dword ptr [esp + 0x34], eax

        $sequence_11 = { 56 6a01 83c00c 51 e8???????? 8bf8 83c418 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   6a01                 | push                1
            //   83c00c               | add                 eax, 0xc
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c418               | add                 esp, 0x18

        $sequence_12 = { 03f0 85f6 7f10 e8???????? 3d33270000 }
            // n = 5, score = 100
            //   03f0                 | add                 esi, eax
            //   85f6                 | test                esi, esi
            //   7f10                 | jg                  0x12
            //   e8????????           |                     
            //   3d33270000           | cmp                 eax, 0x2733

        $sequence_13 = { a1???????? 83c408 8d54244c 83c020 52 68???????? }
            // n = 6, score = 100
            //   a1????????           |                     
            //   83c408               | add                 esp, 8
            //   8d54244c             | lea                 edx, [esp + 0x4c]
            //   83c020               | add                 eax, 0x20
            //   52                   | push                edx
            //   68????????           |                     

        $sequence_14 = { 5d 33c0 5b 81c41c210000 c21000 8b842438210000 }
            // n = 6, score = 100
            //   5d                   | pop                 ebp
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   81c41c210000         | add                 esp, 0x211c
            //   c21000               | ret                 0x10
            //   8b842438210000       | mov                 eax, dword ptr [esp + 0x2138]

        $sequence_15 = { ffd5 83c408 85c0 7562 8b16 c744242401000000 }
            // n = 6, score = 100
            //   ffd5                 | call                ebp
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7562                 | jne                 0x64
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   c744242401000000     | mov                 dword ptr [esp + 0x24], 1

    condition:
        7 of them and filesize < 140288
}
