rule win_sobig_auto {

    meta:
        id = "ArjYaK96PZ8wxrjqzW0O6"
        fingerprint = "v1_sha256_703647dd78e5c80dff25867b8b892bf4ae4d1517eb9d703a33dee66b43a14d30"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sobig."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sobig"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 6a01 8d4db8 e8???????? 83c8ff e9???????? 6a30 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6a01                 | push                1
            //   8d4db8               | lea                 ecx, [ebp - 0x48]
            //   e8????????           |                     
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     
            //   6a30                 | push                0x30

        $sequence_1 = { ff750c 8d4dbc e8???????? 6a01 8d7e20 5b }
            // n = 6, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]
            //   e8????????           |                     
            //   6a01                 | push                1
            //   8d7e20               | lea                 edi, [esi + 0x20]
            //   5b                   | pop                 ebx

        $sequence_2 = { 83650800 c7451008000000 0fb6450f 32d2 }
            // n = 4, score = 100
            //   83650800             | and                 dword ptr [ebp + 8], 0
            //   c7451008000000       | mov                 dword ptr [ebp + 0x10], 8
            //   0fb6450f             | movzx               eax, byte ptr [ebp + 0xf]
            //   32d2                 | xor                 dl, dl

        $sequence_3 = { e8???????? 8bf8 ff7614 8d4d90 c645fc04 e8???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   ff7614               | push                dword ptr [esi + 0x14]
            //   8d4d90               | lea                 ecx, [ebp - 0x70]
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   e8????????           |                     

        $sequence_4 = { 5e 8a1408 80faff 8811 7401 47 }
            // n = 6, score = 100
            //   5e                   | pop                 esi
            //   8a1408               | mov                 dl, byte ptr [eax + ecx]
            //   80faff               | cmp                 dl, 0xff
            //   8811                 | mov                 byte ptr [ecx], dl
            //   7401                 | je                  3
            //   47                   | inc                 edi

        $sequence_5 = { 8b4630 6a01 8985e4feffff 58 53 8d8de0feffff 53 }
            // n = 7, score = 100
            //   8b4630               | mov                 eax, dword ptr [esi + 0x30]
            //   6a01                 | push                1
            //   8985e4feffff         | mov                 dword ptr [ebp - 0x11c], eax
            //   58                   | pop                 eax
            //   53                   | push                ebx
            //   8d8de0feffff         | lea                 ecx, [ebp - 0x120]
            //   53                   | push                ebx

        $sequence_6 = { 8d45bc 50 8bcf 895dfc e8???????? 83780800 0f94c0 }
            // n = 7, score = 100
            //   8d45bc               | lea                 eax, [ebp - 0x44]
            //   50                   | push                eax
            //   8bcf                 | mov                 ecx, edi
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   e8????????           |                     
            //   83780800             | cmp                 dword ptr [eax + 8], 0
            //   0f94c0               | sete                al

        $sequence_7 = { 3bc8 0f8496000000 8bd9 8d4de8 }
            // n = 4, score = 100
            //   3bc8                 | cmp                 ecx, eax
            //   0f8496000000         | je                  0x9c
            //   8bd9                 | mov                 ebx, ecx
            //   8d4de8               | lea                 ecx, [ebp - 0x18]

        $sequence_8 = { 68???????? 6801000080 8d4d08 e8???????? 8b45ec c7451094624100 }
            // n = 6, score = 100
            //   68????????           |                     
            //   6801000080           | push                0x80000001
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   e8????????           |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   c7451094624100       | mov                 dword ptr [ebp + 0x10], 0x416294

        $sequence_9 = { 8a1f 47 83f80b 0f8777020000 ff2485563b4100 }
            // n = 5, score = 100
            //   8a1f                 | mov                 bl, byte ptr [edi]
            //   47                   | inc                 edi
            //   83f80b               | cmp                 eax, 0xb
            //   0f8777020000         | ja                  0x27d
            //   ff2485563b4100       | jmp                 dword ptr [eax*4 + 0x413b56]

    condition:
        7 of them and filesize < 262144
}
