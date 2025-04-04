rule win_mocton_auto {

    meta:
        id = "GxlOe8JlUETuHFBAECwQc"
        fingerprint = "v1_sha256_ab360491efcec62323f6bd101f123d7a2664b6f36f37ac6acc5b7e8f64a1cf18"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mocton."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mocton"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { b8ee2fba29 2b8540fdffff 898540fdffff eb59 8b8dc8fcffff 69c9360d54b3 33d2 }
            // n = 7, score = 100
            //   b8ee2fba29           | mov                 eax, 0x29ba2fee
            //   2b8540fdffff         | sub                 eax, dword ptr [ebp - 0x2c0]
            //   898540fdffff         | mov                 dword ptr [ebp - 0x2c0], eax
            //   eb59                 | jmp                 0x5b
            //   8b8dc8fcffff         | mov                 ecx, dword ptr [ebp - 0x338]
            //   69c9360d54b3         | imul                ecx, ecx, 0xb3540d36
            //   33d2                 | xor                 edx, edx

        $sequence_1 = { 8945e8 e9???????? 8b4dd4 83e901 894dd4 8b55d4 69d240107496 }
            // n = 7, score = 100
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   e9????????           |                     
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   83e901               | sub                 ecx, 1
            //   894dd4               | mov                 dword ptr [ebp - 0x2c], ecx
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]
            //   69d240107496         | imul                edx, edx, 0x96741040

        $sequence_2 = { 33c0 399570feffff 0f9dc0 338570feffff 8b8d70feffff 83e901 898d70feffff }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   399570feffff         | cmp                 dword ptr [ebp - 0x190], edx
            //   0f9dc0               | setge               al
            //   338570feffff         | xor                 eax, dword ptr [ebp - 0x190]
            //   8b8d70feffff         | mov                 ecx, dword ptr [ebp - 0x190]
            //   83e901               | sub                 ecx, 1
            //   898d70feffff         | mov                 dword ptr [ebp - 0x190], ecx

        $sequence_3 = { 8b8518fcffff 2bc2 898518fcffff 6a01 8b4dc0 51 e8???????? }
            // n = 7, score = 100
            //   8b8518fcffff         | mov                 eax, dword ptr [ebp - 0x3e8]
            //   2bc2                 | sub                 eax, edx
            //   898518fcffff         | mov                 dword ptr [ebp - 0x3e8], eax
            //   6a01                 | push                1
            //   8b4dc0               | mov                 ecx, dword ptr [ebp - 0x40]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_4 = { 250b378f61 3385e8fbffff 3385e8fbffff 8b8de8fbffff 83e901 898de8fbffff 85c0 }
            // n = 7, score = 100
            //   250b378f61           | and                 eax, 0x618f370b
            //   3385e8fbffff         | xor                 eax, dword ptr [ebp - 0x418]
            //   3385e8fbffff         | xor                 eax, dword ptr [ebp - 0x418]
            //   8b8de8fbffff         | mov                 ecx, dword ptr [ebp - 0x418]
            //   83e901               | sub                 ecx, 1
            //   898de8fbffff         | mov                 dword ptr [ebp - 0x418], ecx
            //   85c0                 | test                eax, eax

        $sequence_5 = { 8d840afae31ce1 8945c4 c745bc9d7d7759 c745ecf8eddc22 c745d8e052b31e 8b4dec 81f1995c274e }
            // n = 7, score = 100
            //   8d840afae31ce1       | lea                 eax, [edx + ecx - 0x1ee31c06]
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   c745bc9d7d7759       | mov                 dword ptr [ebp - 0x44], 0x59777d9d
            //   c745ecf8eddc22       | mov                 dword ptr [ebp - 0x14], 0x22dcedf8
            //   c745d8e052b31e       | mov                 dword ptr [ebp - 0x28], 0x1eb352e0
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   81f1995c274e         | xor                 ecx, 0x4e275c99

        $sequence_6 = { 50 8b0d???????? 51 e8???????? 83c408 c78550fbfffffb90ba4f c78518fbffff55263138 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b0d????????         |                     
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   c78550fbfffffb90ba4f     | mov    dword ptr [ebp - 0x4b0], 0x4fba90fb
            //   c78518fbffff55263138     | mov    dword ptr [ebp - 0x4e8], 0x38312655

        $sequence_7 = { 0faf45b8 0345b8 2345b8 8945b8 8b4db8 }
            // n = 5, score = 100
            //   0faf45b8             | imul                eax, dword ptr [ebp - 0x48]
            //   0345b8               | add                 eax, dword ptr [ebp - 0x48]
            //   2345b8               | and                 eax, dword ptr [ebp - 0x48]
            //   8945b8               | mov                 dword ptr [ebp - 0x48], eax
            //   8b4db8               | mov                 ecx, dword ptr [ebp - 0x48]

        $sequence_8 = { 2b8594e9ffff 8b8d94e9ffff 8b9594e9ffff 83c201 899594e9ffff 3bc8 0f8c86000000 }
            // n = 7, score = 100
            //   2b8594e9ffff         | sub                 eax, dword ptr [ebp - 0x166c]
            //   8b8d94e9ffff         | mov                 ecx, dword ptr [ebp - 0x166c]
            //   8b9594e9ffff         | mov                 edx, dword ptr [ebp - 0x166c]
            //   83c201               | add                 edx, 1
            //   899594e9ffff         | mov                 dword ptr [ebp - 0x166c], edx
            //   3bc8                 | cmp                 ecx, eax
            //   0f8c86000000         | jl                  0x8c

        $sequence_9 = { 0f9dc1 81e1b0c00d60 740c 8b55f0 81e2803636b3 8955f0 eb1d }
            // n = 7, score = 100
            //   0f9dc1               | setge               cl
            //   81e1b0c00d60         | and                 ecx, 0x600dc0b0
            //   740c                 | je                  0xe
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   81e2803636b3         | and                 edx, 0xb3363680
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   eb1d                 | jmp                 0x1f

    condition:
        7 of them and filesize < 573440
}
