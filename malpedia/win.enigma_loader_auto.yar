rule win_enigma_loader_auto {

    meta:
        id = "3ILsLK8PDe0OH9J2mEnRV4"
        fingerprint = "v1_sha256_a5243000c2e0d210886f2730559565c47c46e77ae7333cb6bce278e91fb001ee"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.enigma_loader."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enigma_loader"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff15???????? 85c0 790c 488d0daa400200 e9???????? 488b5c2450 ba9844c880 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | pop                 esi
            //   790c                 | inc                 ecx
            //   488d0daa400200       | pop                 ebp
            //   e9????????           |                     
            //   488b5c2450           | inc                 ecx
            //   ba9844c880           | pop                 esp

        $sequence_1 = { 81f9df000000 7f7a 7451 81f9d4000000 7f1c 7447 81f9ce000000 }
            // n = 7, score = 100
            //   81f9df000000         | jne                 0xffffffe2
            //   7f7a                 | dec                 esp
            //   7451                 | mov                 ecx, esi
            //   81f9d4000000         | dec                 esp
            //   7f1c                 | mov                 eax, dword ptr [esp + 0x20]
            //   7447                 | dec                 eax
            //   81f9ce000000         | mov                 edx, ebx

        $sequence_2 = { 4c897560 660f6f0d???????? f30f7f4d70 44887560 488d0521c70200 48898580000000 }
            // n = 6, score = 100
            //   4c897560             | dec                 eax
            //   660f6f0d????????     |                     
            //   f30f7f4d70           | mov                 eax, dword ptr [eax]
            //   44887560             | dec                 eax
            //   488d0521c70200       | lea                 edx, [ebp + 0x178]
            //   48898580000000       | dec                 ecx

        $sequence_3 = { 488b7908 4885ff 744e 488b29 488b0f 488b7108 }
            // n = 6, score = 100
            //   488b7908             | dec                 eax
            //   4885ff               | mov                 ecx, ebx
            //   744e                 | inc                 ecx
            //   488b29               | mov                 dword ptr [esi + 0x40], eax
            //   488b0f               | cmp                 eax, 0xc
            //   488b7108             | jne                 0xf8f

        $sequence_4 = { 4a0fbe843978940200 428a8c3988940200 482bd0 8b72fc d3ee 443bce 0f8d5f010000 }
            // n = 7, score = 100
            //   4a0fbe843978940200     | pop    esp
            //   428a8c3988940200     | dec                 ecx
            //   482bd0               | mov                 eax, esi
            //   8b72fc               | dec                 eax
            //   d3ee                 | mov                 ebx, dword ptr [esp + 0x80]
            //   443bce               | dec                 eax
            //   0f8d5f010000         | add                 esp, 0x50

        $sequence_5 = { 418bc4 41f7e0 b801000000 c1ea04 662bc2 0fb7c0 6bc834 }
            // n = 7, score = 100
            //   418bc4               | mov                 byte ptr [esp + 0x50], bh
            //   41f7e0               | dec                 eax
            //   b801000000           | mov                 edx, dword ptr [ebp - 0x68]
            //   c1ea04               | dec                 ecx
            //   662bc2               | cmp                 edx, esp
            //   0fb7c0               | ja                  0xf6d
            //   6bc834               | dec                 esp

        $sequence_6 = { 48c1e102 48c7c0fcffffff 482bc1 eb11 4c8b02 4d03c3 498bc0 }
            // n = 7, score = 100
            //   48c1e102             | movsd               xmm1, qword ptr [esi + 0x78]
            //   48c7c0fcffffff       | dec                 eax
            //   482bc1               | lea                 edx, [esp + 0x78]
            //   eb11                 | dec                 eax
            //   4c8b02               | mov                 ecx, edi
            //   4d03c3               | nop                 
            //   498bc0               | inc                 ecx

        $sequence_7 = { 83e901 7435 83f901 0f850c020000 660f6f05???????? c745c780000000 c745cbbf000000 }
            // n = 7, score = 100
            //   83e901               | lea                 ecx, [0x23c56]
            //   7435                 | dec                 esp
            //   83f901               | lea                 ebx, [esp + 0x50]
            //   0f850c020000         | dec                 ecx
            //   660f6f05????????     |                     
            //   c745c780000000       | mov                 ebx, dword ptr [ebx + 0x28]
            //   c745cbbf000000       | dec                 ecx

        $sequence_8 = { 0f8778070000 e9???????? 48897560 41bc0f000000 4c896578 48c7457005000000 8b05???????? }
            // n = 7, score = 100
            //   0f8778070000         | inc                 ecx
            //   e9????????           |                     
            //   48897560             | mov                 ecx, ebp
            //   41bc0f000000         | inc                 ebp
            //   4c896578             | xor                 ecx, ecx
            //   48c7457005000000     | inc                 ebp
            //   8b05????????         |                     

        $sequence_9 = { 48832300 4883c308 488d0514ce0100 483bd8 75d8 b001 4883c420 }
            // n = 7, score = 100
            //   48832300             | inc                 esp
            //   4883c308             | cmp                 byte ptr [eax + 8], ah
            //   488d0514ce0100       | jne                 0x1d6b
            //   483bd8               | dec                 eax
            //   75d8                 | lea                 ecx, [0x2e4e1]
            //   b001                 | dec                 ecx
            //   4883c420             | mov                 ebx, esp

    condition:
        7 of them and filesize < 798720
}
