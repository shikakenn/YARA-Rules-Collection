rule win_veiledsignal_auto {

    meta:
        id = "47boMg4ls9MxyAOe1pheA4"
        fingerprint = "v1_sha256_9a6f92fe1de553c3683182fb5ec18013c09f63a6458b1c64fe2148d2dc0fd4cc"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.veiledsignal."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.veiledsignal"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bcf e8???????? 488bd7 4c8d05e3270400 83e23f }
            // n = 5, score = 100
            //   8bcf                 | mov                 dword ptr [esp + 0x28], ecx
            //   e8????????           |                     
            //   488bd7               | dec                 esp
            //   4c8d05e3270400       | mov                 ecx, eax
            //   83e23f               | xor                 edx, edx

        $sequence_1 = { 4863c9 488d15a8360400 488bc1 83e13f }
            // n = 4, score = 100
            //   4863c9               | cmp                 dword ptr [eax - 0x10], edx
            //   488d15a8360400       | je                  0x12a
            //   488bc1               | inc                 ecx
            //   83e13f               | mov                 eax, 6

        $sequence_2 = { 4d8be1 498be8 4c8bea 4b8b8cfef0e50400 4c8b15???????? }
            // n = 5, score = 100
            //   4d8be1               | lea                 eax, [ecx - 0x47ba]
            //   498be8               | dec                 eax
            //   4c8bea               | cmp                 dword ptr [ecx + 0x138], ebx
            //   4b8b8cfef0e50400     | jne                 0x667
            //   4c8b15????????       |                     

        $sequence_3 = { 4c8d05eeab0000 488bf9 488d15ecab0000 b904000000 e8???????? }
            // n = 5, score = 100
            //   4c8d05eeab0000       | dec                 eax
            //   488bf9               | mov                 ecx, dword ptr [ebp - 0x21]
            //   488d15ecab0000       | inc                 ebp
            //   b904000000           | xor                 eax, eax
            //   e8????????           |                     

        $sequence_4 = { 418bc6 4d8d4d10 4c8d3d3c680400 41be04000000 4c8d1c40 }
            // n = 5, score = 100
            //   418bc6               | cmp                 byte ptr [eax + edi + 0x3e], dl
            //   4d8d4d10             | dec                 ebp
            //   4c8d3d3c680400       | mov                 esi, dword ptr [esi + esi*8 + 0xf490]
            //   41be04000000         | xor                 edx, edx
            //   4c8d1c40             | dec                 ecx

        $sequence_5 = { 81f95a290000 752b 488d0df8030000 b801000000 48890d???????? }
            // n = 5, score = 100
            //   81f95a290000         | ret                 
            //   752b                 | dec                 eax
            //   488d0df8030000       | sub                 esp, 0x28
            //   b801000000           | dec                 esp
            //   48890d????????       |                     

        $sequence_6 = { 4c8bd1 b82a000000 0f05 c3 4c8bd1 b80f000000 }
            // n = 6, score = 100
            //   4c8bd1               | lea                 eax, [0x439b1]
            //   b82a000000           | dec                 edx
            //   0f05                 | mov                 ecx, dword ptr [eax + ebp*8]
            //   c3                   | dec                 eax
            //   4c8bd1               | lea                 edx, [ebp - 0x10]
            //   b80f000000           | dec                 edx

        $sequence_7 = { 7509 488d055f820400 eb04 4883c024 8938 e8???????? }
            // n = 6, score = 100
            //   7509                 | dec                 eax
            //   488d055f820400       | lea                 edi, [0x46e22]
            //   eb04                 | jmp                 0x24f
            //   4883c024             | inc                 esp
            //   8938                 | mov                 dword ptr [esp + 0x44], edx
            //   e8????????           |                     

        $sequence_8 = { 7513 488d15ad940000 488d0d86940000 e8???????? }
            // n = 4, score = 100
            //   7513                 | dec                 eax
            //   488d15ad940000       | lea                 ecx, [0x43edc]
            //   488d0d86940000       | inc                 ecx
            //   e8????????           |                     

        $sequence_9 = { 428844f13e 4b8b84e010e70400 42804cf03d04 38558f e9???????? ff15???????? 894597 }
            // n = 7, score = 100
            //   428844f13e           | inc                 ebp
            //   4b8b84e010e70400     | xor                 eax, eax
            //   42804cf03d04         | mov                 edx, 0xfa0
            //   38558f               | dec                 esp
            //   e9????????           |                     
            //   ff15????????         |                     
            //   894597               | lea                 edi, [0xffff5c05]

    condition:
        7 of them and filesize < 667648
}
