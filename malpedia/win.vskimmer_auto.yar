rule win_vskimmer_auto {

    meta:
        id = "6y0DaBGdR5U9M9915LO9Xc"
        fingerprint = "v1_sha256_3a5deb80227e8fbb07640a24d78b7397cb1bc684cae3032e29532961361bc773"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.vskimmer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vskimmer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 33c0 8b8dbcfdffff 6bc009 0fb6840808e64100 6a08 c1e804 5e }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   8b8dbcfdffff         | mov                 ecx, dword ptr [ebp - 0x244]
            //   6bc009               | imul                eax, eax, 9
            //   0fb6840808e64100     | movzx               eax, byte ptr [eax + ecx + 0x41e608]
            //   6a08                 | push                8
            //   c1e804               | shr                 eax, 4
            //   5e                   | pop                 esi

        $sequence_1 = { ff15???????? 53 8d85ecfbffff 50 68???????? 8d85f8feffff }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   8d85ecfbffff         | lea                 eax, [ebp - 0x414]
            //   50                   | push                eax
            //   68????????           |                     
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]

        $sequence_2 = { 8d85b0fdffff 57 50 e8???????? 8d85a4faffff }
            // n = 5, score = 100
            //   8d85b0fdffff         | lea                 eax, [ebp - 0x250]
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d85a4faffff         | lea                 eax, [ebp - 0x55c]

        $sequence_3 = { ff75e8 8b4c3038 e8???????? 83f8ff 7506 834dec04 eba0 }
            // n = 7, score = 100
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   8b4c3038             | mov                 ecx, dword ptr [eax + esi + 0x38]
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   7506                 | jne                 8
            //   834dec04             | or                  dword ptr [ebp - 0x14], 4
            //   eba0                 | jmp                 0xffffffa2

        $sequence_4 = { e8???????? ff7508 8b10 8bc8 ff5208 8b4e10 884508 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8bc8                 | mov                 ecx, eax
            //   ff5208               | call                dword ptr [edx + 8]
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   884508               | mov                 byte ptr [ebp + 8], al

        $sequence_5 = { 3bc6 751c 85c9 7508 c70703000000 eb37 }
            // n = 6, score = 100
            //   3bc6                 | cmp                 eax, esi
            //   751c                 | jne                 0x1e
            //   85c9                 | test                ecx, ecx
            //   7508                 | jne                 0xa
            //   c70703000000         | mov                 dword ptr [edi], 3
            //   eb37                 | jmp                 0x39

        $sequence_6 = { 6a01 8d8dc8fcffff e8???????? e8???????? c3 6a08 }
            // n = 6, score = 100
            //   6a01                 | push                1
            //   8d8dc8fcffff         | lea                 ecx, [ebp - 0x338]
            //   e8????????           |                     
            //   e8????????           |                     
            //   c3                   | ret                 
            //   6a08                 | push                8

        $sequence_7 = { 7508 c70703000000 eb37 83f901 }
            // n = 4, score = 100
            //   7508                 | jne                 0xa
            //   c70703000000         | mov                 dword ptr [edi], 3
            //   eb37                 | jmp                 0x39
            //   83f901               | cmp                 ecx, 1

        $sequence_8 = { 75da 8b4508 8b4d10 8908 e9???????? 55 }
            // n = 6, score = 100
            //   75da                 | jne                 0xffffffdc
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   e9????????           |                     
            //   55                   | push                ebp

        $sequence_9 = { 8d858cf7ffff 8bcc 89a5c0f6ffff 50 e8???????? }
            // n = 5, score = 100
            //   8d858cf7ffff         | lea                 eax, [ebp - 0x874]
            //   8bcc                 | mov                 ecx, esp
            //   89a5c0f6ffff         | mov                 dword ptr [ebp - 0x940], esp
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 376832
}
