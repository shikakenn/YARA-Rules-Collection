rule win_anchor_auto {

    meta:
        id = "5Sw5lrEAGHjcFyYBte6d8N"
        fingerprint = "v1_sha256_3a0df58657b834f57e58b8e626451593809f6f92127cc7c303935ce966927900"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.anchor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anchor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 740c 66c740016578 c6400365 eb0a 66c74001646c c640036c }
            // n = 6, score = 800
            //   740c                 | je                  0xe
            //   66c740016578         | mov                 word ptr [eax + 1], 0x7865
            //   c6400365             | mov                 byte ptr [eax + 3], 0x65
            //   eb0a                 | jmp                 0xc
            //   66c74001646c         | mov                 word ptr [eax + 1], 0x6c64
            //   c640036c             | mov                 byte ptr [eax + 3], 0x6c

        $sequence_1 = { 6aff 6a00 8d45bc c645fc03 }
            // n = 4, score = 600
            //   6aff                 | push                -1
            //   6a00                 | push                0
            //   8d45bc               | lea                 eax, [ebp - 0x44]
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3

        $sequence_2 = { b101 e8???????? e8???????? 84c0 }
            // n = 4, score = 600
            //   b101                 | mov                 cl, 1
            //   e8????????           |                     
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_3 = { 8d45f4 50 e8???????? cc ff25???????? 6a08 68???????? }
            // n = 7, score = 600
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   cc                   | int3                
            //   ff25????????         |                     
            //   6a08                 | push                8
            //   68????????           |                     

        $sequence_4 = { 8d8dbcfeffff e8???????? 68???????? 8d8dbcfeffff e8???????? 56 8d8dbcfeffff }
            // n = 7, score = 600
            //   8d8dbcfeffff         | lea                 ecx, [ebp - 0x144]
            //   e8????????           |                     
            //   68????????           |                     
            //   8d8dbcfeffff         | lea                 ecx, [ebp - 0x144]
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d8dbcfeffff         | lea                 ecx, [ebp - 0x144]

        $sequence_5 = { 2bc2 3bca 7701 48 }
            // n = 4, score = 600
            //   2bc2                 | mov                 word ptr [eax + 4], cx
            //   3bca                 | lea                 ecx, [edi + 0x77]
            //   7701                 | dec                 eax
            //   48                   | mov                 eax, dword ptr [ebx + 0x38]

        $sequence_6 = { ff15???????? 8b15???????? 8bc8 2bc2 }
            // n = 4, score = 600
            //   ff15????????         |                     
            //   8b15????????         |                     
            //   8bc8                 | mov                 ecx, eax
            //   2bc2                 | sub                 eax, edx

        $sequence_7 = { e8???????? 8b0d???????? c1e102 51 }
            // n = 4, score = 600
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   c1e102               | shl                 ecx, 2
            //   51                   | push                ecx

        $sequence_8 = { 8b4638 66897810 8b4638 5f 66894812 33c9 }
            // n = 6, score = 600
            //   8b4638               | mov                 eax, dword ptr [esi + 0x38]
            //   66897810             | mov                 word ptr [eax + 0x10], di
            //   8b4638               | mov                 eax, dword ptr [esi + 0x38]
            //   5f                   | pop                 edi
            //   66894812             | mov                 word ptr [eax + 0x12], cx
            //   33c9                 | xor                 ecx, ecx

        $sequence_9 = { 7509 33d2 33c9 e8???????? }
            // n = 4, score = 400
            //   7509                 | jne                 0xb
            //   33d2                 | xor                 edx, edx
            //   33c9                 | xor                 ecx, ecx
            //   e8????????           |                     

        $sequence_10 = { 488d0d5e160400 e8???????? 488b8d80010000 e8???????? }
            // n = 4, score = 200
            //   488d0d5e160400       | movzx               eax, al
            //   e8????????           |                     
            //   488b8d80010000       | test                eax, eax
            //   e8????????           |                     

        $sequence_11 = { 448865b7 4c8bc0 4c2bc3 488bd3 488d4db7 e8???????? 488d55b7 }
            // n = 7, score = 200
            //   448865b7             | lea                 eax, [0x2d12c]
            //   4c8bc0               | dec                 eax
            //   4c2bc3               | lea                 ecx, [0x1a05d]
            //   488bd3               | nop                 
            //   488d4db7             | dec                 eax
            //   e8????????           |                     
            //   488d55b7             | lea                 ecx, [0x2d148]

        $sequence_12 = { 488d0d5c510200 e8???????? 488d8558010000 48894528 }
            // n = 4, score = 200
            //   488d0d5c510200       | lea                 esp, [ebp + 0xc8]
            //   e8????????           |                     
            //   488d8558010000       | dec                 eax
            //   48894528             | lea                 ecx, [0x2995a]

        $sequence_13 = { 488d0d5d2c0300 e8???????? 488b8d08010000 e8???????? }
            // n = 4, score = 200
            //   488d0d5d2c0300       | dec                 eax
            //   e8????????           |                     
            //   488b8d08010000       | mov                 dword ptr [eax], 0
            //   e8????????           |                     

        $sequence_14 = { 488d0d5c490300 e8???????? 488d0d28490300 e8???????? }
            // n = 4, score = 200
            //   488d0d5c490300       | mov                 ecx, eax
            //   e8????????           |                     
            //   488d0d28490300       | dec                 eax
            //   e8????????           |                     

        $sequence_15 = { 488d0d5a920200 e8???????? 488b8de0000000 e8???????? }
            // n = 4, score = 200
            //   488d0d5a920200       | dec                 eax
            //   e8????????           |                     
            //   488b8de0000000       | mov                 dword ptr [eax], 0
            //   e8????????           |                     

        $sequence_16 = { 4903c7 c64405b032 4903c7 c64405b02e }
            // n = 4, score = 200
            //   4903c7               | cmp                 dword ptr [ebp + 0x188], eax
            //   c64405b032           | jbe                 0x15
            //   4903c7               | dec                 eax
            //   c64405b02e           | lea                 ecx, [0x4165e]

        $sequence_17 = { 448d4f01 418bd1 448d5772 668908 8d4f75 488b4310 66894802 }
            // n = 7, score = 200
            //   448d4f01             | mov                 ecx, dword ptr [ebp + 0x180]
            //   418bd1               | dec                 eax
            //   448d5772             | lea                 ecx, [0x4165e]
            //   668908               | dec                 eax
            //   8d4f75               | mov                 ecx, dword ptr [ebp + 0x180]
            //   488b4310             | dec                 eax
            //   66894802             | cmp                 dword ptr [ebp + 0x188], eax

        $sequence_18 = { 75ae 8bc7 483d00040000 0f83c8010000 44888c05c0050000 }
            // n = 5, score = 200
            //   75ae                 | dec                 eax
            //   8bc7                 | lea                 ecx, [0x4165e]
            //   483d00040000         | dec                 eax
            //   0f83c8010000         | mov                 ecx, dword ptr [ebp + 0x180]
            //   44888c05c0050000     | dec                 eax

        $sequence_19 = { 488d0d5da00100 e8???????? 90 488d0d48d10200 }
            // n = 4, score = 200
            //   488d0d5da00100       | dec                 eax
            //   e8????????           |                     
            //   90                   | mov                 dword ptr [eax + 8], 0
            //   488d0d48d10200       | dec                 eax

        $sequence_20 = { 488b4338 66894804 8d4f77 488b4338 66894806 8d4f6f 488b4338 }
            // n = 7, score = 200
            //   488b4338             | dec                 eax
            //   66894804             | lea                 eax, [0x2d12c]
            //   8d4f77               | dec                 eax
            //   488b4338             | lea                 esp, [ebp + 0x108]
            //   66894806             | dec                 eax
            //   8d4f6f               | lea                 ecx, [0x4165e]
            //   488b4338             | dec                 eax

        $sequence_21 = { 488d0d5a870200 e8???????? 90 488b8500010000 }
            // n = 4, score = 200
            //   488d0d5a870200       | dec                 eax
            //   e8????????           |                     
            //   90                   | lea                 ecx, [0x2875a]
            //   488b8500010000       | nop                 

    condition:
        7 of them and filesize < 778240
}
