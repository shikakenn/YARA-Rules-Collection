rule win_roll_sling_auto {

    meta:
        id = "6lLFvs40Nsk4GMNYkWmxzB"
        fingerprint = "v1_sha256_9fbb0c1a994cbf47daa8ad072c8bc3b15bcfbdc43d87e63c5668a5130ba7c10c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.roll_sling."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.roll_sling"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 85c0 0f847ffdffff 488b17 488bca }
            // n = 5, score = 100
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   0f847ffdffff         | mov                 eax, edi
            //   488b17               | inc                 esp
            //   488bca               | mov                 byte ptr [eax], ah

        $sequence_1 = { 7417 488d05642e0100 483bc8 740b }
            // n = 4, score = 100
            //   7417                 | dec                 ecx
            //   488d05642e0100       | mov                 eax, esi
            //   483bc8               | dec                 eax
            //   740b                 | cmp                 edx, 0x10

        $sequence_2 = { 85c0 488b35???????? 480f4435???????? 4885f6 }
            // n = 4, score = 100
            //   85c0                 | mov                 eax, dword ptr [ebp - 0x78]
            //   488b35????????       |                     
            //   480f4435????????     |                     
            //   4885f6               | dec                 esp

        $sequence_3 = { ff15???????? 4c8b4308 4c89442440 488b03 83b88c00000000 0f8485000000 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   4c8b4308             | mov                 dword ptr [esp + 0x90], esp
            //   4c89442440           | dec                 eax
            //   488b03               | cmp                 esi, edx
            //   83b88c00000000       | jae                 0x196b
            //   0f8485000000         | mov                 ecx, 0xd

        $sequence_4 = { 2bc2 e9???????? 8b5f20 4903d8 448b6724 4d03e0 418bf6 }
            // n = 7, score = 100
            //   2bc2                 | dec                 esp
            //   e9????????           |                     
            //   8b5f20               | lea                 ecx, [0x17d5c]
            //   4903d8               | mov                 edx, 8
            //   448b6724             | dec                 eax
            //   4d03e0               | mov                 ecx, edi
            //   418bf6               | jmp                 0x1d2

        $sequence_5 = { 85c0 7429 448bc3 488d1521860000 498bce e8???????? 85c0 }
            // n = 7, score = 100
            //   85c0                 | dec                 esp
            //   7429                 | mov                 ebp, eax
            //   448bc3               | dec                 esp
            //   488d1521860000       | mov                 dword ptr [esp + 0x20], esi
            //   498bce               | dec                 esp
            //   e8????????           |                     
            //   85c0                 | lea                 ecx, [esp + 0x40]

        $sequence_6 = { eb05 b97e000000 ff15???????? 4533e4 488b742448 488b6c2440 488b7c2450 }
            // n = 7, score = 100
            //   eb05                 | dec                 esp
            //   b97e000000           | lea                 eax, [0xdd23]
            //   ff15????????         |                     
            //   4533e4               | jne                 0xa1
            //   488b742448           | xor                 ecx, ecx
            //   488b6c2440           | test                eax, eax
            //   488b7c2450           | cmove               esi, edi

        $sequence_7 = { 488bc2 488d0dbd150100 0f57c0 488d5308 48890b 488d4808 }
            // n = 6, score = 100
            //   488bc2               | ja                  0x12bf
            //   488d0dbd150100       | dec                 eax
            //   0f57c0               | mov                 eax, edx
            //   488d5308             | dec                 eax
            //   48890b               | sub                 eax, ecx
            //   488d4808             | ja                  0xdd2

        $sequence_8 = { 4c8bc7 ba92080000 488bcd ff15???????? 4c8d0c3b 4c8bc3 }
            // n = 6, score = 100
            //   4c8bc7               | dec                 esp
            //   ba92080000           | lea                 eax, [eax + 1]
            //   488bcd               | inc                 ebp
            //   ff15????????         |                     
            //   4c8d0c3b             | xor                 esp, esp
            //   4c8bc3               | dec                 esp

        $sequence_9 = { 4d0bf0 458b4550 418bf8 f7df 4923fe }
            // n = 5, score = 100
            //   4d0bf0               | cmp                 byte ptr [eax + edi*8 + 0x39], bl
            //   458b4550             | je                  0x3c7
            //   418bf8               | dec                 eax
            //   f7df                 | lea                 eax, [0xeea9]
            //   4923fe               | dec                 eax

    condition:
        7 of them and filesize < 299008
}
