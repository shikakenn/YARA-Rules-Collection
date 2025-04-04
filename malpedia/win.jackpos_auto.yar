rule win_jackpos_auto {

    meta:
        id = "7PyFBqfWxMXdsENR14y6SC"
        fingerprint = "v1_sha256_e318334295704491926f566878a765af2b4635b235cabb0b05edeaa2585792fc"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.jackpos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jackpos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 03f3 50 8d0472 eb6a 83f808 7204 }
            // n = 6, score = 100
            //   03f3                 | add                 esi, ebx
            //   50                   | push                eax
            //   8d0472               | lea                 eax, [edx + esi*2]
            //   eb6a                 | jmp                 0x6c
            //   83f808               | cmp                 eax, 8
            //   7204                 | jb                  6

        $sequence_1 = { 8b07 85c0 7454 8b5934 8b7120 8b1b 8b36 }
            // n = 7, score = 100
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   85c0                 | test                eax, eax
            //   7454                 | je                  0x56
            //   8b5934               | mov                 ebx, dword ptr [ecx + 0x34]
            //   8b7120               | mov                 esi, dword ptr [ecx + 0x20]
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   8b36                 | mov                 esi, dword ptr [esi]

        $sequence_2 = { 8b4dd4 8bc1 83fa08 7303 8d45d4 8d1c78 85db }
            // n = 7, score = 100
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   8bc1                 | mov                 eax, ecx
            //   83fa08               | cmp                 edx, 8
            //   7303                 | jae                 5
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   8d1c78               | lea                 ebx, [eax + edi*2]
            //   85db                 | test                ebx, ebx

        $sequence_3 = { 895df0 3bf3 0f849c000000 391e 0f8594000000 6a10 e8???????? }
            // n = 7, score = 100
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   3bf3                 | cmp                 esi, ebx
            //   0f849c000000         | je                  0xa2
            //   391e                 | cmp                 dword ptr [esi], ebx
            //   0f8594000000         | jne                 0x9a
            //   6a10                 | push                0x10
            //   e8????????           |                     

        $sequence_4 = { 2bf8 6a00 57 bb01000000 8d75d4 e8???????? 8b45b4 }
            // n = 7, score = 100
            //   2bf8                 | sub                 edi, eax
            //   6a00                 | push                0
            //   57                   | push                edi
            //   bb01000000           | mov                 ebx, 1
            //   8d75d4               | lea                 esi, [ebp - 0x2c]
            //   e8????????           |                     
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]

        $sequence_5 = { 1bc0 83e0fe 83c001 7511 3bf7 }
            // n = 5, score = 100
            //   1bc0                 | sbb                 eax, eax
            //   83e0fe               | and                 eax, 0xfffffffe
            //   83c001               | add                 eax, 1
            //   7511                 | jne                 0x13
            //   3bf7                 | cmp                 esi, edi

        $sequence_6 = { 52 8b55bc 57 8d4dac 51 0fb7c0 52 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   8b55bc               | mov                 edx, dword ptr [ebp - 0x44]
            //   57                   | push                edi
            //   8d4dac               | lea                 ecx, [ebp - 0x54]
            //   51                   | push                ecx
            //   0fb7c0               | movzx               eax, ax
            //   52                   | push                edx

        $sequence_7 = { 897df0 3bfe 762a 8da42400000000 8b450c 50 }
            // n = 6, score = 100
            //   897df0               | mov                 dword ptr [ebp - 0x10], edi
            //   3bfe                 | cmp                 edi, esi
            //   762a                 | jbe                 0x2c
            //   8da42400000000       | lea                 esp, [esp]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax

        $sequence_8 = { 52 8d4584 50 eb3e 837d9000 }
            // n = 5, score = 100
            //   52                   | push                edx
            //   8d4584               | lea                 eax, [ebp - 0x7c]
            //   50                   | push                eax
            //   eb3e                 | jmp                 0x40
            //   837d9000             | cmp                 dword ptr [ebp - 0x70], 0

        $sequence_9 = { 3b7d10 747e 83c704 83f808 7204 8b0f }
            // n = 6, score = 100
            //   3b7d10               | cmp                 edi, dword ptr [ebp + 0x10]
            //   747e                 | je                  0x80
            //   83c704               | add                 edi, 4
            //   83f808               | cmp                 eax, 8
            //   7204                 | jb                  6
            //   8b0f                 | mov                 ecx, dword ptr [edi]

    condition:
        7 of them and filesize < 319488
}
