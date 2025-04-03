rule win_zeroaccess_auto {

    meta:
        id = "6xgJlkPvflw94mKZn3zBX3"
        fingerprint = "v1_sha256_b8098d3dcd80de1c46676c7e1dd2cdf56db87599f68b360b87ffc70001011948"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.zeroaccess."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeroaccess"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 85c0 7408 ff15???????? eb02 }
            // n = 4, score = 300
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   ff15????????         |                     
            //   eb02                 | jmp                 4

        $sequence_1 = { 8b01 ff761c ff7618 ff5004 }
            // n = 4, score = 200
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   ff761c               | push                dword ptr [esi + 0x1c]
            //   ff7618               | push                dword ptr [esi + 0x18]
            //   ff5004               | call                dword ptr [eax + 4]

        $sequence_2 = { 8d45fc 50 6a01 8d45f4 50 }
            // n = 5, score = 200
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   6a01                 | push                1
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax

        $sequence_3 = { ff15???????? 85c0 7407 b8e3030000 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   b8e3030000           | mov                 eax, 0x3e3

        $sequence_4 = { 45 33c0 48 83c9ff c744242804000000 48 }
            // n = 6, score = 200
            //   45                   | inc                 ebp
            //   33c0                 | xor                 eax, eax
            //   48                   | dec                 eax
            //   83c9ff               | or                  ecx, 0xffffffff
            //   c744242804000000     | mov                 dword ptr [esp + 0x28], 4
            //   48                   | dec                 eax

        $sequence_5 = { 3bc1 7604 83c8ff c3 }
            // n = 4, score = 200
            //   3bc1                 | cmp                 eax, ecx
            //   7604                 | jbe                 6
            //   83c8ff               | or                  eax, 0xffffffff
            //   c3                   | ret                 

        $sequence_6 = { 56 8d45f8 50 ff15???????? 6a01 8d45f8 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_7 = { 6889001200 8d45fc 50 ff15???????? }
            // n = 4, score = 200
            //   6889001200           | push                0x120089
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_8 = { bf03000040 eb05 bf010000c0 85ff }
            // n = 4, score = 200
            //   bf03000040           | mov                 edi, 0x40000003
            //   eb05                 | jmp                 7
            //   bf010000c0           | mov                 edi, 0xc0000001
            //   85ff                 | test                edi, edi

        $sequence_9 = { 8d4e08 e8???????? f644240801 740c }
            // n = 4, score = 200
            //   8d4e08               | lea                 ecx, [esi + 8]
            //   e8????????           |                     
            //   f644240801           | test                byte ptr [esp + 8], 1
            //   740c                 | je                  0xe

        $sequence_10 = { 50 6819000200 8d45f8 50 ff15???????? 85c0 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   6819000200           | push                0x20019
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_11 = { 48 83e1f0 48 8bc1 e8???????? 48 8b05???????? }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   83e1f0               | and                 ecx, 0xfffffff0
            //   48                   | dec                 eax
            //   8bc1                 | mov                 eax, ecx
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8b05????????         |                     

        $sequence_12 = { 8b4318 48 8b5328 48 8b30 48 8bce }
            // n = 7, score = 100
            //   8b4318               | mov                 eax, dword ptr [ebx + 0x18]
            //   48                   | dec                 eax
            //   8b5328               | mov                 edx, dword ptr [ebx + 0x28]
            //   48                   | dec                 eax
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   48                   | dec                 eax
            //   8bce                 | mov                 ecx, esi

        $sequence_13 = { 3b05???????? 7316 48 8d0d56560000 48 8bd3 }
            // n = 6, score = 100
            //   3b05????????         |                     
            //   7316                 | jae                 0x18
            //   48                   | dec                 eax
            //   8d0d56560000         | lea                 ecx, [0x5656]
            //   48                   | dec                 eax
            //   8bd3                 | mov                 edx, ebx

    condition:
        7 of them and filesize < 172032
}
