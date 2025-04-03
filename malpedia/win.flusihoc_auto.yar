rule win_flusihoc_auto {

    meta:
        id = "5QpZ87rV9u7iOBLzXLdzYD"
        fingerprint = "v1_sha256_410a07cce1b358109f5858d6a241fb0d56be6d17f2ab80d7283dacba4edb86ad"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.flusihoc."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flusihoc"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { a1???????? 33c4 89842450160000 53 56 8b7508 57 }
            // n = 7, score = 400
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   89842450160000       | mov                 dword ptr [esp + 0x1650], eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   57                   | push                edi

        $sequence_1 = { f3a5 c684246402000000 e8???????? 68d6000000 }
            // n = 4, score = 400
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   c684246402000000     | mov                 byte ptr [esp + 0x264], 0
            //   e8????????           |                     
            //   68d6000000           | push                0xd6

        $sequence_2 = { 8d4de8 3c7c 740f 3c0a }
            // n = 4, score = 400
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   3c7c                 | cmp                 al, 0x7c
            //   740f                 | je                  0x11
            //   3c0a                 | cmp                 al, 0xa

        $sequence_3 = { 52 ffd6 6a0a ff15???????? }
            // n = 4, score = 400
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   6a0a                 | push                0xa
            //   ff15????????         |                     

        $sequence_4 = { 8bec 83e4f8 b854160000 e8???????? a1???????? 33c4 }
            // n = 6, score = 400
            //   8bec                 | mov                 ebp, esp
            //   83e4f8               | and                 esp, 0xfffffff8
            //   b854160000           | mov                 eax, 0x1654
            //   e8????????           |                     
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp

        $sequence_5 = { 8d7c2428 50 f3a5 c684246402000000 }
            // n = 4, score = 400
            //   8d7c2428             | lea                 edi, [esp + 0x28]
            //   50                   | push                eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   c684246402000000     | mov                 byte ptr [esp + 0x264], 0

        $sequence_6 = { 6a00 50 c744242c44000000 e8???????? }
            // n = 4, score = 400
            //   6a00                 | push                0
            //   50                   | push                eax
            //   c744242c44000000     | mov                 dword ptr [esp + 0x2c], 0x44
            //   e8????????           |                     

        $sequence_7 = { ffd3 8b442410 6aff 50 ff15???????? 8b4c2410 51 }
            // n = 7, score = 400
            //   ffd3                 | call                ebx
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   51                   | push                ecx

        $sequence_8 = { 83f822 7506 fe8e42010000 3d14010000 7506 fe8633010000 }
            // n = 6, score = 400
            //   83f822               | cmp                 eax, 0x22
            //   7506                 | jne                 8
            //   fe8e42010000         | dec                 byte ptr [esi + 0x142]
            //   3d14010000           | cmp                 eax, 0x114
            //   7506                 | jne                 8
            //   fe8633010000         | inc                 byte ptr [esi + 0x133]

        $sequence_9 = { 57 6a40 8d442428 6a00 }
            // n = 4, score = 400
            //   57                   | push                edi
            //   6a40                 | push                0x40
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   6a00                 | push                0

        $sequence_10 = { f3a5 c684246401000000 e8???????? 83c40c }
            // n = 4, score = 400
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   c684246401000000     | mov                 byte ptr [esp + 0x164], 0
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_11 = { 83f828 7507 80864d01000004 83f822 7506 }
            // n = 5, score = 400
            //   83f828               | cmp                 eax, 0x28
            //   7507                 | jne                 9
            //   80864d01000004       | add                 byte ptr [esi + 0x14d], 4
            //   83f822               | cmp                 eax, 0x22
            //   7506                 | jne                 8

        $sequence_12 = { ff15???????? 8b4c2410 51 ffd6 8b542414 52 ffd6 }
            // n = 7, score = 400
            //   ff15????????         |                     
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx
            //   ffd6                 | call                esi

        $sequence_13 = { 8d8df8feffff 51 6a00 ff15???????? 8d95f4feffff 52 6806000200 }
            // n = 7, score = 200
            //   8d8df8feffff         | lea                 ecx, [ebp - 0x108]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8d95f4feffff         | lea                 edx, [ebp - 0x10c]
            //   52                   | push                edx
            //   6806000200           | push                0x20006

        $sequence_14 = { 6806000200 6a00 68???????? 6802000080 ff15???????? 85c0 752f }
            // n = 7, score = 200
            //   6806000200           | push                0x20006
            //   6a00                 | push                0
            //   68????????           |                     
            //   6802000080           | push                0x80000002
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   752f                 | jne                 0x31

        $sequence_15 = { 85c0 752f 8b8df4feffff 6804010000 8d85f8feffff 50 }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   752f                 | jne                 0x31
            //   8b8df4feffff         | mov                 ecx, dword ptr [ebp - 0x10c]
            //   6804010000           | push                0x104
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 319488
}
