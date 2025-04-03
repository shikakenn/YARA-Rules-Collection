rule win_oceansalt_auto {

    meta:
        id = "4JlMPQGC0bABa6hIfK9ARB"
        fingerprint = "v1_sha256_618191320109f3ef06ff0a1fecf4d89247c2a03c9ed872381bb347fb4c387d8b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.oceansalt."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oceansalt"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a00 6a02 8d8dc8fdffff 51 }
            // n = 4, score = 300
            //   6a00                 | dec                 eax
            //   6a02                 | lea                 edx, [esp + 0x100]
            //   8d8dc8fdffff         | inc                 ecx
            //   51                   | mov                 eax, 0x200

        $sequence_1 = { ff15???????? 5d c3 8b5508 68???????? 52 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   5d                   | inc                 ecx
            //   c3                   | mov                 byte ptr [ebx - 0x46], 0x47
            //   8b5508               | inc                 ecx
            //   68????????           |                     
            //   52                   | mov                 byte ptr [ebx - 0x45], 0x65

        $sequence_2 = { 0fb795f2fbffff 50 0fb785eefbffff 51 52 50 }
            // n = 6, score = 300
            //   0fb795f2fbffff       | push                0
            //   50                   | push                2
            //   0fb785eefbffff       | lea                 ecx, [ebp - 0x238]
            //   51                   | push                ecx
            //   52                   | push                1
            //   50                   | push                -1

        $sequence_3 = { 85c0 75ce 8b8dc4fdffff 8d85ccfdffff 50 }
            // n = 5, score = 300
            //   85c0                 | lea                 ebp, [0x10d1a]
            //   75ce                 | inc                 ecx
            //   8b8dc4fdffff         | mov                 byte ptr [ebx - 0x3b], al
            //   8d85ccfdffff         | inc                 ecx
            //   50                   | mov                 byte ptr [ebx - 0x47], 0x48

        $sequence_4 = { 6a04 50 8d55fc 52 }
            // n = 4, score = 300
            //   6a04                 | mov                 esp, ebx
            //   50                   | dec                 ecx
            //   8d55fc               | sar                 esp, 5
            //   52                   | dec                 esp

        $sequence_5 = { 668945f9 8845fb 6a07 8d45f4 50 56 }
            // n = 6, score = 300
            //   668945f9             | inc                 ecx
            //   8845fb               | mov                 byte ptr [ebx - 0x44], 0x74
            //   6a07                 | inc                 ecx
            //   8d45f4               | mov                 byte ptr [ebx - 0x43], 0x46
            //   50                   | inc                 ecx
            //   56                   | mov                 byte ptr [ebx - 0x42], 0x69

        $sequence_6 = { 6a04 53 ff15???????? 8bf8 85ff 743c }
            // n = 6, score = 300
            //   6a04                 | push                eax
            //   53                   | push                0
            //   ff15????????         |                     
            //   8bf8                 | push                2
            //   85ff                 | push                4
            //   743c                 | push                eax

        $sequence_7 = { 6a01 ff15???????? 6aff 50 ff15???????? 6a00 6a02 }
            // n = 7, score = 300
            //   6a01                 | jl                  0x9c
            //   ff15????????         |                     
            //   6aff                 | jae                 0x90
            //   50                   | dec                 eax
            //   ff15????????         |                     
            //   6a00                 | mov                 esi, ebx
            //   6a02                 | dec                 esp

        $sequence_8 = { eb26 488d442420 488d4c2420 482bd8 660f1f840000000000 0fb601 48ffc1 }
            // n = 7, score = 100
            //   eb26                 | dec                 ecx
            //   488d442420           | mov                 eax, dword ptr [eax + eax*8]
            //   488d4c2420           | and                 byte ptr [eax + ecx + 8], 0xfe
            //   482bd8               | jmp                 9
            //   660f1f840000000000     | jmp    0x28
            //   0fb601               | dec                 eax
            //   48ffc1               | lea                 eax, [esp + 0x20]

        $sequence_9 = { 85c0 7e3a 488b0d???????? 4c8d0df1140100 488d942400010000 41b800020000 }
            // n = 6, score = 100
            //   85c0                 | mov                 byte ptr [ecx + eax + 0x12e20], al
            //   7e3a                 | inc                 edi
            //   488b0d????????       |                     
            //   4c8d0df1140100       | dec                 eax
            //   488d942400010000     | lea                 ecx, [esp + 0x58]
            //   41b800020000         | dec                 eax

        $sequence_10 = { f644246010 740a c68424e002000000 eb1a }
            // n = 4, score = 100
            //   f644246010           | test                byte ptr [esp + 0x60], 0x10
            //   740a                 | je                  0xc
            //   c68424e002000000     | mov                 byte ptr [esp + 0x2e0], 0
            //   eb1a                 | jmp                 0x1c

        $sequence_11 = { 0f8c96000000 3b1d???????? 0f838a000000 488bf3 4c8be3 49c1fc05 4c8d2d1a0d0100 }
            // n = 7, score = 100
            //   0f8c96000000         | mov                 dword ptr [esp + 0x58], eax
            //   3b1d????????         |                     
            //   0f838a000000         | movzx               edx, word ptr [esp + 0x54]
            //   488bf3               | movzx               ecx, word ptr [esp + 0x50]
            //   4c8be3               | dec                 eax
            //   49c1fc05             | inc                 ebx
            //   4c8d2d1a0d0100       | dec                 eax

        $sequence_12 = { 48c1f805 4c8d0542720000 83e11f 486bc958 498b04c0 80640808fe eb07 }
            // n = 7, score = 100
            //   48c1f805             | dec                 eax
            //   4c8d0542720000       | sar                 eax, 5
            //   83e11f               | dec                 esp
            //   486bc958             | lea                 eax, [0x7242]
            //   498b04c0             | and                 ecx, 0x1f
            //   80640808fe           | dec                 eax
            //   eb07                 | imul                ecx, ecx, 0x58

        $sequence_13 = { 48ffc3 48ffc0 884bff 84c9 }
            // n = 4, score = 100
            //   48ffc3               | dec                 eax
            //   48ffc0               | arpl                di, cx
            //   884bff               | mov                 al, byte ptr [ecx + ebx + 0x11d]
            //   84c9                 | inc                 edx

        $sequence_14 = { 488d4c2458 4889442458 ff15???????? 0fb7542454 0fb74c2450 }
            // n = 5, score = 100
            //   488d4c2458           | movzx               eax, byte ptr [ecx]
            //   4889442458           | dec                 eax
            //   ff15????????         |                     
            //   0fb7542454           | inc                 ecx
            //   0fb74c2450           | jge                 0x1c

        $sequence_15 = { 7d1a 4863cf 8a84191d010000 42888401202e0100 ffc7 }
            // n = 5, score = 100
            //   7d1a                 | dec                 eax
            //   4863cf               | lea                 ecx, [esp + 0x20]
            //   8a84191d010000       | dec                 eax
            //   42888401202e0100     | sub                 ebx, eax
            //   ffc7                 | nop                 word ptr [eax + eax]

    condition:
        7 of them and filesize < 212992
}
