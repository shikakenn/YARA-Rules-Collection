rule win_bluehaze_auto {

    meta:
        id = "35XJ1VLVhdlDzA7yBfBFRm"
        fingerprint = "v1_sha256_108c6f0ac1c0898d4930ded73b9aadddbebc2ff25c5a1de920dfb159113df607"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.bluehaze."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bluehaze"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83c404 89856cfeffff c645fc24 85c0 742d 8b8d78feffff 68a4010000 }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   89856cfeffff         | mov                 dword ptr [ebp - 0x194], eax
            //   c645fc24             | mov                 byte ptr [ebp - 4], 0x24
            //   85c0                 | test                eax, eax
            //   742d                 | je                  0x2f
            //   8b8d78feffff         | mov                 ecx, dword ptr [ebp - 0x188]
            //   68a4010000           | push                0x1a4

        $sequence_1 = { c745e80f000000 8945e4 8845d4 e8???????? 56 8d45d4 50 }
            // n = 7, score = 100
            //   c745e80f000000       | mov                 dword ptr [ebp - 0x18], 0xf
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8845d4               | mov                 byte ptr [ebp - 0x2c], al
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax

        $sequence_2 = { e8???????? 83c404 33c0 c7467c0f000000 894678 884668 8bce }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   c7467c0f000000       | mov                 dword ptr [esi + 0x7c], 0xf
            //   894678               | mov                 dword ptr [esi + 0x78], eax
            //   884668               | mov                 byte ptr [esi + 0x68], al
            //   8bce                 | mov                 ecx, esi

        $sequence_3 = { 897e14 c7461000000000 c60600 83c61c 3bf3 75d8 50 }
            // n = 7, score = 100
            //   897e14               | mov                 dword ptr [esi + 0x14], edi
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   c60600               | mov                 byte ptr [esi], 0
            //   83c61c               | add                 esi, 0x1c
            //   3bf3                 | cmp                 esi, ebx
            //   75d8                 | jne                 0xffffffda
            //   50                   | push                eax

        $sequence_4 = { 8b5604 8b5214 68???????? 83c604 50 8d857cffffff 50 }
            // n = 7, score = 100
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   8b5214               | mov                 edx, dword ptr [edx + 0x14]
            //   68????????           |                     
            //   83c604               | add                 esi, 4
            //   50                   | push                eax
            //   8d857cffffff         | lea                 eax, [ebp - 0x84]
            //   50                   | push                eax

        $sequence_5 = { 85c0 7567 ff15???????? 3d6d270000 7573 8d856cfeffff 50 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7567                 | jne                 0x69
            //   ff15????????         |                     
            //   3d6d270000           | cmp                 eax, 0x276d
            //   7573                 | jne                 0x75
            //   8d856cfeffff         | lea                 eax, [ebp - 0x194]
            //   50                   | push                eax

        $sequence_6 = { 59 c3 8d8d60ffffff e9???????? 8d8d7cffffff e9???????? 8d8dd4feffff }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   8d8d60ffffff         | lea                 ecx, [ebp - 0xa0]
            //   e9????????           |                     
            //   8d8d7cffffff         | lea                 ecx, [ebp - 0x84]
            //   e9????????           |                     
            //   8d8dd4feffff         | lea                 ecx, [ebp - 0x12c]

        $sequence_7 = { 8d45ec 50 8bf1 ff15???????? 0fb755f4 8b4dec 69d2e8030000 }
            // n = 7, score = 100
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   8bf1                 | mov                 esi, ecx
            //   ff15????????         |                     
            //   0fb755f4             | movzx               edx, word ptr [ebp - 0xc]
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   69d2e8030000         | imul                edx, edx, 0x3e8

        $sequence_8 = { 83c408 8bc8 ff15???????? 8d4d80 51 8d8d08feffff }
            // n = 6, score = 100
            //   83c408               | add                 esp, 8
            //   8bc8                 | mov                 ecx, eax
            //   ff15????????         |                     
            //   8d4d80               | lea                 ecx, [ebp - 0x80]
            //   51                   | push                ecx
            //   8d8d08feffff         | lea                 ecx, [ebp - 0x1f8]

        $sequence_9 = { e9???????? 8d8d78fbffff e9???????? 8b542408 8d420c 8b8a04faffff 33c8 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8d78fbffff         | lea                 ecx, [ebp - 0x488]
            //   e9????????           |                     
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   8d420c               | lea                 eax, [edx + 0xc]
            //   8b8a04faffff         | mov                 ecx, dword ptr [edx - 0x5fc]
            //   33c8                 | xor                 ecx, eax

    condition:
        7 of them and filesize < 424960
}
