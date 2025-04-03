rule win_unidentified_037_auto {

    meta:
        id = "1H7QxhbRzWwgGnFETEu3E0"
        fingerprint = "v1_sha256_1d2de4db39b1900c0def6a2d43ab52baecc925bfad5faca5ff76425cebd9b30d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_037."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_037"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { b9ff000000 33c0 8dbc242d040000 889c242c040000 be???????? }
            // n = 5, score = 100
            //   b9ff000000           | mov                 ecx, 0xff
            //   33c0                 | xor                 eax, eax
            //   8dbc242d040000       | lea                 edi, [esp + 0x42d]
            //   889c242c040000       | mov                 byte ptr [esp + 0x42c], bl
            //   be????????           |                     

        $sequence_1 = { 52 e8???????? 55 8d4c2414 }
            // n = 4, score = 100
            //   52                   | push                edx
            //   e8????????           |                     
            //   55                   | push                ebp
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

        $sequence_2 = { e8???????? 56 8d8c24ac010000 8b542420 2bd6 8d8414ac010000 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d8c24ac010000       | lea                 ecx, [esp + 0x1ac]
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   2bd6                 | sub                 edx, esi
            //   8d8414ac010000       | lea                 eax, [esp + edx + 0x1ac]
            //   50                   | push                eax

        $sequence_3 = { 83c704 48 75e2 8b442410 5b 33d2 33ff }
            // n = 7, score = 100
            //   83c704               | add                 edi, 4
            //   48                   | dec                 eax
            //   75e2                 | jne                 0xffffffe4
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   5b                   | pop                 ebx
            //   33d2                 | xor                 edx, edx
            //   33ff                 | xor                 edi, edi

        $sequence_4 = { 8d8424b8040000 52 50 ff15???????? 8d8c24b8040000 51 ff15???????? }
            // n = 7, score = 100
            //   8d8424b8040000       | lea                 eax, [esp + 0x4b8]
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d8c24b8040000       | lea                 ecx, [esp + 0x4b8]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_5 = { 6a00 8d4c2424 681f000f00 51 ffd5 85c0 }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   681f000f00           | push                0xf001f
            //   51                   | push                ecx
            //   ffd5                 | call                ebp
            //   85c0                 | test                eax, eax

        $sequence_6 = { 83c002 4f 75f1 8b4604 894e08 66c704480000 8b4d14 }
            // n = 7, score = 100
            //   83c002               | add                 eax, 2
            //   4f                   | dec                 edi
            //   75f1                 | jne                 0xfffffff3
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   894e08               | mov                 dword ptr [esi + 8], ecx
            //   66c704480000         | mov                 word ptr [eax + ecx*2], 0
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]

        $sequence_7 = { 3bf5 7639 8b542418 55 8d4c2414 8d3c32 57 }
            // n = 7, score = 100
            //   3bf5                 | cmp                 esi, ebp
            //   7639                 | jbe                 0x3b
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   55                   | push                ebp
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   8d3c32               | lea                 edi, [edx + esi]
            //   57                   | push                edi

        $sequence_8 = { 03f3 81ec84020000 b9a1000000 8bfc f3a5 e8???????? 85c0 }
            // n = 7, score = 100
            //   03f3                 | add                 esi, ebx
            //   81ec84020000         | sub                 esp, 0x284
            //   b9a1000000           | mov                 ecx, 0xa1
            //   8bfc                 | mov                 edi, esp
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8801 eb09 51 e8???????? 83c404 8b4c240c 895e04 }
            // n = 7, score = 100
            //   8801                 | mov                 byte ptr [ecx], al
            //   eb09                 | jmp                 0xb
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   895e04               | mov                 dword ptr [esi + 4], ebx

    condition:
        7 of them and filesize < 167936
}
