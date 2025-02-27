rule win_smanager_auto {

    meta:
        id = "4prW9kRJp8NYumqZUIuvEV"
        fingerprint = "v1_sha256_3f482517aa3a2ee02c64524a13e643b42a87540d5888bda3f974015b63620502"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.smanager."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.smanager"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7410 6a00 6a00 6830001100 }
            // n = 4, score = 600
            //   7410                 | je                  0x12
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6830001100           | push                0x110030

        $sequence_1 = { 83c602 6a22 56 e8???????? 83c408 }
            // n = 5, score = 600
            //   83c602               | add                 esi, 2
            //   6a22                 | push                0x22
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_2 = { 85f6 7417 8b0e 85c9 }
            // n = 4, score = 600
            //   85f6                 | test                esi, esi
            //   7417                 | je                  0x19
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   85c9                 | test                ecx, ecx

        $sequence_3 = { 8b4510 85c0 7407 50 }
            // n = 4, score = 600
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   50                   | push                eax

        $sequence_4 = { 740e 3d45270000 7407 3d46270000 }
            // n = 4, score = 600
            //   740e                 | je                  0x10
            //   3d45270000           | cmp                 eax, 0x2745
            //   7407                 | je                  9
            //   3d46270000           | cmp                 eax, 0x2746

        $sequence_5 = { 6a00 ff15???????? 8bf8 897e28 }
            // n = 4, score = 600
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   897e28               | mov                 dword ptr [esi + 0x28], edi

        $sequence_6 = { 51 51 ffd0 83c40c c7460800000000 }
            // n = 5, score = 600
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   ffd0                 | call                eax
            //   83c40c               | add                 esp, 0xc
            //   c7460800000000       | mov                 dword ptr [esi + 8], 0

        $sequence_7 = { 8b7604 6a00 6a00 56 68???????? 6a00 6a00 }
            // n = 7, score = 600
            //   8b7604               | mov                 esi, dword ptr [esi + 4]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   56                   | push                esi
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_8 = { ff15???????? 32c0 e9???????? 0f1005???????? }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   32c0                 | xor                 al, al
            //   e9????????           |                     
            //   0f1005????????       |                     

        $sequence_9 = { 0001 ce 50 0008 }
            // n = 4, score = 100
            //   0001                 | call                eax
            //   ce                   | add                 esp, 0xc
            //   50                   | mov                 dword ptr [esi + 8], 0
            //   0008                 | push                0xd

        $sequence_10 = { e8???????? 4c8d4c2430 488d4e10 4c8bc3 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   4c8d4c2430           | dec                 esp
            //   488d4e10             | lea                 ecx, [esp + 0x30]
            //   4c8bc3               | dec                 eax

        $sequence_11 = { 48897c2428 48896c2420 ff15???????? 85c0 }
            // n = 4, score = 100
            //   48897c2428           | lea                 ecx, [esi + 0x10]
            //   48896c2420           | dec                 esp
            //   ff15????????         |                     
            //   85c0                 | mov                 eax, ebx

        $sequence_12 = { 0007 b15a 0089b05a0089 b05a }
            // n = 4, score = 100
            //   0007                 | add                 byte ptr [ebx], al
            //   b15a                 | mov                 cl, 0x57
            //   0089b05a0089         | add                 byte ptr [eax], al
            //   b05a                 | or                  al, 0xc

        $sequence_13 = { 488d053bdc0000 488d542458 488d4c2420 41b801000000 4889442458 e8???????? 488d050adc0000 }
            // n = 7, score = 100
            //   488d053bdc0000       | dec                 eax
            //   488d542458           | lea                 esi, [eax - 0xc]
            //   488d4c2420           | dec                 eax
            //   41b801000000         | lea                 edi, [esp + 0x48]
            //   4889442458           | dec                 eax
            //   e8????????           |                     
            //   488d050adc0000       | mov                 dword ptr [esp + 0x58], ebx

        $sequence_14 = { 48895c2458 488bd9 ba02000000 488b4938 ff15???????? b90a000000 ff15???????? }
            // n = 7, score = 100
            //   48895c2458           | test                eax, eax
            //   488bd9               | je                  0xa9
            //   ba02000000           | dec                 eax
            //   488b4938             | cmp                 eax, 0xd
            //   ff15????????         |                     
            //   b90a000000           | jb                  0xa9
            //   ff15????????         |                     

        $sequence_15 = { 0008 53 4f 00ef }
            // n = 4, score = 100
            //   0008                 | add                 byte ptr [edi], al
            //   53                   | mov                 cl, 0x5a
            //   4f                   | add                 byte ptr [ecx - 0x76ffa550], cl
            //   00ef                 | mov                 al, 0x5a

        $sequence_16 = { 0000 80ed4a 0044feff ff900100008c }
            // n = 4, score = 100
            //   0000                 | jne                 0x1d
            //   80ed4a               | and                 eax, 0xfffffffe
            //   0044feff             | mov                 esi, dword ptr [esi + 4]
            //   ff900100008c         | push                0

        $sequence_17 = { 0003 b157 0000 0c0c }
            // n = 4, score = 100
            //   0003                 | add                 byte ptr [eax], al
            //   b157                 | sub                 ch, 0x4a
            //   0000                 | add                 byte ptr [esi + edi*8 - 1], al
            //   0c0c                 | call                dword ptr [eax - 0x73ffffff]

        $sequence_18 = { 488b05???????? 4833c4 48898570010000 4c8bf1 488d442438 4889442420 }
            // n = 6, score = 100
            //   488b05????????       |                     
            //   4833c4               | inc                 ecx
            //   48898570010000       | mov                 eax, 1
            //   4c8bf1               | dec                 eax
            //   488d442438           | mov                 dword ptr [esp + 0x58], eax
            //   4889442420           | dec                 eax

        $sequence_19 = { 0007 b15a 00c4 b15a }
            // n = 4, score = 100
            //   0007                 | add                 byte ptr [edi], al
            //   b15a                 | mov                 cl, 0x5a
            //   00c4                 | add                 byte ptr [edi], al
            //   b15a                 | mov                 cl, 0x5a

        $sequence_20 = { 0007 b15a 0007 b15a }
            // n = 4, score = 100
            //   0007                 | add                 byte ptr [ecx], al
            //   b15a                 | into                
            //   0007                 | push                eax
            //   b15a                 | add                 byte ptr [eax], cl

        $sequence_21 = { 488905???????? 4885c0 7519 488b8c2460020000 4833cc e8???????? 4881c470020000 }
            // n = 7, score = 100
            //   488905????????       |                     
            //   4885c0               | lea                 eax, [0xdc3b]
            //   7519                 | dec                 eax
            //   488b8c2460020000     | lea                 edx, [esp + 0x58]
            //   4833cc               | dec                 eax
            //   e8????????           |                     
            //   4881c470020000       | lea                 ecx, [esp + 0x20]

        $sequence_22 = { 4885c0 0f84a3000000 4883f80d 0f8299000000 488d70f4 488d7c2448 }
            // n = 6, score = 100
            //   4885c0               | dec                 eax
            //   0f84a3000000         | mov                 dword ptr [esp + 0x28], edi
            //   4883f80d             | dec                 eax
            //   0f8299000000         | mov                 dword ptr [esp + 0x20], ebp
            //   488d70f4             | test                eax, eax
            //   488d7c2448           | dec                 eax

        $sequence_23 = { 0000 0c0c 0c0c 0c0c 0c0c 0c0c 0102 }
            // n = 7, score = 100
            //   0000                 | push                0
            //   0c0c                 | mov                 edi, eax
            //   0c0c                 | mov                 dword ptr [esi + 0x28], edi
            //   0c0c                 | mov                 eax, dword ptr [esi + 8]
            //   0c0c                 | test                eax, eax
            //   0c0c                 | je                  0x24
            //   0102                 | test                al, 1

    condition:
        7 of them and filesize < 10013696
}
