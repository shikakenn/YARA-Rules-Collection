rule win_beepservice_auto {

    meta:
        id = "KJFPNRP056Tu67FYQSm6a"
        fingerprint = "v1_sha256_e9b2216bc0e3755a16cf68b15ef3152aac9ea65a9d59c9db364017acc5ba848e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.beepservice."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.beepservice"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ffd6 8bc8 ff15???????? 50 ff15???????? }
            // n = 5, score = 600
            //   ffd6                 | call                esi
            //   8bc8                 | mov                 ecx, eax
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_1 = { 8b0d???????? 68???????? ffd6 8bc8 }
            // n = 4, score = 600
            //   8b0d????????         |                     
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   8bc8                 | mov                 ecx, eax

        $sequence_2 = { 83c408 e9???????? 68???????? e8???????? 83c404 6a00 }
            // n = 6, score = 500
            //   83c408               | add                 esp, 8
            //   e9????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   6a00                 | push                0

        $sequence_3 = { 7512 6888130000 68???????? e8???????? }
            // n = 4, score = 500
            //   7512                 | jne                 0x14
            //   6888130000           | push                0x1388
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_4 = { 83f801 7505 e8???????? 68???????? 68???????? }
            // n = 5, score = 500
            //   83f801               | cmp                 eax, 1
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   68????????           |                     
            //   68????????           |                     

        $sequence_5 = { ff15???????? 50 68???????? e8???????? 83c408 e9???????? 68???????? }
            // n = 7, score = 500
            //   ff15????????         |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   e9????????           |                     
            //   68????????           |                     

        $sequence_6 = { 683f000f00 6a00 68???????? ff15???????? }
            // n = 4, score = 500
            //   683f000f00           | push                0xf003f
            //   6a00                 | push                0
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_7 = { 53 ffd7 56 ff15???????? 85c0 5b }
            // n = 6, score = 400
            //   53                   | push                ebx
            //   ffd7                 | call                edi
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   5b                   | pop                 ebx

        $sequence_8 = { 8d85fcfdffff 68???????? 50 ff15???????? 83c410 }
            // n = 5, score = 400
            //   8d85fcfdffff         | lea                 eax, [ebp - 0x204]
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c410               | add                 esp, 0x10

        $sequence_9 = { 6a14 57 68???????? 89442420 }
            // n = 4, score = 400
            //   6a14                 | push                0x14
            //   57                   | push                edi
            //   68????????           |                     
            //   89442420             | mov                 dword ptr [esp + 0x20], eax

        $sequence_10 = { 6a01 56 ff15???????? 85c0 7513 ff15???????? }
            // n = 6, score = 400
            //   6a01                 | push                1
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7513                 | jne                 0x15
            //   ff15????????         |                     

        $sequence_11 = { 741c 3975fc 7517 57 ff15???????? 68???????? e8???????? }
            // n = 7, score = 400
            //   741c                 | je                  0x1e
            //   3975fc               | cmp                 dword ptr [ebp - 4], esi
            //   7517                 | jne                 0x19
            //   57                   | push                edi
            //   ff15????????         |                     
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_12 = { 8bec 81ec04020000 56 57 68???????? 68???????? }
            // n = 6, score = 400
            //   8bec                 | mov                 ebp, esp
            //   81ec04020000         | sub                 esp, 0x204
            //   56                   | push                esi
            //   57                   | push                edi
            //   68????????           |                     
            //   68????????           |                     

        $sequence_13 = { f3a4 8b7b08 83c9ff f2ae f7d1 49 83f914 }
            // n = 7, score = 300
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b7b08               | mov                 edi, dword ptr [ebx + 8]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   83f914               | cmp                 ecx, 0x14

        $sequence_14 = { 52 6800240000 68???????? 56 }
            // n = 4, score = 300
            //   52                   | push                edx
            //   6800240000           | push                0x2400
            //   68????????           |                     
            //   56                   | push                esi

        $sequence_15 = { 8b5304 83c9ff 8bfa 33c0 f2ae f7d1 49 }
            // n = 7, score = 300
            //   8b5304               | mov                 edx, dword ptr [ebx + 4]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   8bfa                 | mov                 edi, edx
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx

        $sequence_16 = { 8b8dfcfdffff 51 ff15???????? 8985f0fdffff 83bdf0fdffff00 }
            // n = 5, score = 200
            //   8b8dfcfdffff         | mov                 ecx, dword ptr [ebp - 0x204]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8985f0fdffff         | mov                 dword ptr [ebp - 0x210], eax
            //   83bdf0fdffff00       | cmp                 dword ptr [ebp - 0x210], 0

        $sequence_17 = { 8b5104 52 68???????? e8???????? 83c408 eb0a }
            // n = 6, score = 200
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   52                   | push                edx
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   eb0a                 | jmp                 0xc

        $sequence_18 = { e8???????? 83c40c 6a20 6a00 68???????? e8???????? 83c40c }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a20                 | push                0x20
            //   6a00                 | push                0
            //   68????????           |                     
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_19 = { 8b4508 50 56 682a040000 ff15???????? }
            // n = 5, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   56                   | push                esi
            //   682a040000           | push                0x42a
            //   ff15????????         |                     

        $sequence_20 = { 50 6a01 e8???????? 83c414 a1???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   6a01                 | push                1
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   a1????????           |                     

        $sequence_21 = { e8???????? 8bb42438010000 8b3d???????? 8d4c240c 51 53 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8bb42438010000       | mov                 esi, dword ptr [esp + 0x138]
            //   8b3d????????         |                     
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   51                   | push                ecx
            //   53                   | push                ebx

        $sequence_22 = { 6a00 6a04 e8???????? 83c414 85c0 7510 ff15???????? }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12
            //   ff15????????         |                     

        $sequence_23 = { 668935???????? 7e15 b299 8a9874304000 32da }
            // n = 5, score = 100
            //   668935????????       |                     
            //   7e15                 | jle                 0x17
            //   b299                 | mov                 dl, 0x99
            //   8a9874304000         | mov                 bl, byte ptr [eax + 0x403074]
            //   32da                 | xor                 bl, dl

        $sequence_24 = { eb08 c744240c2a040000 8b54242c 8d4c2400 89542414 8b15???????? 56 }
            // n = 7, score = 100
            //   eb08                 | jmp                 0xa
            //   c744240c2a040000     | mov                 dword ptr [esp + 0xc], 0x42a
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   8d4c2400             | lea                 ecx, [esp]
            //   89542414             | mov                 dword ptr [esp + 0x14], edx
            //   8b15????????         |                     
            //   56                   | push                esi

        $sequence_25 = { 5e 5b 81c428010000 c3 5f 5e 33c0 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   81c428010000         | add                 esp, 0x128
            //   c3                   | ret                 
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax

        $sequence_26 = { ff248548144000 6888130000 6a01 6a00 6a00 6a03 }
            // n = 6, score = 100
            //   ff248548144000       | jmp                 dword ptr [eax*4 + 0x401448]
            //   6888130000           | push                0x1388
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a03                 | push                3

    condition:
        7 of them and filesize < 253952
}
