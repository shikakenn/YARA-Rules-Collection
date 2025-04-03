rule win_sedreco_auto {

    meta:
        id = "1z2jBrauVpU2Ehj9sz28Bl"
        fingerprint = "v1_sha256_79e378080daf9957ad7b702ae6910bfba39dd77a995aedb850c5514668bb56cb"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sedreco."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sedreco"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 89450c 56 85c0 }
            // n = 4, score = 2600
            //   e8????????           |                     
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   56                   | push                esi
            //   85c0                 | test                eax, eax

        $sequence_1 = { 8bec 51 836d0804 53 56 }
            // n = 5, score = 2600
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   836d0804             | sub                 dword ptr [ebp + 8], 4
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_2 = { c645ff30 e8???????? 85c0 7505 }
            // n = 4, score = 2600
            //   c645ff30             | mov                 byte ptr [ebp - 1], 0x30
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7

        $sequence_3 = { 8b750c 56 e8???????? 6a08 }
            // n = 4, score = 2600
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   e8????????           |                     
            //   6a08                 | push                8

        $sequence_4 = { 50 68???????? 6a0d 68???????? }
            // n = 4, score = 2500
            //   50                   | push                eax
            //   68????????           |                     
            //   6a0d                 | push                0xd
            //   68????????           |                     

        $sequence_5 = { 51 6802020000 68???????? 50 }
            // n = 4, score = 2400
            //   51                   | push                ecx
            //   6802020000           | push                0x202
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_6 = { 7ce0 a1???????? 5e 85c0 }
            // n = 4, score = 2400
            //   7ce0                 | jl                  0xffffffe2
            //   a1????????           |                     
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax

        $sequence_7 = { 7411 6a04 68???????? 68???????? }
            // n = 4, score = 2400
            //   7411                 | je                  0x13
            //   6a04                 | push                4
            //   68????????           |                     
            //   68????????           |                     

        $sequence_8 = { ffd6 8b0d???????? 894170 85c0 }
            // n = 4, score = 2200
            //   ffd6                 | call                esi
            //   8b0d????????         |                     
            //   894170               | mov                 dword ptr [ecx + 0x70], eax
            //   85c0                 | test                eax, eax

        $sequence_9 = { ff15???????? 83c604 81fe???????? 7ce0 a1???????? }
            // n = 5, score = 2200
            //   ff15????????         |                     
            //   83c604               | add                 esi, 4
            //   81fe????????         |                     
            //   7ce0                 | jl                  0xffffffe2
            //   a1????????           |                     

        $sequence_10 = { e8???????? 83c40c b8f6eeeeee 8b4df0 64890d00000000 }
            // n = 5, score = 2200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   b8f6eeeeee           | mov                 eax, 0xeeeeeef6
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_11 = { ffd6 8b0d???????? 898180000000 85c0 }
            // n = 4, score = 2200
            //   ffd6                 | call                esi
            //   8b0d????????         |                     
            //   898180000000         | mov                 dword ptr [ecx + 0x80], eax
            //   85c0                 | test                eax, eax

        $sequence_12 = { 56 be???????? 8b06 85c0 740f 50 }
            // n = 6, score = 2200
            //   56                   | push                esi
            //   be????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   50                   | push                eax

        $sequence_13 = { ffd0 c745fcfeffffff e8???????? 33c0 }
            // n = 4, score = 2200
            //   ffd0                 | call                eax
            //   c745fcfeffffff       | mov                 dword ptr [ebp - 4], 0xfffffffe
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_14 = { 6a01 68???????? ff35???????? ff15???????? ffd0 }
            // n = 5, score = 1100
            //   6a01                 | push                1
            //   68????????           |                     
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   ffd0                 | call                eax

        $sequence_15 = { 68???????? 6a00 6a00 ffd6 50 68???????? 6aff }
            // n = 7, score = 500
            //   68????????           |                     
            //   6a00                 | push                eax
            //   6a00                 | jl                  0xffffffe2
            //   ffd6                 | pop                 esi
            //   50                   | test                eax, eax
            //   68????????           |                     
            //   6aff                 | add                 esi, 4

        $sequence_16 = { 8b35???????? 83c404 6a00 68???????? 6aff 68???????? 6a00 }
            // n = 7, score = 500
            //   8b35????????         |                     
            //   83c404               | push                8
            //   6a00                 | mov                 dword ptr [ebp + 0xc], eax
            //   68????????           |                     
            //   6aff                 | push                esi
            //   68????????           |                     
            //   6a00                 | test                eax, eax

        $sequence_17 = { 6800010000 6a00 68???????? e8???????? 6800020000 }
            // n = 5, score = 500
            //   6800010000           | pop                 esi
            //   6a00                 | push                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   6800020000           | mov                 eax, dword ptr [esi]

        $sequence_18 = { 488b15???????? 48c7c101000080 488b05???????? ff9038010000 }
            // n = 4, score = 500
            //   488b15????????       |                     
            //   48c7c101000080       | inc                 ecx
            //   488b05????????       |                     
            //   ff9038010000         | mov                 ecx, 0x20006

        $sequence_19 = { 4533c9 4533c0 ba00000080 488b0d???????? 488b05???????? }
            // n = 5, score = 500
            //   4533c9               | call                dword ptr [eax + 0xe8]
            //   4533c0               | mov                 edx, 0x2710
            //   ba00000080           | call                dword ptr [eax + 0x10]
            //   488b0d????????       |                     
            //   488b05????????       |                     

        $sequence_20 = { 488b0d???????? 488b05???????? ff5010 85c0 }
            // n = 4, score = 500
            //   488b0d????????       |                     
            //   488b05????????       |                     
            //   ff5010               | dec                 eax
            //   85c0                 | mov                 dword ptr [esp + 0x10], ebx

        $sequence_21 = { 488b05???????? ff9040010000 90 4883c430 }
            // n = 4, score = 500
            //   488b05????????       |                     
            //   ff9040010000         | call                dword ptr [eax + 0xe8]
            //   90                   | mov                 edx, 0x2710
            //   4883c430             | call                dword ptr [eax + 0x140]

        $sequence_22 = { 488b05???????? ff90e8000000 488b0d???????? 488b05???????? ff5028 48c705????????00000000 }
            // n = 6, score = 500
            //   488b05????????       |                     
            //   ff90e8000000         | dec                 eax
            //   488b0d????????       |                     
            //   488b05????????       |                     
            //   ff5028               | add                 esp, 0x28
            //   48c705????????00000000     |     

        $sequence_23 = { 68???????? e8???????? 8b35???????? 83c404 6a00 }
            // n = 5, score = 500
            //   68????????           |                     
            //   e8????????           |                     
            //   8b35????????         |                     
            //   83c404               | push                0x200
            //   6a00                 | push                0

        $sequence_24 = { 4889442420 41b906000200 4533c0 488b15???????? 48c7c101000080 }
            // n = 5, score = 500
            //   4889442420           | inc                 ebp
            //   41b906000200         | xor                 ecx, ecx
            //   4533c0               | inc                 ebp
            //   488b15????????       |                     
            //   48c7c101000080       | xor                 eax, eax

        $sequence_25 = { 4883c428 c3 48890d???????? c3 48895c2410 }
            // n = 5, score = 500
            //   4883c428             | dec                 eax
            //   c3                   | add                 esp, 0x28
            //   48890d????????       |                     
            //   c3                   | ret                 
            //   48895c2410           | ret                 

        $sequence_26 = { 488b05???????? ff90e8000000 ba10270000 488b0d???????? }
            // n = 4, score = 500
            //   488b05????????       |                     
            //   ff90e8000000         | call                dword ptr [eax + 0x10]
            //   ba10270000           | test                eax, eax
            //   488b0d????????       |                     

        $sequence_27 = { 7cd5 68???????? e8???????? 8b4dfc }
            // n = 4, score = 400
            //   7cd5                 | call                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   8b4dfc               | call                esi

        $sequence_28 = { 6a00 ffd6 8b4dfc 5f 5e 33cd b8???????? }
            // n = 7, score = 400
            //   6a00                 | push                eax
            //   ffd6                 | push                -1
            //   8b4dfc               | add                 esp, 4
            //   5f                   | push                0
            //   5e                   | push                0
            //   33cd                 | push                0
            //   b8????????           |                     

        $sequence_29 = { 53 68???????? ff35???????? ffd6 ffd0 85c0 }
            // n = 6, score = 400
            //   53                   | push                ebx
            //   68????????           |                     
            //   ff35????????         |                     
            //   ffd6                 | call                esi
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax

        $sequence_30 = { c20c00 6a02 ff74240c ff74240c e8???????? c20800 ff74240c }
            // n = 7, score = 300
            //   c20c00               | ret                 0xc
            //   6a02                 | push                2
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   e8????????           |                     
            //   c20800               | ret                 8
            //   ff74240c             | push                dword ptr [esp + 0xc]

        $sequence_31 = { 8d55f8 52 50 8b08 ff5124 }
            // n = 5, score = 300
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5124               | call                dword ptr [ecx + 0x24]

        $sequence_32 = { e8???????? 8d0c36 51 50 68???????? e8???????? }
            // n = 6, score = 300
            //   e8????????           |                     
            //   8d0c36               | push                -1
            //   51                   | push                0
            //   50                   | push                0
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_33 = { 52 50 ff91f0000000 8bf0 }
            // n = 4, score = 300
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff91f0000000         | call                dword ptr [ecx + 0xf0]
            //   8bf0                 | mov                 esi, eax

        $sequence_34 = { 33cc e8???????? 8be5 5d c3 e8???????? a1???????? }
            // n = 7, score = 300
            //   33cc                 | push                -1
            //   e8????????           |                     
            //   8be5                 | push                0
            //   5d                   | call                esi
            //   c3                   | push                eax
            //   e8????????           |                     
            //   a1????????           |                     

        $sequence_35 = { 6aff 50 6a00 6a00 ff15???????? 5e }
            // n = 6, score = 200
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   5e                   | pop                 esi

        $sequence_36 = { 53 56 57 c745dce197af54 }
            // n = 4, score = 200
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   c745dce197af54       | mov                 dword ptr [ebp - 0x24], 0x54af97e1

        $sequence_37 = { 8b85ecfeffff 8b4df4 64890d00000000 5f 5e }
            // n = 5, score = 200
            //   8b85ecfeffff         | mov                 eax, dword ptr [ebp - 0x114]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_38 = { 741f 6a07 68???????? e8???????? 85c0 7402 }
            // n = 6, score = 200
            //   741f                 | je                  0x21
            //   6a07                 | push                7
            //   68????????           |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7402                 | je                  4

        $sequence_39 = { 50 ff512c 8bf0 f7de 1bf6 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   ff512c               | call                dword ptr [ecx + 0x2c]
            //   8bf0                 | mov                 esi, eax
            //   f7de                 | neg                 esi
            //   1bf6                 | sbb                 esi, esi

        $sequence_40 = { 57 894df0 ff15???????? 8945fc 8b45f0 8945f4 8b45f4 }
            // n = 7, score = 200
            //   57                   | push                edi
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_41 = { 57 50 ff512c 8bce 8bd8 e8???????? 57 }
            // n = 7, score = 200
            //   57                   | push                edi
            //   50                   | push                eax
            //   ff512c               | call                dword ptr [ecx + 0x2c]
            //   8bce                 | mov                 ecx, esi
            //   8bd8                 | mov                 ebx, eax
            //   e8????????           |                     
            //   57                   | push                edi

        $sequence_42 = { 8b06 50 8b08 ff9180000000 8b06 }
            // n = 5, score = 200
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff9180000000         | call                dword ptr [ecx + 0x80]
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_43 = { c644043c00 8854242c ff15???????? 8d7c2438 83c9ff }
            // n = 5, score = 100
            //   c644043c00           | add                 esi, 4
            //   8854242c             | jl                  0xffffffe2
            //   ff15????????         |                     
            //   8d7c2438             | push                esi
            //   83c9ff               | mov                 eax, dword ptr [esi]

        $sequence_44 = { 7640 3bdf 753c 8b742448 a1???????? 85f6 7402 }
            // n = 7, score = 100
            //   7640                 | jl                  0xffffffe2
            //   3bdf                 | pop                 esi
            //   753c                 | add                 esi, 4
            //   8b742448             | jl                  0xffffffe2
            //   a1????????           |                     
            //   85f6                 | pop                 esi
            //   7402                 | test                eax, eax

        $sequence_45 = { f3aa 8a5c2411 8a442410 8ad3 }
            // n = 4, score = 100
            //   f3aa                 | add                 esi, 4
            //   8a5c2411             | jl                  0xffffffe5
            //   8a442410             | pop                 esi
            //   8ad3                 | test                eax, eax

        $sequence_46 = { 740d 3cff 7409 fec8 8841ff b001 eb65 }
            // n = 7, score = 100
            //   740d                 | push                4
            //   3cff                 | jl                  0xffffffe2
            //   7409                 | pop                 esi
            //   fec8                 | test                eax, eax
            //   8841ff               | add                 esi, 4
            //   b001                 | jl                  0xffffffe2
            //   eb65                 | add                 esi, 4

        $sequence_47 = { 52 e8???????? 8d4624 8d4c2418 }
            // n = 4, score = 100
            //   52                   | push                0x202
            //   e8????????           |                     
            //   8d4624               | push                eax
            //   8d4c2418             | je                  0x13

        $sequence_48 = { 8b8c247c080000 e8???????? b907010000 33c0 8dbc243c040000 c7842464080000ffffffff f3ab }
            // n = 7, score = 100
            //   8b8c247c080000       | add                 esi, 4
            //   e8????????           |                     
            //   b907010000           | jl                  0xffffffe2
            //   33c0                 | pop                 esi
            //   8dbc243c040000       | mov                 eax, dword ptr [esi]
            //   c7842464080000ffffffff     | test    eax, eax
            //   f3ab                 | je                  0x13

        $sequence_49 = { 741d 8b542428 8b44242c 0fbecb 03c2 8ae9 }
            // n = 6, score = 100
            //   741d                 | jl                  0xffffffe2
            //   8b542428             | jl                  0xffffffe2
            //   8b44242c             | pop                 esi
            //   0fbecb               | jl                  0xffffffe2
            //   03c2                 | pop                 esi
            //   8ae9                 | test                eax, eax

        $sequence_50 = { 8915???????? 83fbfd 8935???????? 763b ff15???????? }
            // n = 5, score = 100
            //   8915????????         |                     
            //   83fbfd               | push                eax
            //   8935????????         |                     
            //   763b                 | add                 esi, 4
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 1586176
}
