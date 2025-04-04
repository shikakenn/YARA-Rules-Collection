rule win_runningrat_auto {

    meta:
        id = "4aBfsVaCxDICx0jV9SAbyj"
        fingerprint = "v1_sha256_cc8e1228550694df797c7f86352429950a0d9bf3c450fac5ae045f777304a562"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.runningrat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.runningrat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff15???????? 56 ff15???????? 8b8c2418010000 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b8c2418010000       | mov                 ecx, dword ptr [esp + 0x118]

        $sequence_1 = { 8b4e24 51 ffd7 8b5628 6aff }
            // n = 5, score = 200
            //   8b4e24               | mov                 ecx, dword ptr [esi + 0x24]
            //   51                   | push                ecx
            //   ffd7                 | call                edi
            //   8b5628               | mov                 edx, dword ptr [esi + 0x28]
            //   6aff                 | push                -1

        $sequence_2 = { 55 8b2d???????? 57 eb02 }
            // n = 4, score = 200
            //   55                   | push                ebp
            //   8b2d????????         |                     
            //   57                   | push                edi
            //   eb02                 | jmp                 4

        $sequence_3 = { 75b1 8b442418 8bce 0bc8 }
            // n = 4, score = 200
            //   75b1                 | jne                 0xffffffb3
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   8bce                 | mov                 ecx, esi
            //   0bc8                 | or                  ecx, eax

        $sequence_4 = { 8b4e2c 2bca 894c2414 8b08 83f909 0f87fa060000 ff248dd0580110 }
            // n = 7, score = 200
            //   8b4e2c               | mov                 ecx, dword ptr [esi + 0x2c]
            //   2bca                 | sub                 ecx, edx
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   83f909               | cmp                 ecx, 9
            //   0f87fa060000         | ja                  0x700
            //   ff248dd0580110       | jmp                 dword ptr [ecx*4 + 0x100158d0]

        $sequence_5 = { 894578 e8???????? 83c438 89457c 8b8c249c010000 5f 8bc5 }
            // n = 7, score = 200
            //   894578               | mov                 dword ptr [ebp + 0x78], eax
            //   e8????????           |                     
            //   83c438               | add                 esp, 0x38
            //   89457c               | mov                 dword ptr [ebp + 0x7c], eax
            //   8b8c249c010000       | mov                 ecx, dword ptr [esp + 0x19c]
            //   5f                   | pop                 edi
            //   8bc5                 | mov                 eax, ebp

        $sequence_6 = { 7505 e8???????? 8a03 8b35???????? 8b3d???????? 3c26 }
            // n = 6, score = 200
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   8a03                 | mov                 al, byte ptr [ebx]
            //   8b35????????         |                     
            //   8b3d????????         |                     
            //   3c26                 | cmp                 al, 0x26

        $sequence_7 = { c7466c00000000 e8???????? 8b4c2410 8bc6 5f 5e }
            // n = 6, score = 200
            //   c7466c00000000       | mov                 dword ptr [esi + 0x6c], 0
            //   e8????????           |                     
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   8bc6                 | mov                 eax, esi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_8 = { 2bc1 894c2430 f6c310 74d3 83e30f 3bc3 }
            // n = 6, score = 100
            //   2bc1                 | sub                 eax, ecx
            //   894c2430             | mov                 dword ptr [esp + 0x30], ecx
            //   f6c310               | test                bl, 0x10
            //   74d3                 | je                  0xffffffd5
            //   83e30f               | and                 ebx, 0xf
            //   3bc3                 | cmp                 eax, ebx

        $sequence_9 = { 56 ff15???????? 8bf8 85ff 752b 68???????? e8???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   752b                 | jne                 0x2d
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_10 = { 52 53 ff15???????? 5f 83f801 7406 ff15???????? }
            // n = 7, score = 100
            //   52                   | push                edx
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   83f801               | cmp                 eax, 1
            //   7406                 | je                  8
            //   ff15????????         |                     

        $sequence_11 = { 7507 c74724b0302a00 8b4728 8b4f20 6a18 }
            // n = 5, score = 100
            //   7507                 | jne                 9
            //   c74724b0302a00       | mov                 dword ptr [edi + 0x24], 0x2a30b0
            //   8b4728               | mov                 eax, dword ptr [edi + 0x28]
            //   8b4f20               | mov                 ecx, dword ptr [edi + 0x20]
            //   6a18                 | push                0x18

        $sequence_12 = { 83f901 0f82fd020000 8b460c 8b4488fc eb02 33c0 }
            // n = 6, score = 100
            //   83f901               | cmp                 ecx, 1
            //   0f82fd020000         | jb                  0x303
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   8b4488fc             | mov                 eax, dword ptr [eax + ecx*4 - 4]
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_13 = { 55 8bac2408010000 56 33f6 }
            // n = 4, score = 100
            //   55                   | push                ebp
            //   8bac2408010000       | mov                 ebp, dword ptr [esp + 0x108]
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi

        $sequence_14 = { 890f c70005000000 8b4704 85c0 0f846fffffff 8b0f }
            // n = 6, score = 100
            //   890f                 | mov                 dword ptr [edi], ecx
            //   c70005000000         | mov                 dword ptr [eax], 5
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   85c0                 | test                eax, eax
            //   0f846fffffff         | je                  0xffffff75
            //   8b0f                 | mov                 ecx, dword ptr [edi]

    condition:
        7 of them and filesize < 278528
}
