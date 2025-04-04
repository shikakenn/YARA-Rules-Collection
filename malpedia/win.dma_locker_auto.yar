rule win_dma_locker_auto {

    meta:
        id = "7bN4XXIcCRzP4RiWr1YrSJ"
        fingerprint = "v1_sha256_3ae5bccd6371af15118f93027d88904afa2d354f640add9013354700a19edfc8"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.dma_locker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dma_locker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83c40c 6804010000 8d8c24b0060000 51 56 ff15???????? 8d8424ac060000 }
            // n = 7, score = 200
            //   83c40c               | add                 esp, 0xc
            //   6804010000           | push                0x104
            //   8d8c24b0060000       | lea                 ecx, [esp + 0x6b0]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8d8424ac060000       | lea                 eax, [esp + 0x6ac]

        $sequence_1 = { 6a00 ffd7 50 6a00 56 6a0f 6896000000 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   ffd7                 | call                edi
            //   50                   | push                eax
            //   6a00                 | push                0
            //   56                   | push                esi
            //   6a0f                 | push                0xf
            //   6896000000           | push                0x96

        $sequence_2 = { eb88 8bff 55 8bec 83ec10 a1???????? 33d2 }
            // n = 7, score = 200
            //   eb88                 | jmp                 0xffffff8a
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   a1????????           |                     
            //   33d2                 | xor                 edx, edx

        $sequence_3 = { c744243c08020000 ff15???????? 85c0 7440 8b742418 }
            // n = 5, score = 200
            //   c744243c08020000     | mov                 dword ptr [esp + 0x3c], 0x208
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7440                 | je                  0x42
            //   8b742418             | mov                 esi, dword ptr [esp + 0x18]

        $sequence_4 = { 75f9 2bc2 56 50 8d85fcefffff 6a01 }
            // n = 6, score = 200
            //   75f9                 | jne                 0xfffffffb
            //   2bc2                 | sub                 eax, edx
            //   56                   | push                esi
            //   50                   | push                eax
            //   8d85fcefffff         | lea                 eax, [ebp - 0x1004]
            //   6a01                 | push                1

        $sequence_5 = { 8b4340 83c40c 50 68???????? eb3e 83f806 7543 }
            // n = 7, score = 200
            //   8b4340               | mov                 eax, dword ptr [ebx + 0x40]
            //   83c40c               | add                 esp, 0xc
            //   50                   | push                eax
            //   68????????           |                     
            //   eb3e                 | jmp                 0x40
            //   83f806               | cmp                 eax, 6
            //   7543                 | jne                 0x45

        $sequence_6 = { 3bc8 7345 8b4e08 8d95ccefffff 3bca 7738 8bda }
            // n = 7, score = 200
            //   3bc8                 | cmp                 ecx, eax
            //   7345                 | jae                 0x47
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   8d95ccefffff         | lea                 edx, [ebp - 0x1034]
            //   3bca                 | cmp                 ecx, edx
            //   7738                 | ja                  0x3a
            //   8bda                 | mov                 ebx, edx

        $sequence_7 = { e8???????? 6a1c e8???????? 83c404 85c0 7452 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   6a1c                 | push                0x1c
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   7452                 | je                  0x54

        $sequence_8 = { 83c404 894604 85c0 7414 8b750c b967000000 }
            // n = 6, score = 200
            //   83c404               | add                 esp, 4
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   85c0                 | test                eax, eax
            //   7414                 | je                  0x16
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   b967000000           | mov                 ecx, 0x67

        $sequence_9 = { 6a00 6a01 6a00 68???????? 8d5f14 53 893d???????? }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   68????????           |                     
            //   8d5f14               | lea                 ebx, [edi + 0x14]
            //   53                   | push                ebx
            //   893d????????         |                     

    condition:
        7 of them and filesize < 532480
}
