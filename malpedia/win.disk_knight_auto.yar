rule win_disk_knight_auto {

    meta:
        id = "6L1b57v0XmirJS55vTEmTN"
        fingerprint = "v1_sha256_09ce3baeb29e85d6695478868b4b5a99498537909676146b33cec4463b3e4ba4"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.disk_knight."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.disk_knight"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 56 56 8b45c4 50 8d4dc0 51 8b3d???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   56                   | push                esi
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   50                   | push                eax
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]
            //   51                   | push                ecx
            //   8b3d????????         |                     

        $sequence_1 = { ff15???????? 8945a8 a1???????? bf03000000 c745a008000000 85c0 895d88 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8945a8               | mov                 dword ptr [ebp - 0x58], eax
            //   a1????????           |                     
            //   bf03000000           | mov                 edi, 3
            //   c745a008000000       | mov                 dword ptr [ebp - 0x60], 8
            //   85c0                 | test                eax, eax
            //   895d88               | mov                 dword ptr [ebp - 0x78], ebx

        $sequence_2 = { 8b06 ff5004 8b4d0c 8d55e8 897de8 8b3d???????? 51 }
            // n = 7, score = 100
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   ff5004               | call                dword ptr [eax + 4]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8d55e8               | lea                 edx, [ebp - 0x18]
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi
            //   8b3d????????         |                     
            //   51                   | push                ecx

        $sequence_3 = { ff15???????? a1???????? 83c410 3bc3 7510 68???????? 68???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   a1????????           |                     
            //   83c410               | add                 esp, 0x10
            //   3bc3                 | cmp                 eax, ebx
            //   7510                 | jne                 0x12
            //   68????????           |                     
            //   68????????           |                     

        $sequence_4 = { 8945cc 895dc4 c7459403400000 8b07 51 52 57 }
            // n = 7, score = 100
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   895dc4               | mov                 dword ptr [ebp - 0x3c], ebx
            //   c7459403400000       | mov                 dword ptr [ebp - 0x6c], 0x4003
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   57                   | push                edi

        $sequence_5 = { 8955d8 897dd0 897dcc 897dc8 897dc4 897dc0 897dbc }
            // n = 7, score = 100
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx
            //   897dd0               | mov                 dword ptr [ebp - 0x30], edi
            //   897dcc               | mov                 dword ptr [ebp - 0x34], edi
            //   897dc8               | mov                 dword ptr [ebp - 0x38], edi
            //   897dc4               | mov                 dword ptr [ebp - 0x3c], edi
            //   897dc0               | mov                 dword ptr [ebp - 0x40], edi
            //   897dbc               | mov                 dword ptr [ebp - 0x44], edi

        $sequence_6 = { 894da8 8b4dd4 b80a000000 68???????? 51 894590 8945a0 }
            // n = 7, score = 100
            //   894da8               | mov                 dword ptr [ebp - 0x58], ecx
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   b80a000000           | mov                 eax, 0xa
            //   68????????           |                     
            //   51                   | push                ecx
            //   894590               | mov                 dword ptr [ebp - 0x70], eax
            //   8945a0               | mov                 dword ptr [ebp - 0x60], eax

        $sequence_7 = { db464c dd9d14ffffff 833d????????00 7508 dcb514ffffff eb11 ffb518ffffff }
            // n = 7, score = 100
            //   db464c               | fild                dword ptr [esi + 0x4c]
            //   dd9d14ffffff         | fstp                qword ptr [ebp - 0xec]
            //   833d????????00       |                     
            //   7508                 | jne                 0xa
            //   dcb514ffffff         | fdiv                qword ptr [ebp - 0xec]
            //   eb11                 | jmp                 0x13
            //   ffb518ffffff         | push                dword ptr [ebp - 0xe8]

        $sequence_8 = { 8985c8fdffff eb0a c785c8fdffff00000000 833d????????00 751c 68???????? 68???????? }
            // n = 7, score = 100
            //   8985c8fdffff         | mov                 dword ptr [ebp - 0x238], eax
            //   eb0a                 | jmp                 0xc
            //   c785c8fdffff00000000     | mov    dword ptr [ebp - 0x238], 0
            //   833d????????00       |                     
            //   751c                 | jne                 0x1e
            //   68????????           |                     
            //   68????????           |                     

        $sequence_9 = { 7d0e 68d8000000 68???????? 56 50 ffd3 8b0e }
            // n = 7, score = 100
            //   7d0e                 | jge                 0x10
            //   68d8000000           | push                0xd8
            //   68????????           |                     
            //   56                   | push                esi
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   8b0e                 | mov                 ecx, dword ptr [esi]

    condition:
        7 of them and filesize < 868352
}
