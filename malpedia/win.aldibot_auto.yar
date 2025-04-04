rule win_aldibot_auto {

    meta:
        id = "6Ta5TuevZtQ92JafYcw5OU"
        fingerprint = "v1_sha256_06f3b8faad0069a5358ae6e374fdd6f12d750b34349ceedfaf1d011206529415"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.aldibot"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 752b 837c240801 7524 80bc249a00000001 750e 8bc3 }
            // n = 6, score = 100
            //   752b                 | jne                 0x2d
            //   837c240801           | cmp                 dword ptr [esp + 8], 1
            //   7524                 | jne                 0x26
            //   80bc249a00000001     | cmp                 byte ptr [esp + 0x9a], 1
            //   750e                 | jne                 0x10
            //   8bc3                 | mov                 eax, ebx

        $sequence_1 = { ff560c ffb5f4feffff 68???????? 8d85fcfeffff ba04000000 }
            // n = 5, score = 100
            //   ff560c               | call                dword ptr [esi + 0xc]
            //   ffb5f4feffff         | push                dword ptr [ebp - 0x10c]
            //   68????????           |                     
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   ba04000000           | mov                 edx, 4

        $sequence_2 = { 49 ba01000000 8b45c0 e8???????? 8d4dbc }
            // n = 5, score = 100
            //   49                   | dec                 ecx
            //   ba01000000           | mov                 edx, 1
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]
            //   e8????????           |                     
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]

        $sequence_3 = { 8d55f4 a1???????? 8b08 ff511c 8d55cc a1???????? }
            // n = 6, score = 100
            //   8d55f4               | lea                 edx, [ebp - 0xc]
            //   a1????????           |                     
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff511c               | call                dword ptr [ecx + 0x1c]
            //   8d55cc               | lea                 edx, [ebp - 0x34]
            //   a1????????           |                     

        $sequence_4 = { 85c0 7e2e 8d8d30ffffff 8bd3 }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   7e2e                 | jle                 0x30
            //   8d8d30ffffff         | lea                 ecx, [ebp - 0xd0]
            //   8bd3                 | mov                 edx, ebx

        $sequence_5 = { 8bcb 49 ba01000000 8b45e0 e8???????? }
            // n = 5, score = 100
            //   8bcb                 | mov                 ecx, ebx
            //   49                   | dec                 ecx
            //   ba01000000           | mov                 edx, 1
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   e8????????           |                     

        $sequence_6 = { e8???????? 8b8564feffff e8???????? 50 e8???????? 8d9558feffff b826000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b8564feffff         | mov                 eax, dword ptr [ebp - 0x19c]
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d9558feffff         | lea                 edx, [ebp - 0x1a8]
            //   b826000000           | mov                 eax, 0x26

        $sequence_7 = { 8b45a4 83e804 8b00 8945a4 8b4da4 83c102 8d45f0 }
            // n = 7, score = 100
            //   8b45a4               | mov                 eax, dword ptr [ebp - 0x5c]
            //   83e804               | sub                 eax, 4
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8945a4               | mov                 dword ptr [ebp - 0x5c], eax
            //   8b4da4               | mov                 ecx, dword ptr [ebp - 0x5c]
            //   83c102               | add                 ecx, 2
            //   8d45f0               | lea                 eax, [ebp - 0x10]

        $sequence_8 = { 68???????? 64ff30 648920 8b45fc c7009c000000 8b45fc }
            // n = 6, score = 100
            //   68????????           |                     
            //   64ff30               | push                dword ptr fs:[eax]
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c7009c000000         | mov                 dword ptr [eax], 0x9c
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_9 = { 50 e8???????? 8d9540feffff b826000000 e8???????? ffb540feffff }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d9540feffff         | lea                 edx, [ebp - 0x1c0]
            //   b826000000           | mov                 eax, 0x26
            //   e8????????           |                     
            //   ffb540feffff         | push                dword ptr [ebp - 0x1c0]

    condition:
        7 of them and filesize < 368640
}
