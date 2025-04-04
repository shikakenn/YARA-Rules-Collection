rule win_webc2_bolid_auto {

    meta:
        id = "4qQuzy1kX8byhewM4k2qec"
        fingerprint = "v1_sha256_d5bb74d5c966a3742a98e85309bd13720d314db10e6aa05f8d544024f31adb6b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.webc2_bolid."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_bolid"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 897344 8b3d???????? 33c0 897dec 6a01 f2ae f7d1 }
            // n = 7, score = 100
            //   897344               | mov                 dword ptr [ebx + 0x44], esi
            //   8b3d????????         |                     
            //   33c0                 | xor                 eax, eax
            //   897dec               | mov                 dword ptr [ebp - 0x14], edi
            //   6a01                 | push                1
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

        $sequence_1 = { f3a5 8bca 83e103 f3a4 8b4dbc }
            // n = 5, score = 100
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bca                 | mov                 ecx, edx
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b4dbc               | mov                 ecx, dword ptr [ebp - 0x44]

        $sequence_2 = { 8a4c2413 53 884c2460 8d4c2460 c684240002000001 }
            // n = 5, score = 100
            //   8a4c2413             | mov                 cl, byte ptr [esp + 0x13]
            //   53                   | push                ebx
            //   884c2460             | mov                 byte ptr [esp + 0x60], cl
            //   8d4c2460             | lea                 ecx, [esp + 0x60]
            //   c684240002000001     | mov                 byte ptr [esp + 0x200], 1

        $sequence_3 = { 8d4c2404 e8???????? 8d4c2404 c784242803000000000000 e8???????? }
            // n = 5, score = 100
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   e8????????           |                     
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   c784242803000000000000     | mov    dword ptr [esp + 0x328], 0
            //   e8????????           |                     

        $sequence_4 = { 57 897de8 e8???????? 84c0 7427 }
            // n = 5, score = 100
            //   57                   | push                edi
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7427                 | je                  0x29

        $sequence_5 = { 8b4dec 8b75e4 03c1 894508 }
            // n = 4, score = 100
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   8b75e4               | mov                 esi, dword ptr [ebp - 0x1c]
            //   03c1                 | add                 eax, ecx
            //   894508               | mov                 dword ptr [ebp + 8], eax

        $sequence_6 = { 03c1 c60000 8b4dbc c645fc00 85c9 7422 }
            // n = 6, score = 100
            //   03c1                 | add                 eax, ecx
            //   c60000               | mov                 byte ptr [eax], 0
            //   8b4dbc               | mov                 ecx, dword ptr [ebp - 0x44]
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   85c9                 | test                ecx, ecx
            //   7422                 | je                  0x24

        $sequence_7 = { 8b6c2414 03c2 8a4d00 8a18 }
            // n = 4, score = 100
            //   8b6c2414             | mov                 ebp, dword ptr [esp + 0x14]
            //   03c2                 | add                 eax, edx
            //   8a4d00               | mov                 cl, byte ptr [ebp]
            //   8a18                 | mov                 bl, byte ptr [eax]

        $sequence_8 = { eb22 85f6 741c 8a46ff }
            // n = 4, score = 100
            //   eb22                 | jmp                 0x24
            //   85f6                 | test                esi, esi
            //   741c                 | je                  0x1e
            //   8a46ff               | mov                 al, byte ptr [esi - 1]

        $sequence_9 = { c68424240200000d e8???????? 83ec10 8d9424a0000000 8bcc 89a424c4000000 52 }
            // n = 7, score = 100
            //   c68424240200000d     | mov                 byte ptr [esp + 0x224], 0xd
            //   e8????????           |                     
            //   83ec10               | sub                 esp, 0x10
            //   8d9424a0000000       | lea                 edx, [esp + 0xa0]
            //   8bcc                 | mov                 ecx, esp
            //   89a424c4000000       | mov                 dword ptr [esp + 0xc4], esp
            //   52                   | push                edx

    condition:
        7 of them and filesize < 163840
}
