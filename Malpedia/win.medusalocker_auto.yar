rule win_medusalocker_auto {

    meta:
        id = "2i7vUCuiYhH8WDrKXnA2PU"
        fingerprint = "v1_sha256_7df5844b357690737586e0cd4cc89af865edb4da022c679b11e7f73e8fc7409a"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.medusalocker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.medusalocker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b5004 52 8b00 50 8d4dd8 e8???????? 68???????? }
            // n = 7, score = 400
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   52                   | push                edx
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   50                   | push                eax
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   68????????           |                     

        $sequence_1 = { 8b4d0c e8???????? 0fb6c0 85c0 7549 6aff 68???????? }
            // n = 7, score = 400
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   0fb6c0               | movzx               eax, al
            //   85c0                 | test                eax, eax
            //   7549                 | jne                 0x4b
            //   6aff                 | push                -1
            //   68????????           |                     

        $sequence_2 = { 8955ac 8955b0 8955b4 8d45a8 50 8d4db8 51 }
            // n = 7, score = 400
            //   8955ac               | mov                 dword ptr [ebp - 0x54], edx
            //   8955b0               | mov                 dword ptr [ebp - 0x50], edx
            //   8955b4               | mov                 dword ptr [ebp - 0x4c], edx
            //   8d45a8               | lea                 eax, [ebp - 0x58]
            //   50                   | push                eax
            //   8d4db8               | lea                 ecx, [ebp - 0x48]
            //   51                   | push                ecx

        $sequence_3 = { 8d4dd8 e8???????? 0fb708 83f95c }
            // n = 4, score = 400
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   0fb708               | movzx               ecx, word ptr [eax]
            //   83f95c               | cmp                 ecx, 0x5c

        $sequence_4 = { e8???????? 83c408 8945e0 8b55e0 8955dc }
            // n = 5, score = 400
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   8955dc               | mov                 dword ptr [ebp - 0x24], edx

        $sequence_5 = { 64a300000000 894df0 8b4df0 e8???????? c6400800 8b4df0 }
            // n = 6, score = 400
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   c6400800             | mov                 byte ptr [eax + 8], 0
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]

        $sequence_6 = { 8b4de8 83c150 e8???????? 8b4de8 e8???????? 8b4df4 64890d00000000 }
            // n = 7, score = 400
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   83c150               | add                 ecx, 0x50
            //   e8????????           |                     
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   e8????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_7 = { e8???????? 8b4d08 83c148 51 }
            // n = 4, score = 400
            //   e8????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   83c148               | add                 ecx, 0x48
            //   51                   | push                ecx

        $sequence_8 = { 83ec08 8bcc 8965e0 8d4508 50 e8???????? 8b4de4 }
            // n = 7, score = 400
            //   83ec08               | sub                 esp, 8
            //   8bcc                 | mov                 ecx, esp
            //   8965e0               | mov                 dword ptr [ebp - 0x20], esp
            //   8d4508               | lea                 eax, [ebp + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]

        $sequence_9 = { 8945ec eb07 c745ec00000000 8b55ec 8955e8 c745fcffffffff 8b4de8 }
            // n = 7, score = 400
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   eb07                 | jmp                 9
            //   c745ec00000000       | mov                 dword ptr [ebp - 0x14], 0
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]

    condition:
        7 of them and filesize < 1433600
}
