rule win_floki_bot_auto {

    meta:
        id = "5O9TvQgb2MBGfMdPGW8UK8"
        fingerprint = "v1_sha256_e2f9df61c4df036b71f6882cf4c35419384506db07aa4de7d79fcad14d6710ad"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.floki_bot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.floki_bot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { fe45ff 8a45ff 3a45fc 7285 fe45fe 8a45fe 3a4601 }
            // n = 7, score = 1100
            //   fe45ff               | inc                 byte ptr [ebp - 1]
            //   8a45ff               | mov                 al, byte ptr [ebp - 1]
            //   3a45fc               | cmp                 al, byte ptr [ebp - 4]
            //   7285                 | jb                  0xffffff87
            //   fe45fe               | inc                 byte ptr [ebp - 2]
            //   8a45fe               | mov                 al, byte ptr [ebp - 2]
            //   3a4601               | cmp                 al, byte ptr [esi + 1]

        $sequence_1 = { 8bc6 8d74241c e8???????? 84c0 0f843f010000 8b442414 }
            // n = 6, score = 1100
            //   8bc6                 | mov                 eax, esi
            //   8d74241c             | lea                 esi, [esp + 0x1c]
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   0f843f010000         | je                  0x145
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]

        $sequence_2 = { 53 57 8bf8 8d45f8 50 33db }
            // n = 6, score = 1100
            //   53                   | push                ebx
            //   57                   | push                edi
            //   8bf8                 | mov                 edi, eax
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   33db                 | xor                 ebx, ebx

        $sequence_3 = { 8b4c2414 0fb713 83fa04 7516 663911 7507 8b4d10 }
            // n = 7, score = 1100
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   0fb713               | movzx               edx, word ptr [ebx]
            //   83fa04               | cmp                 edx, 4
            //   7516                 | jne                 0x18
            //   663911               | cmp                 word ptr [ecx], dx
            //   7507                 | jne                 9
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]

        $sequence_4 = { 50 53 ff35???????? 682d010000 e8???????? 83c418 }
            // n = 6, score = 1100
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff35????????         |                     
            //   682d010000           | push                0x12d
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_5 = { 50 e8???????? ff471c 015f14 8bc6 8b55fc e8???????? }
            // n = 7, score = 1100
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff471c               | inc                 dword ptr [edi + 0x1c]
            //   015f14               | add                 dword ptr [edi + 0x14], ebx
            //   8bc6                 | mov                 eax, esi
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   e8????????           |                     

        $sequence_6 = { bf???????? e8???????? ff75f0 84c0 7407 e8???????? eb08 }
            // n = 7, score = 1100
            //   bf????????           |                     
            //   e8????????           |                     
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   84c0                 | test                al, al
            //   7407                 | je                  9
            //   e8????????           |                     
            //   eb08                 | jmp                 0xa

        $sequence_7 = { 8d45f4 50 e8???????? 6a09 6a00 8d45f4 50 }
            // n = 7, score = 1100
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a09                 | push                9
            //   6a00                 | push                0
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax

        $sequence_8 = { 744d 66391f 7448 8d4c2440 e8???????? 6a04 8d544444 }
            // n = 7, score = 1100
            //   744d                 | je                  0x4f
            //   66391f               | cmp                 word ptr [edi], bx
            //   7448                 | je                  0x4a
            //   8d4c2440             | lea                 ecx, [esp + 0x40]
            //   e8????????           |                     
            //   6a04                 | push                4
            //   8d544444             | lea                 edx, [esp + eax*2 + 0x44]

        $sequence_9 = { 84c0 744b 8b45f8 85c0 7414 ff75ec e8???????? }
            // n = 7, score = 1100
            //   84c0                 | test                al, al
            //   744b                 | je                  0x4d
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   85c0                 | test                eax, eax
            //   7414                 | je                  0x16
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 286720
}
