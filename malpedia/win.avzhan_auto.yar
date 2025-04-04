rule win_avzhan_auto {

    meta:
        id = "4J3lggSVE3zt6g646Tphk5"
        fingerprint = "v1_sha256_71cd3a78708c6b20dbe933c0b73634c73ab7a935896c5127cd1ee325ea10e744"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.avzhan."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.avzhan"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 88442418 c644241906 51 66895c241e }
            // n = 4, score = 200
            //   88442418             | mov                 byte ptr [esp + 0x18], al
            //   c644241906           | mov                 byte ptr [esp + 0x19], 6
            //   51                   | push                ecx
            //   66895c241e           | mov                 word ptr [esp + 0x1e], bx

        $sequence_1 = { 83c418 0bc6 8944244c 66c74424500000 3935???????? }
            // n = 5, score = 200
            //   83c418               | add                 esp, 0x18
            //   0bc6                 | or                  eax, esi
            //   8944244c             | mov                 dword ptr [esp + 0x4c], eax
            //   66c74424500000       | mov                 word ptr [esp + 0x50], 0
            //   3935????????         |                     

        $sequence_2 = { 0f85bc000000 8d84247c010000 50 e8???????? 8d8c24e8000000 }
            // n = 5, score = 200
            //   0f85bc000000         | jne                 0xc2
            //   8d84247c010000       | lea                 eax, [esp + 0x17c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8c24e8000000       | lea                 ecx, [esp + 0xe8]

        $sequence_3 = { 68d0070000 ffd7 6a00 8b542414 52 }
            // n = 5, score = 200
            //   68d0070000           | push                0x7d0
            //   ffd7                 | call                edi
            //   6a00                 | push                0
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx

        $sequence_4 = { 8d7c243c c744243844000000 f3ab 8b442464 8b3d???????? }
            // n = 5, score = 200
            //   8d7c243c             | lea                 edi, [esp + 0x3c]
            //   c744243844000000     | mov                 dword ptr [esp + 0x38], 0x44
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8b442464             | mov                 eax, dword ptr [esp + 0x64]
            //   8b3d????????         |                     

        $sequence_5 = { 83c418 0bc6 8944244c 66c74424500000 3935???????? 743c }
            // n = 6, score = 200
            //   83c418               | add                 esp, 0x18
            //   0bc6                 | or                  eax, esi
            //   8944244c             | mov                 dword ptr [esp + 0x4c], eax
            //   66c74424500000       | mov                 word ptr [esp + 0x50], 0
            //   3935????????         |                     
            //   743c                 | je                  0x3e

        $sequence_6 = { ff15???????? 8b2d???????? 8b1d???????? b910000000 33c0 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   8b2d????????         |                     
            //   8b1d????????         |                     
            //   b910000000           | mov                 ecx, 0x10
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 8bf0 8dbc2404020000 83c9ff 33c0 83c408 f2ae }
            // n = 6, score = 200
            //   8bf0                 | mov                 esi, eax
            //   8dbc2404020000       | lea                 edi, [esp + 0x204]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   83c408               | add                 esp, 8
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

        $sequence_8 = { ffd7 6a00 8b542414 52 ffd3 }
            // n = 5, score = 200
            //   ffd7                 | call                edi
            //   6a00                 | push                0
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx
            //   ffd3                 | call                ebx

        $sequence_9 = { 33c0 8d7c243c c744243844000000 f3ab 8b442464 8b3d???????? 83c418 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   8d7c243c             | lea                 edi, [esp + 0x3c]
            //   c744243844000000     | mov                 dword ptr [esp + 0x38], 0x44
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8b442464             | mov                 eax, dword ptr [esp + 0x64]
            //   8b3d????????         |                     
            //   83c418               | add                 esp, 0x18

    condition:
        7 of them and filesize < 122880
}
