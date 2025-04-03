rule win_sslmm_auto {

    meta:
        id = "7SZD1l7xCVqMDIbvJQa8Ja"
        fingerprint = "v1_sha256_e05d1383c6fd4195ee348036204c560e38cfb3624a913866f02778d6ae43e5d9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sslmm."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sslmm"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff9630010000 897c2428 81fb18030980 0f8493feffff }
            // n = 4, score = 400
            //   ff9630010000         | call                dword ptr [esi + 0x130]
            //   897c2428             | mov                 dword ptr [esp + 0x28], edi
            //   81fb18030980         | cmp                 ebx, 0x80090318
            //   0f8493feffff         | je                  0xfffffe99

        $sequence_1 = { 0f8447010000 03f8 eb08 c744241801000000 8d542464 }
            // n = 5, score = 400
            //   0f8447010000         | je                  0x14d
            //   03f8                 | add                 edi, eax
            //   eb08                 | jmp                 0xa
            //   c744241801000000     | mov                 dword ptr [esp + 0x18], 1
            //   8d542464             | lea                 edx, [esp + 0x64]

        $sequence_2 = { 33db 57 8b85ac000000 53 }
            // n = 4, score = 400
            //   33db                 | xor                 ebx, ebx
            //   57                   | push                edi
            //   8b85ac000000         | mov                 eax, dword ptr [ebp + 0xac]
            //   53                   | push                ebx

        $sequence_3 = { 56 8bc1 8bf7 8b7c2410 c1e902 f3a5 }
            // n = 6, score = 400
            //   56                   | push                esi
            //   8bc1                 | mov                 eax, ecx
            //   8bf7                 | mov                 esi, edi
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_4 = { ff930c010000 8be8 89742414 3bee 7415 81fd12030900 }
            // n = 6, score = 400
            //   ff930c010000         | call                dword ptr [ebx + 0x10c]
            //   8be8                 | mov                 ebp, eax
            //   89742414             | mov                 dword ptr [esp + 0x14], esi
            //   3bee                 | cmp                 ebp, esi
            //   7415                 | je                  0x17
            //   81fd12030900         | cmp                 ebp, 0x90312

        $sequence_5 = { 8d4e0c 53 51 89869c000000 e8???????? 8b9790000000 83c408 }
            // n = 7, score = 400
            //   8d4e0c               | lea                 ecx, [esi + 0xc]
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   89869c000000         | mov                 dword ptr [esi + 0x9c], eax
            //   e8????????           |                     
            //   8b9790000000         | mov                 edx, dword ptr [edi + 0x90]
            //   83c408               | add                 esp, 8

        $sequence_6 = { 50 8bcf e8???????? c7442410ffffffff eb1f }
            // n = 5, score = 400
            //   50                   | push                eax
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   c7442410ffffffff     | mov                 dword ptr [esp + 0x10], 0xffffffff
            //   eb1f                 | jmp                 0x21

        $sequence_7 = { 53 6a00 6a00 e8???????? 8b96a0000000 83c420 8d4c240c }
            // n = 7, score = 400
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   e8????????           |                     
            //   8b96a0000000         | mov                 edx, dword ptr [esi + 0xa0]
            //   83c420               | add                 esp, 0x20
            //   8d4c240c             | lea                 ecx, [esp + 0xc]

        $sequence_8 = { f2ae f7d1 49 85c9 7e3a }
            // n = 5, score = 400
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   85c9                 | test                ecx, ecx
            //   7e3a                 | jle                 0x3c

        $sequence_9 = { ff15???????? 6a00 6a00 8d542418 6a00 }
            // n = 5, score = 400
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 188416
}
