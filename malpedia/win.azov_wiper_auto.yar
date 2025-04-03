rule win_azov_wiper_auto {

    meta:
        id = "kApjkRIX6GL0CAS9eNzKc"
        fingerprint = "v1_sha256_011364438eb01e088c781e3c84797626beea4dfb11a3cc9222e67a61e76881e5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.azov_wiper."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.azov_wiper"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 488d942460020000 488d4c2430 488b00 ff9078010000 488b3d???????? f20f10842460020000 488b4710 }
            // n = 7, score = 100
            //   488d942460020000     | inc                 ecx
            //   488d4c2430           | mov                 ecx, 1
            //   488b00               | dec                 eax
            //   ff9078010000         | mov                 edi, dword ptr [esp + 0x300]
            //   488b3d????????       |                     
            //   f20f10842460020000     | dec    eax
            //   488b4710             | mov                 ecx, esi

        $sequence_1 = { 4831f6 4801c6 4883c03c 4831d2 8b10 4883ec08 }
            // n = 6, score = 100
            //   4831f6               | call                dword ptr [edi + 0x190]
            //   4801c6               | dec                 eax
            //   4883c03c             | test                eax, eax
            //   4831d2               | je                  0x42f
            //   8b10                 | movsd               xmm0, qword ptr [esp + 0x260]
            //   4883ec08             | dec                 eax

        $sequence_2 = { 488d144a 66833a5c 740b 4883ea02 83c0ff }
            // n = 5, score = 100
            //   488d144a             | mov                 eax, 0x3000
            //   66833a5c             | dec                 esp
            //   740b                 | mov                 edx, dword ptr [eax]
            //   4883ea02             | inc                 esp
            //   83c0ff               | lea                 ecx, [ecx + 4]

        $sequence_3 = { 488bf1 498943c8 498d7bc8 488d055ffbffff 33db 498943d0 }
            // n = 6, score = 100
            //   488bf1               | lea                 ecx, [esp + 0x78]
            //   498943c8             | inc                 ebp
            //   498d7bc8             | mov                 eax, esi
            //   488d055ffbffff       | dec                 eax
            //   33db                 | mov                 dword ptr [esp + 0x20], ebx
            //   498943d0             | dec                 eax

        $sequence_4 = { 488b05???????? bafe010000 488bd9 33f6 4c8b00 41ff9048010000 ffc8 }
            // n = 7, score = 100
            //   488b05????????       |                     
            //   bafe010000           | mov                 ecx, esi
            //   488bd9               | call                dword ptr [eax + 0x40]
            //   33f6                 | dec                 eax
            //   4c8b00               | test                eax, eax
            //   41ff9048010000       | dec                 eax
            //   ffc8                 | mov                 ecx, esi

        $sequence_5 = { 0f1f4000 488938 48897808 48897810 488d4040 }
            // n = 5, score = 100
            //   0f1f4000             | mov                 dword ptr [esp + 0x28], eax
            //   488938               | dec                 eax
            //   48897808             | mov                 dword ptr [esp + 0x20], edi
            //   48897810             | inc                 ecx
            //   488d4040             | call                dword ptr [edx + 0xc0]

        $sequence_6 = { 41ff9258010000 488b8c2470080000 4885c9 7410 488b05???????? 488b10 ff9268010000 }
            // n = 7, score = 100
            //   41ff9258010000       | lea                 eax, [esp + 0x870]
            //   488b8c2470080000     | dec                 eax
            //   4885c9               | mov                 dword ptr [esp + 0x38], eax
            //   7410                 | dec                 eax
            //   488b05????????       |                     
            //   488b10               | mov                 dword ptr [esp + 0x30], ecx
            //   ff9268010000         | inc                 ebp

        $sequence_7 = { 448d4904 41ff5208 4c8bc8 4885c0 }
            // n = 4, score = 100
            //   448d4904             | mov                 eax, 0x8000
            //   41ff5208             | dec                 esp
            //   4c8bc8               | mov                 ecx, dword ptr [ecx]
            //   4885c0               | dec                 eax

        $sequence_8 = { ffc0 8bc8 488d156cfaffff 4c8d0409 }
            // n = 4, score = 100
            //   ffc0                 | lea                 edx, [esp + 0x40]
            //   8bc8                 | dec                 eax
            //   488d156cfaffff       | mov                 ecx, ebx
            //   4c8d0409             | dec                 esp

        $sequence_9 = { 488d05acf3ffff 4883ec08 48890c24 48c7c1619afeff }
            // n = 4, score = 100
            //   488d05acf3ffff       | dec                 eax
            //   4883ec08             | mov                 edx, edi
            //   48890c24             | dec                 eax
            //   48c7c1619afeff       | mov                 ecx, esi

    condition:
        7 of them and filesize < 73728
}
