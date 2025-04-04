rule win_shadowhammer_auto {

    meta:
        id = "7YUd9lLfroGUTAc1NfZb3"
        fingerprint = "v1_sha256_9c0187702056fafb079efbd5dab5b93b10eb6c78f6f641de1a14fc5c3fa972f5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.shadowhammer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shadowhammer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8945fc ff5624 83c40c 53 }
            // n = 4, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ff5624               | call                dword ptr [esi + 0x24]
            //   83c40c               | add                 esp, 0xc
            //   53                   | push                ebx

        $sequence_1 = { 6a08 57 ff741da4 ff16 8945f0 }
            // n = 5, score = 100
            //   6a08                 | push                8
            //   57                   | push                edi
            //   ff741da4             | push                dword ptr [ebp + ebx - 0x5c]
            //   ff16                 | call                dword ptr [esi]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_2 = { 8dbd01feffff ab ab ab ab }
            // n = 5, score = 100
            //   8dbd01feffff         | lea                 edi, [ebp - 0x1ff]
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_3 = { c78534ffffffdfa04cab c78538ffffff1a0dccc9 c7853cffffffc9d42289 c78540ffffff30bc1403 c78544ffffff1212cb9a c78548ffffff7c1bb287 }
            // n = 6, score = 100
            //   c78534ffffffdfa04cab     | mov    dword ptr [ebp - 0xcc], 0xab4ca0df
            //   c78538ffffff1a0dccc9     | mov    dword ptr [ebp - 0xc8], 0xc9cc0d1a
            //   c7853cffffffc9d42289     | mov    dword ptr [ebp - 0xc4], 0x8922d4c9
            //   c78540ffffff30bc1403     | mov    dword ptr [ebp - 0xc0], 0x314bc30
            //   c78544ffffff1212cb9a     | mov    dword ptr [ebp - 0xbc], 0x9acb1212
            //   c78548ffffff7c1bb287     | mov    dword ptr [ebp - 0xb8], 0x87b21b7c

        $sequence_4 = { 50 53 ff5608 3bc3 745f 48 8945f8 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff5608               | call                dword ptr [esi + 8]
            //   3bc3                 | cmp                 eax, ebx
            //   745f                 | je                  0x61
            //   48                   | dec                 eax
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_5 = { 6a06 8d472c 50 8d4588 }
            // n = 4, score = 100
            //   6a06                 | push                6
            //   8d472c               | lea                 eax, [edi + 0x2c]
            //   50                   | push                eax
            //   8d4588               | lea                 eax, [ebp - 0x78]

        $sequence_6 = { 33c0 8dbd04ffffff ab 889d08ffffff 8dbd09ffffff ab ab }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   8dbd04ffffff         | lea                 edi, [ebp - 0xfc]
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   889d08ffffff         | mov                 byte ptr [ebp - 0xf8], bl
            //   8dbd09ffffff         | lea                 edi, [ebp - 0xf7]
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_7 = { 6800804000 ff15???????? 833d????????00 7508 6a01 e8???????? }
            // n = 6, score = 100
            //   6800804000           | push                0x408000
            //   ff15????????         |                     
            //   833d????????00       |                     
            //   7508                 | jne                 0xa
            //   6a01                 | push                1
            //   e8????????           |                     

        $sequence_8 = { 47 83c614 3b7d14 72e3 }
            // n = 4, score = 100
            //   47                   | inc                 edi
            //   83c614               | add                 esi, 0x14
            //   3b7d14               | cmp                 edi, dword ptr [ebp + 0x14]
            //   72e3                 | jb                  0xffffffe5

        $sequence_9 = { 8955a0 c745a409da9df3 c745a8a050afad c745ac0df0ef96 c745b03b41b6e2 33c0 8d7db4 }
            // n = 7, score = 100
            //   8955a0               | mov                 dword ptr [ebp - 0x60], edx
            //   c745a409da9df3       | mov                 dword ptr [ebp - 0x5c], 0xf39dda09
            //   c745a8a050afad       | mov                 dword ptr [ebp - 0x58], 0xadaf50a0
            //   c745ac0df0ef96       | mov                 dword ptr [ebp - 0x54], 0x96eff00d
            //   c745b03b41b6e2       | mov                 dword ptr [ebp - 0x50], 0xe2b6413b
            //   33c0                 | xor                 eax, eax
            //   8d7db4               | lea                 edi, [ebp - 0x4c]

    condition:
        7 of them and filesize < 49152
}
