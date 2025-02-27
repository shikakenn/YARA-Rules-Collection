rule win_risepro_auto {

    meta:
        id = "668AuQM8ssKtMEmvMnqbSD"
        fingerprint = "v1_sha256_d29313e60d544119ebfa72aa2a82b5ab903014cb2fa565cd9721952588d526d1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.risepro."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.risepro"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0fb695e4feffff 52 0fb685e3feffff 50 0fb68de2feffff }
            // n = 5, score = 100
            //   0fb695e4feffff       | movzx               edx, byte ptr [ebp - 0x11c]
            //   52                   | push                edx
            //   0fb685e3feffff       | movzx               eax, byte ptr [ebp - 0x11d]
            //   50                   | push                eax
            //   0fb68de2feffff       | movzx               ecx, byte ptr [ebp - 0x11e]

        $sequence_1 = { 0fb655ff 52 8b450c 50 8b4d08 51 8b4df8 }
            // n = 7, score = 100
            //   0fb655ff             | movzx               edx, byte ptr [ebp - 1]
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_2 = { eb0d 6a64 ff15???????? e9???????? 8b4df4 }
            // n = 5, score = 100
            //   eb0d                 | jmp                 0xf
            //   6a64                 | push                0x64
            //   ff15????????         |                     
            //   e9????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_3 = { e8???????? 50 ba0f000000 8b4dbc e8???????? 8945d4 8b4dd8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   ba0f000000           | mov                 edx, 0xf
            //   8b4dbc               | mov                 ecx, dword ptr [ebp - 0x44]
            //   e8????????           |                     
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]

        $sequence_4 = { 8b049500ef4100 f644082801 7422 8d4508 8975f8 8945f4 8d4dff }
            // n = 7, score = 100
            //   8b049500ef4100       | mov                 eax, dword ptr [edx*4 + 0x41ef00]
            //   f644082801           | test                byte ptr [eax + ecx + 0x28], 1
            //   7422                 | je                  0x24
            //   8d4508               | lea                 eax, [ebp + 8]
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8d4dff               | lea                 ecx, [ebp - 1]

        $sequence_5 = { 8b4dd8 e8???????? 8b45f4 8b4df8 8908 eb27 8b5514 }
            // n = 7, score = 100
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   e8????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   eb27                 | jmp                 0x29
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]

        $sequence_6 = { 8d5584 52 8d4dbc e8???????? 8b00 89459c 8d4d80 }
            // n = 7, score = 100
            //   8d5584               | lea                 edx, [ebp - 0x7c]
            //   52                   | push                edx
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]
            //   e8????????           |                     
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   89459c               | mov                 dword ptr [ebp - 0x64], eax
            //   8d4d80               | lea                 ecx, [ebp - 0x80]

        $sequence_7 = { 8b4d0c e8???????? 8b4dfc e8???????? 8b45fc 8be5 5d }
            // n = 7, score = 100
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_8 = { 6a00 8d4b08 e8???????? 33c9 884db7 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   8d4b08               | lea                 ecx, [ebx + 8]
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   884db7               | mov                 byte ptr [ebp - 0x49], cl

        $sequence_9 = { 8945dc 8b4d08 e8???????? 8bd0 8d4de7 e8???????? }
            // n = 6, score = 100
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d4de7               | lea                 ecx, [ebp - 0x19]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 280576
}
