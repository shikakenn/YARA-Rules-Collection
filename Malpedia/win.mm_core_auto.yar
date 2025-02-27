rule win_mm_core_auto {

    meta:
        id = "39SaXyPT2tFoAJXUor0Do6"
        fingerprint = "v1_sha256_29ec3357b82a9f4eff6706385f45e4b797a4fc7c02bf49f9f64641ab1015abf0"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mm_core."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mm_core"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 68???????? 57 89442430 ffd6 68???????? 57 89442434 }
            // n = 7, score = 200
            //   68????????           |                     
            //   57                   | push                edi
            //   89442430             | mov                 dword ptr [esp + 0x30], eax
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   57                   | push                edi
            //   89442434             | mov                 dword ptr [esp + 0x34], eax

        $sequence_1 = { 8b5608 8d0417 3b4604 761d c1e80a 40 c1e00a }
            // n = 7, score = 200
            //   8b5608               | mov                 edx, dword ptr [esi + 8]
            //   8d0417               | lea                 eax, [edi + edx]
            //   3b4604               | cmp                 eax, dword ptr [esi + 4]
            //   761d                 | jbe                 0x1f
            //   c1e80a               | shr                 eax, 0xa
            //   40                   | inc                 eax
            //   c1e00a               | shl                 eax, 0xa

        $sequence_2 = { 752e 8b45b8 8b483c 894df8 }
            // n = 4, score = 200
            //   752e                 | jne                 0x30
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   8b483c               | mov                 ecx, dword ptr [eax + 0x3c]
            //   894df8               | mov                 dword ptr [ebp - 8], ecx

        $sequence_3 = { 0fbe07 83c099 46 83f811 7713 }
            // n = 5, score = 200
            //   0fbe07               | movsx               eax, byte ptr [edi]
            //   83c099               | add                 eax, -0x67
            //   46                   | inc                 esi
            //   83f811               | cmp                 eax, 0x11
            //   7713                 | ja                  0x15

        $sequence_4 = { 51 52 50 68???????? b9ff0f0000 }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   52                   | push                edx
            //   50                   | push                eax
            //   68????????           |                     
            //   b9ff0f0000           | mov                 ecx, 0xfff

        $sequence_5 = { 6a00 50 e8???????? 83c40c 33c0 33c9 8d542408 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   33c0                 | xor                 eax, eax
            //   33c9                 | xor                 ecx, ecx
            //   8d542408             | lea                 edx, [esp + 8]

        $sequence_6 = { 83c440 8d942460030000 52 68???????? b923010000 e8???????? }
            // n = 6, score = 200
            //   83c440               | add                 esp, 0x40
            //   8d942460030000       | lea                 edx, [esp + 0x360]
            //   52                   | push                edx
            //   68????????           |                     
            //   b923010000           | mov                 ecx, 0x123
            //   e8????????           |                     

        $sequence_7 = { 8b442428 8bce e8???????? 56 55 ffd3 }
            // n = 6, score = 200
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   56                   | push                esi
            //   55                   | push                ebp
            //   ffd3                 | call                ebx

        $sequence_8 = { 8b35???????? 33c0 6801040000 89442418 89442414 8944241c }
            // n = 6, score = 200
            //   8b35????????         |                     
            //   33c0                 | xor                 eax, eax
            //   6801040000           | push                0x401
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax

        $sequence_9 = { 68???????? e8???????? b8???????? 83c430 8d5002 }
            // n = 5, score = 200
            //   68????????           |                     
            //   e8????????           |                     
            //   b8????????           |                     
            //   83c430               | add                 esp, 0x30
            //   8d5002               | lea                 edx, [eax + 2]

    condition:
        7 of them and filesize < 319488
}
