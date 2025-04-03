rule win_clop_auto {

    meta:
        id = "2kfxhJMNbbd2euDYQ1IjH8"
        fingerprint = "v1_sha256_3750789377624c88727401f0639208a90e22f423fdcc34c5c702f455dce2beef"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.clop."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83c40c 6860070000 6a40 ff15???????? }
            // n = 4, score = 900
            //   83c40c               | add                 esp, 0xc
            //   6860070000           | push                0x760
            //   6a40                 | push                0x40
            //   ff15????????         |                     

        $sequence_1 = { 6a04 6800300000 6887000000 6a00 }
            // n = 4, score = 900
            //   6a04                 | push                4
            //   6800300000           | push                0x3000
            //   6887000000           | push                0x87
            //   6a00                 | push                0

        $sequence_2 = { 53 ff15???????? 50 ff15???????? 56 53 8bf8 }
            // n = 7, score = 800
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   56                   | push                esi
            //   53                   | push                ebx
            //   8bf8                 | mov                 edi, eax

        $sequence_3 = { 6a00 ff15???????? 68???????? 8bd8 }
            // n = 4, score = 800
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   68????????           |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_4 = { 8bf8 ff15???????? 8bf0 56 6a40 }
            // n = 5, score = 800
            //   8bf8                 | mov                 edi, eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   6a40                 | push                0x40

        $sequence_5 = { 75be ddd8 db2d???????? b802000000 833d????????00 0f85f0080000 }
            // n = 6, score = 700
            //   75be                 | jne                 0xffffffc0
            //   ddd8                 | fstp                st(0)
            //   db2d????????         |                     
            //   b802000000           | mov                 eax, 2
            //   833d????????00       |                     
            //   0f85f0080000         | jne                 0x8f6

        $sequence_6 = { 0f842e0c0000 83ec08 0fae5c2404 8b442404 }
            // n = 4, score = 700
            //   0f842e0c0000         | je                  0xc34
            //   83ec08               | sub                 esp, 8
            //   0fae5c2404           | stmxcsr             dword ptr [esp + 4]
            //   8b442404             | mov                 eax, dword ptr [esp + 4]

        $sequence_7 = { 50 ff15???????? 83c40c 6860070000 }
            // n = 4, score = 600
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   6860070000           | push                0x760

        $sequence_8 = { 8d85bcefffff 50 ff15???????? 68???????? }
            // n = 4, score = 500
            //   8d85bcefffff         | lea                 eax, [ebp - 0x1044]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_9 = { 68???????? 68???????? e8???????? 83c424 6aff }
            // n = 5, score = 500
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   6aff                 | push                -1

        $sequence_10 = { 68???????? 50 ffd3 8d85d4f7ffff 50 }
            // n = 5, score = 500
            //   68????????           |                     
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   8d85d4f7ffff         | lea                 eax, [ebp - 0x82c]
            //   50                   | push                eax

        $sequence_11 = { ffd0 c3 8bff 55 8bec 83ec1c 8d4de4 }
            // n = 7, score = 500
            //   ffd0                 | call                eax
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec1c               | sub                 esp, 0x1c
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]

        $sequence_12 = { e8???????? 8be5 5d c20400 56 ff15???????? 6a00 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   56                   | push                esi
            //   ff15????????         |                     
            //   6a00                 | push                0

        $sequence_13 = { 0f85aa010000 68???????? 8d442450 50 }
            // n = 4, score = 500
            //   0f85aa010000         | jne                 0x1b0
            //   68????????           |                     
            //   8d442450             | lea                 eax, [esp + 0x50]
            //   50                   | push                eax

        $sequence_14 = { ff15???????? 68???????? 8d85dcf7ffff 50 }
            // n = 4, score = 500
            //   ff15????????         |                     
            //   68????????           |                     
            //   8d85dcf7ffff         | lea                 eax, [ebp - 0x824]
            //   50                   | push                eax

        $sequence_15 = { 6a00 6a00 e8???????? 83c408 6aff ff15???????? 33c0 }
            // n = 7, score = 400
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6aff                 | push                -1
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_16 = { 6aff ffd7 8b4dfc 33c0 5f }
            // n = 5, score = 300
            //   6aff                 | push                -1
            //   ffd7                 | call                edi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi

        $sequence_17 = { 83c40c 33f6 85ff 7428 }
            // n = 4, score = 300
            //   83c40c               | add                 esp, 0xc
            //   33f6                 | xor                 esi, esi
            //   85ff                 | test                edi, edi
            //   7428                 | je                  0x2a

        $sequence_18 = { 83c424 53 50 ffd6 }
            // n = 4, score = 300
            //   83c424               | add                 esp, 0x24
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_19 = { 6a00 56 ffd7 8b35???????? 6800800000 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   8b35????????         |                     
            //   6800800000           | push                0x8000

    condition:
        7 of them and filesize < 796672
}
