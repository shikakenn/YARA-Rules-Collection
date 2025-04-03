rule win_solarbot_auto {

    meta:
        id = "5GBYFdTT4eHjDVnL2mPSkd"
        fingerprint = "v1_sha256_78704c2bda81ce32f769ec7e509f90cf94c947eb12d602603a0979d813473a0e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.solarbot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.solarbot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c745fc00000000 c745dc18000000 c745e400000000 c745e800000000 }
            // n = 4, score = 300
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   c745dc18000000       | mov                 dword ptr [ebp - 0x24], 0x18
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   c745e800000000       | mov                 dword ptr [ebp - 0x18], 0

        $sequence_1 = { 83ec10 895df0 8975f4 e8???????? 89c6 }
            // n = 5, score = 300
            //   83ec10               | sub                 esp, 0x10
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   e8????????           |                     
            //   89c6                 | mov                 esi, eax

        $sequence_2 = { 8b55f4 01d0 50 e8???????? }
            // n = 4, score = 300
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   01d0                 | add                 eax, edx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { 8b5510 8955fc c745f800000000 6a00 }
            // n = 4, score = 300
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   6a00                 | push                0

        $sequence_4 = { 8b45f8 8b400c 8b00 8945f4 83c018 8b00 8945fc }
            // n = 7, score = 300
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   83c018               | add                 eax, 0x18
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_5 = { 8b4508 8945cc 8b7d0c 8b4510 8b5514 c745c800000000 c745e400000000 }
            // n = 7, score = 300
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   c745c800000000       | mov                 dword ptr [ebp - 0x38], 0
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0

        $sequence_6 = { 53 e8???????? 83fe04 750a ff75f0 56 }
            // n = 6, score = 300
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83fe04               | cmp                 esi, 4
            //   750a                 | jne                 0xc
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   56                   | push                esi

        $sequence_7 = { 0f84be000000 53 e8???????? 89c6 ff75a8 }
            // n = 5, score = 300
            //   0f84be000000         | je                  0xc4
            //   53                   | push                ebx
            //   e8????????           |                     
            //   89c6                 | mov                 esi, eax
            //   ff75a8               | push                dword ptr [ebp - 0x58]

        $sequence_8 = { 8b7508 8b7d0c bb00000000 68cc020000 8d8534fdffff }
            // n = 5, score = 300
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   bb00000000           | mov                 ebx, 0
            //   68cc020000           | push                0x2cc
            //   8d8534fdffff         | lea                 eax, [ebp - 0x2cc]

        $sequence_9 = { 89f0 c1e002 038550feffff 8b955cfeffff 8910 81fefa000000 }
            // n = 6, score = 300
            //   89f0                 | mov                 eax, esi
            //   c1e002               | shl                 eax, 2
            //   038550feffff         | add                 eax, dword ptr [ebp - 0x1b0]
            //   8b955cfeffff         | mov                 edx, dword ptr [ebp - 0x1a4]
            //   8910                 | mov                 dword ptr [eax], edx
            //   81fefa000000         | cmp                 esi, 0xfa

    condition:
        7 of them and filesize < 204800
}
