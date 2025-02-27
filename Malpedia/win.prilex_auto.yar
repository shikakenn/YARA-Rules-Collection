rule win_prilex_auto {

    meta:
        id = "1YI5XAN0Ek8Hj4tZbthWe4"
        fingerprint = "v1_sha256_6de539b63b8562d1b8bdbaceab1132bb64a8bf2aa0cf4524ffc6127b96beab6c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.prilex."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prilex"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 2b4814 898de8feffff 8b55ac 8b85e8feffff 3b4210 730c }
            // n = 6, score = 400
            //   2b4814               | sub                 ecx, dword ptr [eax + 0x14]
            //   898de8feffff         | mov                 dword ptr [ebp - 0x118], ecx
            //   8b55ac               | mov                 edx, dword ptr [ebp - 0x54]
            //   8b85e8feffff         | mov                 eax, dword ptr [ebp - 0x118]
            //   3b4210               | cmp                 eax, dword ptr [edx + 0x10]
            //   730c                 | jae                 0xe

        $sequence_1 = { 8b45a0 8985b4feffff c745a000000000 8b8db4feffff 898d54ffffff }
            // n = 5, score = 400
            //   8b45a0               | mov                 eax, dword ptr [ebp - 0x60]
            //   8985b4feffff         | mov                 dword ptr [ebp - 0x14c], eax
            //   c745a000000000       | mov                 dword ptr [ebp - 0x60], 0
            //   8b8db4feffff         | mov                 ecx, dword ptr [ebp - 0x14c]
            //   898d54ffffff         | mov                 dword ptr [ebp - 0xac], ecx

        $sequence_2 = { 6aff 52 895dbc e8???????? ffd6 }
            // n = 5, score = 400
            //   6aff                 | push                -1
            //   52                   | push                edx
            //   895dbc               | mov                 dword ptr [ebp - 0x44], ebx
            //   e8????????           |                     
            //   ffd6                 | call                esi

        $sequence_3 = { 0f8097000000 50 6a01 6a03 51 6a04 }
            // n = 6, score = 400
            //   0f8097000000         | jo                  0x9d
            //   50                   | push                eax
            //   6a01                 | push                1
            //   6a03                 | push                3
            //   51                   | push                ecx
            //   6a04                 | push                4

        $sequence_4 = { 7405 e9???????? c745fc15000000 6a00 }
            // n = 4, score = 400
            //   7405                 | je                  7
            //   e9????????           |                     
            //   c745fc15000000       | mov                 dword ptr [ebp - 4], 0x15
            //   6a00                 | push                0

        $sequence_5 = { 897db0 ff15???????? 50 8d45d8 50 ff15???????? 8bf0 }
            // n = 7, score = 400
            //   897db0               | mov                 dword ptr [ebp - 0x50], edi
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_6 = { e8???????? 8bf8 ff15???????? 8d55d4 }
            // n = 4, score = 400
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   ff15????????         |                     
            //   8d55d4               | lea                 edx, [ebp - 0x2c]

        $sequence_7 = { 52 ff15???????? 50 8b4508 8b08 51 57 }
            // n = 7, score = 400
            //   52                   | push                edx
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   51                   | push                ecx
            //   57                   | push                edi

        $sequence_8 = { ffd6 50 8d4da0 68???????? 51 ffd6 }
            // n = 6, score = 400
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   8d4da0               | lea                 ecx, [ebp - 0x60]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ffd6                 | call                esi

        $sequence_9 = { ff15???????? 8b4d08 8b35???????? b808000000 }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b35????????         |                     
            //   b808000000           | mov                 eax, 8

    condition:
        7 of them and filesize < 450560
}
