rule win_rarog_auto {

    meta:
        id = "6vC8ZAMTH07YtyUrbgezBU"
        fingerprint = "v1_sha256_dcc275a3610670298392baeef430ff6a6f46366e16201b4054f65002692c15e6"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.rarog."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rarog"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a00 68ffff1f00 ff15???????? 8bf8 57 ff15???????? 57 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   68ffff1f00           | push                0x1fffff
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   57                   | push                edi

        $sequence_1 = { 8819 e8???????? 83ec1c 8bc4 89a590fbffff 50 c645fc61 }
            // n = 7, score = 100
            //   8819                 | mov                 byte ptr [ecx], bl
            //   e8????????           |                     
            //   83ec1c               | sub                 esp, 0x1c
            //   8bc4                 | mov                 eax, esp
            //   89a590fbffff         | mov                 dword ptr [ebp - 0x470], esp
            //   50                   | push                eax
            //   c645fc61             | mov                 byte ptr [ebp - 4], 0x61

        $sequence_2 = { 8d8dd0feffff e8???????? 8d8d9cfdffff 51 8d8db4feffff 51 8bc8 }
            // n = 7, score = 100
            //   8d8dd0feffff         | lea                 ecx, [ebp - 0x130]
            //   e8????????           |                     
            //   8d8d9cfdffff         | lea                 ecx, [ebp - 0x264]
            //   51                   | push                ecx
            //   8d8db4feffff         | lea                 ecx, [ebp - 0x14c]
            //   51                   | push                ecx
            //   8bc8                 | mov                 ecx, eax

        $sequence_3 = { 8d8d7cfeffff e9???????? 8d8dd0feffff e9???????? }
            // n = 4, score = 100
            //   8d8d7cfeffff         | lea                 ecx, [ebp - 0x184]
            //   e9????????           |                     
            //   8d8dd0feffff         | lea                 ecx, [ebp - 0x130]
            //   e9????????           |                     

        $sequence_4 = { 8bf0 8bc4 e8???????? 83ec1c 8bcc c645fc3a 89a58cfbffff }
            // n = 7, score = 100
            //   8bf0                 | mov                 esi, eax
            //   8bc4                 | mov                 eax, esp
            //   e8????????           |                     
            //   83ec1c               | sub                 esp, 0x1c
            //   8bcc                 | mov                 ecx, esp
            //   c645fc3a             | mov                 byte ptr [ebp - 4], 0x3a
            //   89a58cfbffff         | mov                 dword ptr [ebp - 0x474], esp

        $sequence_5 = { 50 e8???????? 59 59 3bc7 7431 8bce }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   3bc7                 | cmp                 eax, edi
            //   7431                 | je                  0x33
            //   8bce                 | mov                 ecx, esi

        $sequence_6 = { c746140f000000 895e10 881e 895dfc 8b4710 0305???????? }
            // n = 6, score = 100
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   895e10               | mov                 dword ptr [esi + 0x10], ebx
            //   881e                 | mov                 byte ptr [esi], bl
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   8b4710               | mov                 eax, dword ptr [edi + 0x10]
            //   0305????????         |                     

        $sequence_7 = { 83c40c ff75b4 8945ac 0fbe45a0 50 57 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   ff75b4               | push                dword ptr [ebp - 0x4c]
            //   8945ac               | mov                 dword ptr [ebp - 0x54], eax
            //   0fbe45a0             | movsx               eax, byte ptr [ebp - 0x60]
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_8 = { e9???????? 8d8dfcfeffff e9???????? 8d8d50ffffff e9???????? 8d4da4 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8dfcfeffff         | lea                 ecx, [ebp - 0x104]
            //   e9????????           |                     
            //   8d8d50ffffff         | lea                 ecx, [ebp - 0xb0]
            //   e9????????           |                     
            //   8d4da4               | lea                 ecx, [ebp - 0x5c]
            //   e9????????           |                     

        $sequence_9 = { 53 56 8d8d2cfdffff e8???????? 53 56 8d8df4fcffff }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8d8d2cfdffff         | lea                 ecx, [ebp - 0x2d4]
            //   e8????????           |                     
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8d8df4fcffff         | lea                 ecx, [ebp - 0x30c]

    condition:
        7 of them and filesize < 598016
}
