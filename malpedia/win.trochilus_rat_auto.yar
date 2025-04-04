rule win_trochilus_rat_auto {

    meta:
        id = "az8JCtcIOsonb6KMl8CuZ"
        fingerprint = "v1_sha256_28ef93658f73bc964eedcf05592130cfb5b477accac6e59366138836c637cdc2"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.trochilus_rat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.trochilus_rat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { bb00010000 e8???????? 85c0 7452 8bf0 eb2d 8b4d08 }
            // n = 7, score = 100
            //   bb00010000           | mov                 ebx, 0x100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7452                 | je                  0x54
            //   8bf0                 | mov                 esi, eax
            //   eb2d                 | jmp                 0x2f
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_1 = { 0f84e0000000 399d2cffffff 0f84d4000000 57 56 68???????? 53 }
            // n = 7, score = 100
            //   0f84e0000000         | je                  0xe6
            //   399d2cffffff         | cmp                 dword ptr [ebp - 0xd4], ebx
            //   0f84d4000000         | je                  0xda
            //   57                   | push                edi
            //   56                   | push                esi
            //   68????????           |                     
            //   53                   | push                ebx

        $sequence_2 = { 8b01 8d55fc 52 ff7510 ff750c ff5030 6a00 }
            // n = 7, score = 100
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8d55fc               | lea                 edx, [ebp - 4]
            //   52                   | push                edx
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff5030               | call                dword ptr [eax + 0x30]
            //   6a00                 | push                0

        $sequence_3 = { 8975e0 8db1f8190110 8975e4 eb2b 8a4601 84c0 7429 }
            // n = 7, score = 100
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   8db1f8190110         | lea                 esi, [ecx + 0x100119f8]
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   eb2b                 | jmp                 0x2d
            //   8a4601               | mov                 al, byte ptr [esi + 1]
            //   84c0                 | test                al, al
            //   7429                 | je                  0x2b

        $sequence_4 = { e8???????? 89442410 85c0 0f849e000000 8bf8 8d4728 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   85c0                 | test                eax, eax
            //   0f849e000000         | je                  0xa4
            //   8bf8                 | mov                 edi, eax
            //   8d4728               | lea                 eax, [edi + 0x28]

        $sequence_5 = { e8???????? c70009000000 e8???????? ebd5 8bc8 c1f905 8b0c8d409a8100 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c70009000000         | mov                 dword ptr [eax], 9
            //   e8????????           |                     
            //   ebd5                 | jmp                 0xffffffd7
            //   8bc8                 | mov                 ecx, eax
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d409a8100       | mov                 ecx, dword ptr [ecx*4 + 0x819a40]

        $sequence_6 = { 57 ff15???????? 33c0 5f 5d c20400 55 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   55                   | push                ebp

        $sequence_7 = { 85c0 7414 53 ff15???????? 8b4dfc 8bc6 e8???????? }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7414                 | je                  0x16
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     

        $sequence_8 = { 83630400 832300 8b4508 894308 8b450c }
            // n = 5, score = 100
            //   83630400             | and                 dword ptr [ebx + 4], 0
            //   832300               | and                 dword ptr [ebx], 0
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   894308               | mov                 dword ptr [ebx + 8], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_9 = { 8d8534ffffff 50 8d8d7cffffff e8???????? 397df0 764d 837df408 }
            // n = 7, score = 100
            //   8d8534ffffff         | lea                 eax, [ebp - 0xcc]
            //   50                   | push                eax
            //   8d8d7cffffff         | lea                 ecx, [ebp - 0x84]
            //   e8????????           |                     
            //   397df0               | cmp                 dword ptr [ebp - 0x10], edi
            //   764d                 | jbe                 0x4f
            //   837df408             | cmp                 dword ptr [ebp - 0xc], 8

    condition:
        7 of them and filesize < 630784
}
