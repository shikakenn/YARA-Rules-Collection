rule win_murkytop_auto {

    meta:
        id = "4NgUACu0CYXReHJn1pbKdM"
        fingerprint = "v1_sha256_e4a555eba2d93ac52653d0ddd1b98a4be2b8b9fd7f1c8d48fbca611f1976d1c2"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.murkytop."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.murkytop"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b35???????? c7450800000000 90 6800100000 8d8dd0eeffff 6a00 51 }
            // n = 7, score = 100
            //   8b35????????         |                     
            //   c7450800000000       | mov                 dword ptr [ebp + 8], 0
            //   90                   | nop                 
            //   6800100000           | push                0x1000
            //   8d8dd0eeffff         | lea                 ecx, [ebp - 0x1130]
            //   6a00                 | push                0
            //   51                   | push                ecx

        $sequence_1 = { e8???????? 8b5de0 8b75dc 8d4dec 83c418 8bf8 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b5de0               | mov                 ebx, dword ptr [ebp - 0x20]
            //   8b75dc               | mov                 esi, dword ptr [ebp - 0x24]
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   83c418               | add                 esp, 0x18
            //   8bf8                 | mov                 edi, eax

        $sequence_2 = { eb0b 3d2f050000 0f855fffffff 8b45f4 85c0 }
            // n = 5, score = 100
            //   eb0b                 | jmp                 0xd
            //   3d2f050000           | cmp                 eax, 0x52f
            //   0f855fffffff         | jne                 0xffffff65
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   85c0                 | test                eax, eax

        $sequence_3 = { 77cf 56 ff15???????? 85c0 74c4 8b500c }
            // n = 6, score = 100
            //   77cf                 | ja                  0xffffffd1
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   74c4                 | je                  0xffffffc6
            //   8b500c               | mov                 edx, dword ptr [eax + 0xc]

        $sequence_4 = { 52 50 51 68???????? e8???????? 83c424 6a00 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   50                   | push                eax
            //   51                   | push                ecx
            //   68????????           |                     
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   6a00                 | push                0

        $sequence_5 = { 52 56 68???????? e8???????? 8b45fc }
            // n = 5, score = 100
            //   52                   | push                edx
            //   56                   | push                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_6 = { 6a01 51 ff15???????? 3bc6 743f 50 ff15???????? }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   3bc6                 | cmp                 eax, esi
            //   743f                 | je                  0x41
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_7 = { 51 52 0fb6c0 50 68???????? 53 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   52                   | push                edx
            //   0fb6c0               | movzx               eax, al
            //   50                   | push                eax
            //   68????????           |                     
            //   53                   | push                ebx

        $sequence_8 = { eb08 8b4608 e8???????? 47 3b7d08 0f8c55ffffff 83fb05 }
            // n = 7, score = 100
            //   eb08                 | jmp                 0xa
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   e8????????           |                     
            //   47                   | inc                 edi
            //   3b7d08               | cmp                 edi, dword ptr [ebp + 8]
            //   0f8c55ffffff         | jl                  0xffffff5b
            //   83fb05               | cmp                 ebx, 5

        $sequence_9 = { 33f6 8b4dfc 8b511c 52 }
            // n = 4, score = 100
            //   33f6                 | xor                 esi, esi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b511c               | mov                 edx, dword ptr [ecx + 0x1c]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 294912
}
