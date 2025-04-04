rule win_blackcat_auto {

    meta:
        id = "1VryYSzTiX397wtwclR41W"
        fingerprint = "v1_sha256_ca17c8ec53cce7ae9541a2b17fcd5b20eeda404acb33b9d6489549a59a5a4868"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.blackcat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackcat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ffd0 eb09 8d45f8 50 }
            // n = 4, score = 600
            //   ffd0                 | call                eax
            //   eb09                 | jmp                 0xb
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax

        $sequence_1 = { f20f10459c f20f104da4 8b4df0 8d045b 8d14f500000000 8945e4 8d1452 }
            // n = 7, score = 600
            //   f20f10459c           | movsd               xmm0, qword ptr [ebp - 0x64]
            //   f20f104da4           | movsd               xmm1, qword ptr [ebp - 0x5c]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8d045b               | lea                 eax, [ebx + ebx*2]
            //   8d14f500000000       | lea                 edx, [esi*8]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8d1452               | lea                 edx, [edx + edx*2]

        $sequence_2 = { 84c0 0f858b010000 8d4704 31db }
            // n = 4, score = 600
            //   84c0                 | test                al, al
            //   0f858b010000         | jne                 0x191
            //   8d4704               | lea                 eax, [edi + 4]
            //   31db                 | xor                 ebx, ebx

        $sequence_3 = { 89c1 a3???????? ffd1 8b0d???????? 89c6 85c9 751f }
            // n = 7, score = 600
            //   89c1                 | mov                 ecx, eax
            //   a3????????           |                     
            //   ffd1                 | call                ecx
            //   8b0d????????         |                     
            //   89c6                 | mov                 esi, eax
            //   85c9                 | test                ecx, ecx
            //   751f                 | jne                 0x21

        $sequence_4 = { 8d441601 29d7 8901 8945d4 897904 0f8486000000 }
            // n = 6, score = 600
            //   8d441601             | lea                 eax, [esi + edx + 1]
            //   29d7                 | sub                 edi, edx
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   897904               | mov                 dword ptr [ecx + 4], edi
            //   0f8486000000         | je                  0x8c

        $sequence_5 = { 0f8765ffffff 8b45e4 01d8 ff75ec ff75dc 50 e8???????? }
            // n = 7, score = 600
            //   0f8765ffffff         | ja                  0xffffff6b
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   01d8                 | add                 eax, ebx
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { 895ddc 8b5dec 8b75e0 8b4df0 89d8 }
            // n = 5, score = 600
            //   895ddc               | mov                 dword ptr [ebp - 0x24], ebx
            //   8b5dec               | mov                 ebx, dword ptr [ebp - 0x14]
            //   8b75e0               | mov                 esi, dword ptr [ebp - 0x20]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   89d8                 | mov                 eax, ebx

        $sequence_7 = { 6820010000 68???????? 6a28 eb23 81f900000200 7326 }
            // n = 6, score = 600
            //   6820010000           | push                0x120
            //   68????????           |                     
            //   6a28                 | push                0x28
            //   eb23                 | jmp                 0x25
            //   81f900000200         | cmp                 ecx, 0x20000
            //   7326                 | jae                 0x28

        $sequence_8 = { 29d9 39f9 721a 01d8 57 52 50 }
            // n = 7, score = 600
            //   29d9                 | sub                 ecx, ebx
            //   39f9                 | cmp                 ecx, edi
            //   721a                 | jb                  0x1c
            //   01d8                 | add                 eax, ebx
            //   57                   | push                edi
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_9 = { 56 83ec10 89ce 8b4a04 }
            // n = 4, score = 600
            //   56                   | push                esi
            //   83ec10               | sub                 esp, 0x10
            //   89ce                 | mov                 esi, ecx
            //   8b4a04               | mov                 ecx, dword ptr [edx + 4]

    condition:
        7 of them and filesize < 29981696
}
