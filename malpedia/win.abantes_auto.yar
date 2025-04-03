rule win_abantes_auto {

    meta:
        id = "717clJ2Xe7pxF4RARJWJPH"
        fingerprint = "v1_sha256_bfdd171fe05f7811b61592e155c25025093087db93bdbe0eceaf522fc917d5dd"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.abantes"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 85c0 740f 807d0800 7509 33c0 b91c2b0110 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   807d0800             | cmp                 byte ptr [ebp + 8], 0
            //   7509                 | jne                 0xb
            //   33c0                 | xor                 eax, eax
            //   b91c2b0110           | mov                 ecx, 0x10012b1c

        $sequence_1 = { 85f6 740b 83feff 0f8483000000 eb7d 8b1c9dd0c90010 6800080000 }
            // n = 7, score = 100
            //   85f6                 | test                esi, esi
            //   740b                 | je                  0xd
            //   83feff               | cmp                 esi, -1
            //   0f8483000000         | je                  0x89
            //   eb7d                 | jmp                 0x7f
            //   8b1c9dd0c90010       | mov                 ebx, dword ptr [ebx*4 + 0x1000c9d0]
            //   6800080000           | push                0x800

        $sequence_2 = { 8b4104 85c0 7505 b8d8c10010 c3 }
            // n = 5, score = 100
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   b8d8c10010           | mov                 eax, 0x1000c1d8
            //   c3                   | ret                 

        $sequence_3 = { e9???????? c745dc02000000 c745e004204100 8b4508 }
            // n = 4, score = 100
            //   e9????????           |                     
            //   c745dc02000000       | mov                 dword ptr [ebp - 0x24], 2
            //   c745e004204100       | mov                 dword ptr [ebp - 0x20], 0x412004
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_4 = { b90c2d0110 e8???????? ff35???????? e8???????? ff35???????? }
            // n = 5, score = 100
            //   b90c2d0110           | mov                 ecx, 0x10012d0c
            //   e8????????           |                     
            //   ff35????????         |                     
            //   e8????????           |                     
            //   ff35????????         |                     

        $sequence_5 = { ebec 49 83cb03 ebe6 }
            // n = 4, score = 100
            //   ebec                 | jmp                 0xffffffee
            //   49                   | dec                 ecx
            //   83cb03               | or                  ebx, 3
            //   ebe6                 | jmp                 0xffffffe8

        $sequence_6 = { 0e 1f f8 4c 2cfc }
            // n = 5, score = 100
            //   0e                   | push                cs
            //   1f                   | pop                 ds
            //   f8                   | clc                 
            //   4c                   | dec                 esp
            //   2cfc                 | sub                 al, 0xfc

        $sequence_7 = { 8bff 55 8bec 6b450818 05102e0110 50 ff15???????? }
            // n = 7, score = 100
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   6b450818             | imul                eax, dword ptr [ebp + 8], 0x18
            //   05102e0110           | add                 eax, 0x10012e10
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_8 = { 57 8db8f84c4100 57 ff15???????? }
            // n = 4, score = 100
            //   57                   | push                edi
            //   8db8f84c4100         | lea                 edi, [eax + 0x414cf8]
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_9 = { ff7508 8bf1 e8???????? c7060cc20010 }
            // n = 4, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   c7060cc20010         | mov                 dword ptr [esi], 0x1000c20c

    condition:
        7 of them and filesize < 4587520
}
