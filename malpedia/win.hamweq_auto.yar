rule win_hamweq_auto {

    meta:
        id = "5NPUafym39YHLHbNSyevX"
        fingerprint = "v1_sha256_97fb94f14abe15a4280f753f2ae96a2750195cd748cddbf78c3df32e07994a82"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.hamweq."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hamweq"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6800000040 50 ff5118 8945f4 }
            // n = 4, score = 200
            //   6800000040           | push                0x40000000
            //   50                   | push                eax
            //   ff5118               | call                dword ptr [ecx + 0x18]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

        $sequence_1 = { 740d 3c32 7409 c745fc01000000 eb33 8d45e0 8b0e }
            // n = 7, score = 200
            //   740d                 | je                  0xf
            //   3c32                 | cmp                 al, 0x32
            //   7409                 | je                  0xb
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   eb33                 | jmp                 0x35
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   8b0e                 | mov                 ecx, dword ptr [esi]

        $sequence_2 = { 8b06 ff7140 8d8de0fdffff 51 ff5048 }
            // n = 5, score = 200
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   ff7140               | push                dword ptr [ecx + 0x40]
            //   8d8de0fdffff         | lea                 ecx, [ebp - 0x220]
            //   51                   | push                ecx
            //   ff5048               | call                dword ptr [eax + 0x48]

        $sequence_3 = { 0f8484030000 837de000 0f847a030000 85c0 0f8472030000 }
            // n = 5, score = 200
            //   0f8484030000         | je                  0x38a
            //   837de000             | cmp                 dword ptr [ebp - 0x20], 0
            //   0f847a030000         | je                  0x380
            //   85c0                 | test                eax, eax
            //   0f8472030000         | je                  0x378

        $sequence_4 = { ffb150010000 8d8de8fdffff 51 ff5048 }
            // n = 4, score = 200
            //   ffb150010000         | push                dword ptr [ecx + 0x150]
            //   8d8de8fdffff         | lea                 ecx, [ebp - 0x218]
            //   51                   | push                ecx
            //   ff5048               | call                dword ptr [eax + 0x48]

        $sequence_5 = { 50 8d85ecfeffff 50 895dfc ff5154 8b06 8d8decfeffff }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d85ecfeffff         | lea                 eax, [ebp - 0x114]
            //   50                   | push                eax
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   ff5154               | call                dword ptr [ecx + 0x54]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8d8decfeffff         | lea                 ecx, [ebp - 0x114]

        $sequence_6 = { 8d4580 8b0b 50 ff5154 }
            // n = 4, score = 200
            //   8d4580               | lea                 eax, [ebp - 0x80]
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   50                   | push                eax
            //   ff5154               | call                dword ptr [ecx + 0x54]

        $sequence_7 = { 8b06 753c ffb1d8000000 8d8d00feffff 51 }
            // n = 5, score = 200
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   753c                 | jne                 0x3e
            //   ffb1d8000000         | push                dword ptr [ecx + 0xd8]
            //   8d8d00feffff         | lea                 ecx, [ebp - 0x200]
            //   51                   | push                ecx

        $sequence_8 = { 889decfeffff ffb178010000 8d8decfeffff 51 }
            // n = 4, score = 200
            //   889decfeffff         | mov                 byte ptr [ebp - 0x114], bl
            //   ffb178010000         | push                dword ptr [ecx + 0x178]
            //   8d8decfeffff         | lea                 ecx, [ebp - 0x114]
            //   51                   | push                ecx

        $sequence_9 = { ff75f8 ffd6 ff35???????? 898534ffffff ff75f8 ffd6 ff35???????? }
            // n = 7, score = 200
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ffd6                 | call                esi
            //   ff35????????         |                     
            //   898534ffffff         | mov                 dword ptr [ebp - 0xcc], eax
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ffd6                 | call                esi
            //   ff35????????         |                     

    condition:
        7 of them and filesize < 24576
}
