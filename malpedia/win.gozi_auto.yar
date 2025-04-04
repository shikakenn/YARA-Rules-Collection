rule win_gozi_auto {

    meta:
        id = "6YrbKr7X8ov3bxwY2oSQQG"
        fingerprint = "v1_sha256_6d080496b0bc709b18cae762326b65ba3fe68298a3c52833320cbdca2a2db665"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.gozi."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gozi"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3b4dfc 73df 33c0 5e c9 c21000 }
            // n = 6, score = 100
            //   3b4dfc               | cmp                 ecx, dword ptr [ebp - 4]
            //   73df                 | jae                 0xffffffe1
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c21000               | ret                 0x10

        $sequence_1 = { 0e 96 3b5375 60 }
            // n = 4, score = 100
            //   0e                   | push                cs
            //   96                   | xchg                eax, esi
            //   3b5375               | cmp                 edx, dword ptr [ebx + 0x75]
            //   60                   | pushal              

        $sequence_2 = { 48 fb 5c 3c32 7e02 }
            // n = 5, score = 100
            //   48                   | dec                 eax
            //   fb                   | sti                 
            //   5c                   | pop                 esp
            //   3c32                 | cmp                 al, 0x32
            //   7e02                 | jle                 4

        $sequence_3 = { 894508 eb03 897d08 bf???????? 57 }
            // n = 5, score = 100
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   eb03                 | jmp                 5
            //   897d08               | mov                 dword ptr [ebp + 8], edi
            //   bf????????           |                     
            //   57                   | push                edi

        $sequence_4 = { 0bc0 7408 60 50 e8???????? 61 }
            // n = 6, score = 100
            //   0bc0                 | or                  eax, eax
            //   7408                 | je                  0xa
            //   60                   | pushal              
            //   50                   | push                eax
            //   e8????????           |                     
            //   61                   | popal               

        $sequence_5 = { 7061 63743200 c808bf35 6963c03caff3da c9 50 0c73 }
            // n = 7, score = 100
            //   7061                 | jo                  0x63
            //   63743200             | arpl                word ptr [edx + esi], si
            //   c808bf35             | enter               -0x40f8, 0x35
            //   6963c03caff3da       | imul                esp, dword ptr [ebx - 0x40], 0xdaf3af3c
            //   c9                   | leave               
            //   50                   | push                eax
            //   0c73                 | or                  al, 0x73

        $sequence_6 = { 8b450c 03f0 8b4e0c 85c9 8975e8 0f8453010000 }
            // n = 6, score = 100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   03f0                 | add                 esi, eax
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]
            //   85c9                 | test                ecx, ecx
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi
            //   0f8453010000         | je                  0x159

        $sequence_7 = { 0faff1 c7458804000000 a1???????? 8b0d???????? 6a00 68f80a0000 }
            // n = 6, score = 100
            //   0faff1               | imul                esi, ecx
            //   c7458804000000       | mov                 dword ptr [ebp - 0x78], 4
            //   a1????????           |                     
            //   8b0d????????         |                     
            //   6a00                 | push                0
            //   68f80a0000           | push                0xaf8

        $sequence_8 = { 7e02 19c1 a6 3327 72e7 3ebb4a68d947 }
            // n = 6, score = 100
            //   7e02                 | jle                 4
            //   19c1                 | sbb                 ecx, eax
            //   a6                   | cmpsb               byte ptr [esi], byte ptr es:[edi]
            //   3327                 | xor                 esp, dword ptr [edi]
            //   72e7                 | jb                  0xffffffe9
            //   3ebb4a68d947         | mov                 ebx, 0x47d9684a

        $sequence_9 = { e8???????? 8945fc 6805010000 6a40 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   6805010000           | push                0x105
            //   6a40                 | push                0x40

        $sequence_10 = { 8b45fc 8b08 6a00 50 ff91a4000000 33c9 85c0 }
            // n = 7, score = 100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   ff91a4000000         | call                dword ptr [ecx + 0xa4]
            //   33c9                 | xor                 ecx, ecx
            //   85c0                 | test                eax, eax

        $sequence_11 = { 3a56b9 036890 2b02 9a102a6715fb53 }
            // n = 4, score = 100
            //   3a56b9               | cmp                 dl, byte ptr [esi - 0x47]
            //   036890               | add                 ebp, dword ptr [eax - 0x70]
            //   2b02                 | sub                 eax, dword ptr [edx]
            //   9a102a6715fb53       | lcall               0x53fb:0x15672a10

        $sequence_12 = { 0ad0 4a 0fca 8af4 0fbdf1 0fbaf6be }
            // n = 6, score = 100
            //   0ad0                 | or                  dl, al
            //   4a                   | dec                 edx
            //   0fca                 | bswap               edx
            //   8af4                 | mov                 dh, ah
            //   0fbdf1               | bsr                 esi, ecx
            //   0fbaf6be             | btr                 esi, 0xbe

        $sequence_13 = { ad b710 2dc7ce5bbb d6 b6c6 e8???????? 6af4 }
            // n = 7, score = 100
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   b710                 | mov                 bh, 0x10
            //   2dc7ce5bbb           | sub                 eax, 0xbb5bcec7
            //   d6                   | salc                
            //   b6c6                 | mov                 dh, 0xc6
            //   e8????????           |                     
            //   6af4                 | push                -0xc

        $sequence_14 = { 33c0 ebf7 56 8b74240c 57 }
            // n = 5, score = 100
            //   33c0                 | xor                 eax, eax
            //   ebf7                 | jmp                 0xfffffff9
            //   56                   | push                esi
            //   8b74240c             | mov                 esi, dword ptr [esp + 0xc]
            //   57                   | push                edi

        $sequence_15 = { 7708 8b4df8 e8???????? 837d0c00 766f 8b4df8 }
            // n = 6, score = 100
            //   7708                 | ja                  0xa
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   766f                 | jbe                 0x71
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_16 = { 55 8bec 83c4fc 53 837d0c4a }
            // n = 5, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83c4fc               | add                 esp, -4
            //   53                   | push                ebx
            //   837d0c4a             | cmp                 dword ptr [ebp + 0xc], 0x4a

        $sequence_17 = { 50 0c73 0e 96 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   0c73                 | or                  al, 0x73
            //   0e                   | push                cs
            //   96                   | xchg                eax, esi

        $sequence_18 = { e8???????? 8985b0feffff 8d8dbcfeffff 51 56 ffd0 85c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8985b0feffff         | mov                 dword ptr [ebp - 0x150], eax
            //   8d8dbcfeffff         | lea                 ecx, [ebp - 0x144]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax

        $sequence_19 = { ffd0 8345e404 ebe6 c745e0d4814300 817de0d8814300 }
            // n = 5, score = 100
            //   ffd0                 | call                eax
            //   8345e404             | add                 dword ptr [ebp - 0x1c], 4
            //   ebe6                 | jmp                 0xffffffe8
            //   c745e0d4814300       | mov                 dword ptr [ebp - 0x20], 0x4381d4
            //   817de0d8814300       | cmp                 dword ptr [ebp - 0x20], 0x4381d8

        $sequence_20 = { 1da2c9dde2 f4 16 ee 7f7b 36110b 33745571 }
            // n = 7, score = 100
            //   1da2c9dde2           | sbb                 eax, 0xe2ddc9a2
            //   f4                   | hlt                 
            //   16                   | push                ss
            //   ee                   | out                 dx, al
            //   7f7b                 | jg                  0x7d
            //   36110b               | adc                 dword ptr ss:[ebx], ecx
            //   33745571             | xor                 esi, dword ptr [ebp + edx*2 + 0x71]

        $sequence_21 = { 8b45d0 833800 755d 6a18 e8???????? }
            // n = 5, score = 100
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   833800               | cmp                 dword ptr [eax], 0
            //   755d                 | jne                 0x5f
            //   6a18                 | push                0x18
            //   e8????????           |                     

        $sequence_22 = { eb15 c745f0ffffffff 6a04 8d45f0 50 }
            // n = 5, score = 100
            //   eb15                 | jmp                 0x17
            //   c745f0ffffffff       | mov                 dword ptr [ebp - 0x10], 0xffffffff
            //   6a04                 | push                4
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax

        $sequence_23 = { 8b4dfc 8b09 85c9 0f84d7000000 }
            // n = 4, score = 100
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   85c9                 | test                ecx, ecx
            //   0f84d7000000         | je                  0xdd

        $sequence_24 = { ff45f0 48 8816 75ee }
            // n = 4, score = 100
            //   ff45f0               | inc                 dword ptr [ebp - 0x10]
            //   48                   | dec                 eax
            //   8816                 | mov                 byte ptr [esi], dl
            //   75ee                 | jne                 0xfffffff0

        $sequence_25 = { 0fadce d2ee 84e5 8af4 0fbdf1 }
            // n = 5, score = 100
            //   0fadce               | shrd                esi, ecx, cl
            //   d2ee                 | shr                 dh, cl
            //   84e5                 | test                ch, ah
            //   8af4                 | mov                 dh, ah
            //   0fbdf1               | bsr                 esi, ecx

        $sequence_26 = { 56 8d45fc 50 6a08 33f6 ff15???????? }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   6a08                 | push                8
            //   33f6                 | xor                 esi, esi
            //   ff15????????         |                     

        $sequence_27 = { b636 0fafd5 80cafa 69f1eef9d83b 8ad0 }
            // n = 5, score = 100
            //   b636                 | mov                 dh, 0x36
            //   0fafd5               | imul                edx, ebp
            //   80cafa               | or                  dl, 0xfa
            //   69f1eef9d83b         | imul                esi, ecx, 0x3bd8f9ee
            //   8ad0                 | mov                 dl, al

        $sequence_28 = { 0fbdf1 b67e d2ca f6de }
            // n = 4, score = 100
            //   0fbdf1               | bsr                 esi, ecx
            //   b67e                 | mov                 dh, 0x7e
            //   d2ca                 | ror                 dl, cl
            //   f6de                 | neg                 dh

        $sequence_29 = { 730d 898c85b0feffff ff85acfeffff 899da0feffff 33c0 8dbda4feffff ab }
            // n = 7, score = 100
            //   730d                 | jae                 0xf
            //   898c85b0feffff       | mov                 dword ptr [ebp + eax*4 - 0x150], ecx
            //   ff85acfeffff         | inc                 dword ptr [ebp - 0x154]
            //   899da0feffff         | mov                 dword ptr [ebp - 0x160], ebx
            //   33c0                 | xor                 eax, eax
            //   8dbda4feffff         | lea                 edi, [ebp - 0x15c]
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_30 = { ff15???????? 8bd8 3bde 895d64 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   3bde                 | cmp                 ebx, esi
            //   895d64               | mov                 dword ptr [ebp + 0x64], ebx

        $sequence_31 = { 53 c705????????00000000 68???????? 6a01 }
            // n = 4, score = 100
            //   53                   | push                ebx
            //   c705????????00000000     |     
            //   68????????           |                     
            //   6a01                 | push                1

    condition:
        7 of them and filesize < 568320
}
