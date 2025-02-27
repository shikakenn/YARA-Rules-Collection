rule win_salgorea_auto {

    meta:
        id = "65JbFw7nszCsR5TCM6xcvg"
        fingerprint = "v1_sha256_84460b5404731160a6417d2e0703563ce9ec3d697d914eab182f90119819d293"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.salgorea."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.salgorea"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { f6d7 f7d9 6633d2 66b8b4d2 66b918f6 66f7f1 }
            // n = 6, score = 300
            //   f6d7                 | not                 bh
            //   f7d9                 | neg                 ecx
            //   6633d2               | xor                 dx, dx
            //   66b8b4d2             | mov                 ax, 0xd2b4
            //   66b918f6             | mov                 cx, 0xf618
            //   66f7f1               | div                 cx

        $sequence_1 = { 57 8b7910 3bfb 0f830a000000 }
            // n = 4, score = 300
            //   57                   | push                edi
            //   8b7910               | mov                 edi, dword ptr [ecx + 0x10]
            //   3bfb                 | cmp                 edi, ebx
            //   0f830a000000         | jae                 0x10

        $sequence_2 = { 8b44240c 0fbafa00 0fbcd2 8b542418 }
            // n = 4, score = 300
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   0fbafa00             | btc                 edx, 0
            //   0fbcd2               | bsf                 edx, edx
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]

        $sequence_3 = { d1e0 2ac1 0fbae001 37 d0e0 }
            // n = 5, score = 300
            //   d1e0                 | shl                 eax, 1
            //   2ac1                 | sub                 al, cl
            //   0fbae001             | bt                  eax, 1
            //   37                   | aaa                 
            //   d0e0                 | shl                 al, 1

        $sequence_4 = { b85b000000 51 b92ae90000 f7f1 0fbae304 6603c9 }
            // n = 6, score = 300
            //   b85b000000           | mov                 eax, 0x5b
            //   51                   | push                ecx
            //   b92ae90000           | mov                 ecx, 0xe92a
            //   f7f1                 | div                 ecx
            //   0fbae304             | bt                  ebx, 4
            //   6603c9               | add                 cx, cx

        $sequence_5 = { 3bfb 0f830a000000 68???????? e8???????? 8b4510 }
            // n = 5, score = 300
            //   3bfb                 | cmp                 edi, ebx
            //   0f830a000000         | jae                 0x10
            //   68????????           |                     
            //   e8????????           |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_6 = { 660fbafa04 2f fec3 27 b885000000 f9 81f1b8600000 }
            // n = 7, score = 300
            //   660fbafa04           | btc                 dx, 4
            //   2f                   | das                 
            //   fec3                 | inc                 bl
            //   27                   | daa                 
            //   b885000000           | mov                 eax, 0x85
            //   f9                   | stc                 
            //   81f1b8600000         | xor                 ecx, 0x60b8

        $sequence_7 = { 664b f9 52 80c237 66b86c00 }
            // n = 5, score = 300
            //   664b                 | dec                 bx
            //   f9                   | stc                 
            //   52                   | push                edx
            //   80c237               | add                 dl, 0x37
            //   66b86c00             | mov                 ax, 0x6c

        $sequence_8 = { a1???????? 8945cc 8d45cc 3930 }
            // n = 4, score = 200
            //   a1????????           |                     
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   3930                 | cmp                 dword ptr [eax], esi

        $sequence_9 = { 8d8c0ed6c162ca 8b704c 03f1 8b4850 }
            // n = 4, score = 100
            //   8d8c0ed6c162ca       | lea                 ecx, [esi + ecx - 0x359d3e2a]
            //   8b704c               | mov                 esi, dword ptr [eax + 0x4c]
            //   03f1                 | add                 esi, ecx
            //   8b4850               | mov                 ecx, dword ptr [eax + 0x50]

        $sequence_10 = { 8d8c0b78a46ad7 c1c107 03cf 8bde }
            // n = 4, score = 100
            //   8d8c0b78a46ad7       | lea                 ecx, [ebx + ecx - 0x28955b88]
            //   c1c107               | rol                 ecx, 7
            //   03cf                 | add                 ecx, edi
            //   8bde                 | mov                 ebx, esi

        $sequence_11 = { 8d8c24b8000000 51 e8???????? 83c40c }
            // n = 4, score = 100
            //   8d8c24b8000000       | lea                 ecx, [esp + 0xb8]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_12 = { 8d8c0b2211906b c1c107 03cf 8bfe }
            // n = 4, score = 100
            //   8d8c0b2211906b       | lea                 ecx, [ebx + ecx + 0x6b901122]
            //   c1c107               | rol                 ecx, 7
            //   03cf                 | add                 ecx, edi
            //   8bfe                 | mov                 edi, esi

        $sequence_13 = { 8d8c399979825a 8b7df4 337df8 8bd1 }
            // n = 4, score = 100
            //   8d8c399979825a       | lea                 ecx, [ecx + edi + 0x5a827999]
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]
            //   337df8               | xor                 edi, dword ptr [ebp - 8]
            //   8bd1                 | mov                 edx, ecx

        $sequence_14 = { 8d8c0550fbffff e8???????? 83c408 eb16 ff75f8 }
            // n = 5, score = 100
            //   8d8c0550fbffff       | lea                 ecx, [ebp + eax - 0x4b0]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   eb16                 | jmp                 0x18
            //   ff75f8               | push                dword ptr [ebp - 8]

        $sequence_15 = { 8d8c399979825a 8bfe 337df0 8bd1 }
            // n = 4, score = 100
            //   8d8c399979825a       | lea                 ecx, [ecx + edi + 0x5a827999]
            //   8bfe                 | mov                 edi, esi
            //   337df0               | xor                 edi, dword ptr [ebp - 0x10]
            //   8bd1                 | mov                 edx, ecx

    condition:
        7 of them and filesize < 2007040
}
