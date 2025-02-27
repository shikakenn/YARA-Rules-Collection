rule osx_fruitfly_auto {

    meta:
        id = "209T76Y0tRW3WRsGS4olTt"
        fingerprint = "v1_sha256_0b34c90ebd7ed991dcbd9131db239b495d8c49febc0c1f6578fc4a548f26946f"
        version = "1"
        date = "2020-10-14"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.fruitfly"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b06 c7401417000000 8b06 893424 ff10 8b450c }
            // n = 6, score = 100
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   c7401417000000       | mov                 dword ptr [eax + 0x14], 0x17
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   893424               | mov                 dword ptr [esp], esi
            //   ff10                 | call                dword ptr [eax]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_1 = { be01000000 48 89df e8???????? 48 89de bf01000000 }
            // n = 7, score = 100
            //   be01000000           | mov                 esi, 1
            //   48                   | dec                 eax
            //   89df                 | mov                 edi, ebx
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   89de                 | mov                 esi, ebx
            //   bf01000000           | mov                 edi, 1

        $sequence_2 = { f20f1145a0 48 8b4580 48 89442420 48 }
            // n = 6, score = 100
            //   f20f1145a0           | movsd               qword ptr [ebp - 0x60], xmm0
            //   48                   | dec                 eax
            //   8b4580               | mov                 eax, dword ptr [ebp - 0x80]
            //   48                   | dec                 eax
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   48                   | dec                 eax

        $sequence_3 = { 0f8f05ffffff 8b45c0 ff4008 8b4508 83b8f000000002 }
            // n = 5, score = 100
            //   0f8f05ffffff         | jg                  0xffffff0b
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]
            //   ff4008               | inc                 dword ptr [eax + 8]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83b8f000000002       | cmp                 dword ptr [eax + 0xf0], 2

        $sequence_4 = { 8b05???????? 48 83c420 5b 41 5c }
            // n = 6, score = 100
            //   8b05????????         |                     
            //   48                   | dec                 eax
            //   83c420               | add                 esp, 0x20
            //   5b                   | pop                 ebx
            //   41                   | inc                 ecx
            //   5c                   | pop                 esp

        $sequence_5 = { 8b00 48 85c0 7402 ffd0 48 }
            // n = 6, score = 100
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   48                   | dec                 eax
            //   85c0                 | test                eax, eax
            //   7402                 | je                  4
            //   ffd0                 | call                eax
            //   48                   | dec                 eax

        $sequence_6 = { 895c2408 8d9622a60000 89542404 83c011 }
            // n = 4, score = 100
            //   895c2408             | mov                 dword ptr [esp + 8], ebx
            //   8d9622a60000         | lea                 edx, [esi + 0xa622]
            //   89542404             | mov                 dword ptr [esp + 4], edx
            //   83c011               | add                 eax, 0x11

        $sequence_7 = { 4c 89e7 e8???????? f20f1045a8 }
            // n = 4, score = 100
            //   4c                   | dec                 esp
            //   89e7                 | mov                 edi, esp
            //   e8????????           |                     
            //   f20f1045a8           | movsd               xmm0, qword ptr [ebp - 0x58]

        $sequence_8 = { 81f9???????? 75e1 85c0 0f888c000000 8b4d10 8b3c81 }
            // n = 6, score = 100
            //   81f9????????         |                     
            //   75e1                 | jne                 0xffffffe3
            //   85c0                 | test                eax, eax
            //   0f888c000000         | js                  0x92
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b3c81               | mov                 edi, dword ptr [ecx + eax*4]

        $sequence_9 = { e8???????? f20f2a45e8 f20f5905???????? f20f1145d0 f248 0f2a45e0 f20f5845d0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   f20f2a45e8           | cvtsi2sd            xmm0, dword ptr [ebp - 0x18]
            //   f20f5905????????     |                     
            //   f20f1145d0           | movsd               qword ptr [ebp - 0x30], xmm0
            //   f248                 | dec                 eax
            //   0f2a45e0             | cvtpi2ps            xmm0, qword ptr [ebp - 0x20]
            //   f20f5845d0           | addsd               xmm0, qword ptr [ebp - 0x30]

        $sequence_10 = { be67666666 8b45ec f7ee 89d6 c1ee1f 89d3 }
            // n = 6, score = 100
            //   be67666666           | mov                 esi, 0x66666667
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   f7ee                 | imul                esi
            //   89d6                 | mov                 esi, edx
            //   c1ee1f               | shr                 esi, 0x1f
            //   89d3                 | mov                 ebx, edx

        $sequence_11 = { 48 81ec???????? c645b000 c745b400000000 }
            // n = 4, score = 100
            //   48                   | dec                 eax
            //   81ec????????         |                     
            //   c645b000             | mov                 byte ptr [ebp - 0x50], 0
            //   c745b400000000       | mov                 dword ptr [ebp - 0x4c], 0

        $sequence_12 = { 8b4de4 0fb619 01fb 01de 0faf75e0 0faf55dc 8d943200800000 }
            // n = 7, score = 100
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   0fb619               | movzx               ebx, byte ptr [ecx]
            //   01fb                 | add                 ebx, edi
            //   01de                 | add                 esi, ebx
            //   0faf75e0             | imul                esi, dword ptr [ebp - 0x20]
            //   0faf55dc             | imul                edx, dword ptr [ebp - 0x24]
            //   8d943200800000       | lea                 edx, [edx + esi + 0x8000]

        $sequence_13 = { 8d55b0 48 899560fdffff 48 8d8d60ffffff 48 }
            // n = 6, score = 100
            //   8d55b0               | lea                 edx, [ebp - 0x50]
            //   48                   | dec                 eax
            //   899560fdffff         | mov                 dword ptr [ebp - 0x2a0], edx
            //   48                   | dec                 eax
            //   8d8d60ffffff         | lea                 ecx, [ebp - 0xa0]
            //   48                   | dec                 eax

        $sequence_14 = { c744240401000000 ff5104 8b4de8 894118 }
            // n = 4, score = 100
            //   c744240401000000     | mov                 dword ptr [esp + 4], 1
            //   ff5104               | call                dword ptr [ecx + 4]
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   894118               | mov                 dword ptr [ecx + 0x18], eax

        $sequence_15 = { e9???????? 8b45e4 8b44b80c 85c0 7522 8b4508 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8b44b80c             | mov                 eax, dword ptr [eax + edi*4 + 0xc]
            //   85c0                 | test                eax, eax
            //   7522                 | jne                 0x24
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 153734
}
