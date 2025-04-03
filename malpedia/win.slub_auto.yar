rule win_slub_auto {

    meta:
        id = "4wR9l9lsR7bmsICtBVt6tS"
        fingerprint = "v1_sha256_aee363d67e6a37d8547028a75375273379b56a2505a09b01f68a1ed9e200ef20"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.slub."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.slub"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { eb02 8bc7 83fa10 7204 8b37 eb02 }
            // n = 6, score = 100
            //   eb02                 | jmp                 4
            //   8bc7                 | mov                 eax, edi
            //   83fa10               | cmp                 edx, 0x10
            //   7204                 | jb                  6
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   eb02                 | jmp                 4

        $sequence_1 = { 57 e8???????? 83a634010000fd 83c410 c6863801000001 80bea40b000000 740a }
            // n = 7, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   83a634010000fd       | and                 dword ptr [esi + 0x134], 0xfffffffd
            //   83c410               | add                 esp, 0x10
            //   c6863801000001       | mov                 byte ptr [esi + 0x138], 1
            //   80bea40b000000       | cmp                 byte ptr [esi + 0xba4], 0
            //   740a                 | je                  0xc

        $sequence_2 = { 83bfac010000ff b810020000 b920020000 0f45c1 833c3802 7408 8b9fe0000000 }
            // n = 7, score = 100
            //   83bfac010000ff       | cmp                 dword ptr [edi + 0x1ac], -1
            //   b810020000           | mov                 eax, 0x210
            //   b920020000           | mov                 ecx, 0x220
            //   0f45c1               | cmovne              eax, ecx
            //   833c3802             | cmp                 dword ptr [eax + edi], 2
            //   7408                 | je                  0xa
            //   8b9fe0000000         | mov                 ebx, dword ptr [edi + 0xe0]

        $sequence_3 = { 83e802 0f84bf000000 83e801 0f848c000000 83e801 0f8489000000 8d442420 }
            // n = 7, score = 100
            //   83e802               | sub                 eax, 2
            //   0f84bf000000         | je                  0xc5
            //   83e801               | sub                 eax, 1
            //   0f848c000000         | je                  0x92
            //   83e801               | sub                 eax, 1
            //   0f8489000000         | je                  0x8f
            //   8d442420             | lea                 eax, [esp + 0x20]

        $sequence_4 = { 50 8b842488000000 ff348594a18d00 8d8424ac000000 ffb42488000000 ff32 51 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b842488000000       | mov                 eax, dword ptr [esp + 0x88]
            //   ff348594a18d00       | push                dword ptr [eax*4 + 0x8da194]
            //   8d8424ac000000       | lea                 eax, [esp + 0xac]
            //   ffb42488000000       | push                dword ptr [esp + 0x88]
            //   ff32                 | push                dword ptr [edx]
            //   51                   | push                ecx

        $sequence_5 = { 56 57 8bbc2450010000 8bd8 c1e304 be10020000 03df }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bbc2450010000       | mov                 edi, dword ptr [esp + 0x150]
            //   8bd8                 | mov                 ebx, eax
            //   c1e304               | shl                 ebx, 4
            //   be10020000           | mov                 esi, 0x210
            //   03df                 | add                 ebx, edi

        $sequence_6 = { 8b4c2424 8b4924 894c242c 85c9 743e 8b29 837d2402 }
            // n = 7, score = 100
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   8b4924               | mov                 ecx, dword ptr [ecx + 0x24]
            //   894c242c             | mov                 dword ptr [esp + 0x2c], ecx
            //   85c9                 | test                ecx, ecx
            //   743e                 | je                  0x40
            //   8b29                 | mov                 ebp, dword ptr [ecx]
            //   837d2402             | cmp                 dword ptr [ebp + 0x24], 2

        $sequence_7 = { e8???????? 50 57 53 56 e8???????? 83c418 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   57                   | push                edi
            //   53                   | push                ebx
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_8 = { 8b3b bd00000100 896c2420 80bf4d01000000 7410 8387480100000a bdf4ff0000 }
            // n = 7, score = 100
            //   8b3b                 | mov                 edi, dword ptr [ebx]
            //   bd00000100           | mov                 ebp, 0x10000
            //   896c2420             | mov                 dword ptr [esp + 0x20], ebp
            //   80bf4d01000000       | cmp                 byte ptr [edi + 0x14d], 0
            //   7410                 | je                  0x12
            //   8387480100000a       | add                 dword ptr [edi + 0x148], 0xa
            //   bdf4ff0000           | mov                 ebp, 0xfff4

        $sequence_9 = { 0f45c8 8d4530 2bc8 83f916 7349 8b55dc c645f301 }
            // n = 7, score = 100
            //   0f45c8               | cmovne              ecx, eax
            //   8d4530               | lea                 eax, [ebp + 0x30]
            //   2bc8                 | sub                 ecx, eax
            //   83f916               | cmp                 ecx, 0x16
            //   7349                 | jae                 0x4b
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   c645f301             | mov                 byte ptr [ebp - 0xd], 1

    condition:
        7 of them and filesize < 1785856
}
