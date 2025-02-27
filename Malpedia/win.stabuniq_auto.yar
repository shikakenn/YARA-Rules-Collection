rule win_stabuniq_auto {

    meta:
        id = "diBJ4MARqelt95NwEpDQI"
        fingerprint = "v1_sha256_8abe8b1e5433d79ecca06d79534ec6148ee9460e9d28a8041508dc1cd6d954c1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.stabuniq."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stabuniq"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b4510 8a4de0 8808 8b5510 83c201 }
            // n = 5, score = 100
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8a4de0               | mov                 cl, byte ptr [ebp - 0x20]
            //   8808                 | mov                 byte ptr [eax], cl
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   83c201               | add                 edx, 1

        $sequence_1 = { 8d95e4fcffff 52 8b4510 ff5030 6804010000 6a00 8d8dfcfeffff }
            // n = 7, score = 100
            //   8d95e4fcffff         | lea                 edx, [ebp - 0x31c]
            //   52                   | push                edx
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   ff5030               | call                dword ptr [eax + 0x30]
            //   6804010000           | push                0x104
            //   6a00                 | push                0
            //   8d8dfcfeffff         | lea                 ecx, [ebp - 0x104]

        $sequence_2 = { 8b4510 50 8b4d08 ff5124 8945f4 6aff }
            // n = 6, score = 100
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   ff5124               | call                dword ptr [ecx + 0x24]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   6aff                 | push                -1

        $sequence_3 = { ff92bc000000 6a00 6a00 6a25 8d85c0feffff 50 8b4d14 }
            // n = 7, score = 100
            //   ff92bc000000         | call                dword ptr [edx + 0xbc]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a25                 | push                0x25
            //   8d85c0feffff         | lea                 eax, [ebp - 0x140]
            //   50                   | push                eax
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]

        $sequence_4 = { 6a00 6a00 6a25 8d85c0feffff 50 8b4d14 81c1e8110000 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a25                 | push                0x25
            //   8d85c0feffff         | lea                 eax, [ebp - 0x140]
            //   50                   | push                eax
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   81c1e8110000         | add                 ecx, 0x11e8

        $sequence_5 = { 69d2ff000000 8b4508 8d8c101f090000 51 8d95f8feffff }
            // n = 5, score = 100
            //   69d2ff000000         | imul                edx, edx, 0xff
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8d8c101f090000       | lea                 ecx, [eax + edx + 0x91f]
            //   51                   | push                ecx
            //   8d95f8feffff         | lea                 edx, [ebp - 0x108]

        $sequence_6 = { 8d8dc0fcffff 51 e8???????? 8b5508 83c220 895508 68ff000000 }
            // n = 7, score = 100
            //   8d8dc0fcffff         | lea                 ecx, [ebp - 0x340]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   83c220               | add                 edx, 0x20
            //   895508               | mov                 dword ptr [ebp + 8], edx
            //   68ff000000           | push                0xff

        $sequence_7 = { 8b8d24fdffff 51 8b5510 ff520c 6a40 }
            // n = 5, score = 100
            //   8b8d24fdffff         | mov                 ecx, dword ptr [ebp - 0x2dc]
            //   51                   | push                ecx
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   ff520c               | call                dword ptr [edx + 0xc]
            //   6a40                 | push                0x40

        $sequence_8 = { 8b88f0010000 51 8b5510 ff92b8000000 }
            // n = 4, score = 100
            //   8b88f0010000         | mov                 ecx, dword ptr [eax + 0x1f0]
            //   51                   | push                ecx
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   ff92b8000000         | call                dword ptr [edx + 0xb8]

        $sequence_9 = { ff9098010000 8b4d20 83790800 7513 8b5520 }
            // n = 5, score = 100
            //   ff9098010000         | call                dword ptr [eax + 0x198]
            //   8b4d20               | mov                 ecx, dword ptr [ebp + 0x20]
            //   83790800             | cmp                 dword ptr [ecx + 8], 0
            //   7513                 | jne                 0x15
            //   8b5520               | mov                 edx, dword ptr [ebp + 0x20]

    condition:
        7 of them and filesize < 57344
}
