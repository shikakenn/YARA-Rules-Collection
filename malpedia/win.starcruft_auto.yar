rule win_starcruft_auto {

    meta:
        id = "vMHGXHCaANz8OgOgJBPAY"
        fingerprint = "v1_sha256_8a7d60fd25a814377ba2a7789857a75b6ee211239e9e01336654dc519259df0c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.starcruft."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.starcruft"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0fb6423d c1e008 0bc8 8b550c 0fb6423e c1e010 0bc8 }
            // n = 7, score = 100
            //   0fb6423d             | movzx               eax, byte ptr [edx + 0x3d]
            //   c1e008               | shl                 eax, 8
            //   0bc8                 | or                  ecx, eax
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   0fb6423e             | movzx               eax, byte ptr [edx + 0x3e]
            //   c1e010               | shl                 eax, 0x10
            //   0bc8                 | or                  ecx, eax

        $sequence_1 = { c785e4feffff01000000 c785e8feffff00000000 c785e0feffff00000000 a1???????? 50 ff15???????? }
            // n = 6, score = 100
            //   c785e4feffff01000000     | mov    dword ptr [ebp - 0x11c], 1
            //   c785e8feffff00000000     | mov    dword ptr [ebp - 0x118], 0
            //   c785e0feffff00000000     | mov    dword ptr [ebp - 0x120], 0
            //   a1????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_2 = { c68541fbffffec c68542fbffff90 c68543fbffff47 8d8d48fbffff 51 }
            // n = 5, score = 100
            //   c68541fbffffec       | mov                 byte ptr [ebp - 0x4bf], 0xec
            //   c68542fbffff90       | mov                 byte ptr [ebp - 0x4be], 0x90
            //   c68543fbffff47       | mov                 byte ptr [ebp - 0x4bd], 0x47
            //   8d8d48fbffff         | lea                 ecx, [ebp - 0x4b8]
            //   51                   | push                ecx

        $sequence_3 = { 0bd1 8b450c 0fb64837 c1e118 0bd1 8955e4 8b550c }
            // n = 7, score = 100
            //   0bd1                 | or                  edx, ecx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fb64837             | movzx               ecx, byte ptr [eax + 0x37]
            //   c1e118               | shl                 ecx, 0x18
            //   0bd1                 | or                  edx, ecx
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

        $sequence_4 = { 8d8d30fdffff 51 ff15???????? c745f400000000 c745f000000000 8d55f0 52 }
            // n = 7, score = 100
            //   8d8d30fdffff         | lea                 ecx, [ebp - 0x2d0]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   8d55f0               | lea                 edx, [ebp - 0x10]
            //   52                   | push                edx

        $sequence_5 = { 8975e4 33c0 39b8d8d02e00 0f8491000000 }
            // n = 4, score = 100
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   33c0                 | xor                 eax, eax
            //   39b8d8d02e00         | cmp                 dword ptr [eax + 0x2ed0d8], edi
            //   0f8491000000         | je                  0x97

        $sequence_6 = { ebad 8b85e4feffff c68405f8feffff7c 8b8dbcfeffff 51 8d95c4feffff 52 }
            // n = 7, score = 100
            //   ebad                 | jmp                 0xffffffaf
            //   8b85e4feffff         | mov                 eax, dword ptr [ebp - 0x11c]
            //   c68405f8feffff7c     | mov                 byte ptr [ebp + eax - 0x108], 0x7c
            //   8b8dbcfeffff         | mov                 ecx, dword ptr [ebp - 0x144]
            //   51                   | push                ecx
            //   8d95c4feffff         | lea                 edx, [ebp - 0x13c]
            //   52                   | push                edx

        $sequence_7 = { 8b4510 c70000000000 c705????????00000000 8b4d10 51 8b550c 52 }
            // n = 7, score = 100
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   c705????????00000000     |     
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   51                   | push                ecx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   52                   | push                edx

        $sequence_8 = { 50 e8???????? 83c418 85c0 7516 8b8d04faffff 51 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   85c0                 | test                eax, eax
            //   7516                 | jne                 0x18
            //   8b8d04faffff         | mov                 ecx, dword ptr [ebp - 0x5fc]
            //   51                   | push                ecx

        $sequence_9 = { 52 8b85b4fcffff 50 e8???????? 83c414 }
            // n = 5, score = 100
            //   52                   | push                edx
            //   8b85b4fcffff         | mov                 eax, dword ptr [ebp - 0x34c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14

    condition:
        7 of them and filesize < 294912
}
