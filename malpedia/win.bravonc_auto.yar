rule win_bravonc_auto {

    meta:
        id = "3vIQEFFvoBfEvHlQwOAhnA"
        fingerprint = "v1_sha256_c173b555e387356384c480cbe1258c67f0fa737efd2cf0efcccd2c272e1e677f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.bravonc."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bravonc"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { a1???????? 6a06 68???????? 50 ffd6 83c40c 85c0 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   6a06                 | push                6
            //   68????????           |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax

        $sequence_1 = { 034a24 034dfc 8d8401d6c162ca 8945fc }
            // n = 4, score = 100
            //   034a24               | add                 ecx, dword ptr [edx + 0x24]
            //   034dfc               | add                 ecx, dword ptr [ebp - 4]
            //   8d8401d6c162ca       | lea                 eax, [ecx + eax - 0x359d3e2a]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_2 = { 56 8d85fcfeffff 56 50 ff750c 56 e8???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   56                   | push                esi
            //   50                   | push                eax
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_3 = { 8d45c8 68???????? 50 8d85e4feffff 50 e8???????? 83c40c }
            // n = 7, score = 100
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   68????????           |                     
            //   50                   | push                eax
            //   8d85e4feffff         | lea                 eax, [ebp - 0x11c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_4 = { 59 33c0 8d7db0 895dac c645fc01 895df0 }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   8d7db0               | lea                 edi, [ebp - 0x50]
            //   895dac               | mov                 dword ptr [ebp - 0x54], ebx
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx

        $sequence_5 = { 8bf1 57 8b7d0c 8b460c 8d0c38 3b4e08 }
            // n = 6, score = 100
            //   8bf1                 | mov                 esi, ecx
            //   57                   | push                edi
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   8d0c38               | lea                 ecx, [eax + edi]
            //   3b4e08               | cmp                 ecx, dword ptr [esi + 8]

        $sequence_6 = { 66897004 5f 5e 668908 66895006 5b c9 }
            // n = 7, score = 100
            //   66897004             | mov                 word ptr [eax + 4], si
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   668908               | mov                 word ptr [eax], cx
            //   66895006             | mov                 word ptr [eax + 6], dx
            //   5b                   | pop                 ebx
            //   c9                   | leave               

        $sequence_7 = { ff15???????? 59 3bc3 59 7404 802000 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   3bc3                 | cmp                 eax, ebx
            //   59                   | pop                 ecx
            //   7404                 | je                  6
            //   802000               | and                 byte ptr [eax], 0

        $sequence_8 = { 51 b85c120000 e8???????? 53 56 57 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   b85c120000           | mov                 eax, 0x125c
            //   e8????????           |                     
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_9 = { 59 8d7db0 6a10 c745ac44000000 59 895df0 f3ab }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   8d7db0               | lea                 edi, [ebp - 0x50]
            //   6a10                 | push                0x10
            //   c745ac44000000       | mov                 dword ptr [ebp - 0x54], 0x44
            //   59                   | pop                 ecx
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

    condition:
        7 of them and filesize < 131072
}
