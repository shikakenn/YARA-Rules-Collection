rule win_dustpan_auto {

    meta:
        id = "7iZnJ4rbnb7IAYRJBhhno4"
        fingerprint = "v1_sha256_5224f428476ca9b9e044abefc44ce9a53e06974708bc3448eb44f67994867ab4"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.dustpan."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dustpan"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 4533c0 4c891d???????? e8???????? 488d0d32010000 4883c420 5b e9???????? }
            // n = 7, score = 100
            //   4533c0               | imul                ebx, ebx, 0x58
            //   4c891d????????       |                     
            //   e8????????           |                     
            //   488d0d32010000       | inc                 edx
            //   4883c420             | mov                 byte ptr [ecx + ebx + 8], 0
            //   5b                   | dec                 eax
            //   e9????????           |                     

        $sequence_1 = { b9ff000000 e8???????? 488bfb 4803ff 4c8d2d45eb0000 }
            // n = 5, score = 100
            //   b9ff000000           | mov                 word ptr [esp + 0x38], ax
            //   e8????????           |                     
            //   488bfb               | movzx               eax, word ptr [esp + ecx*2 + 0x1e]
            //   4803ff               | dec                 eax
            //   4c8d2d45eb0000       | dec                 ecx

        $sequence_2 = { 488d0d19a80100 33d2 c744242800000008 895c2420 ffd0 488b4d00 4833cc }
            // n = 7, score = 100
            //   488d0d19a80100       | dec                 eax
            //   33d2                 | lea                 ebx, [0xec10]
            //   c744242800000008     | mov                 esi, edi
            //   895c2420             | dec                 eax
            //   ffd0                 | mov                 ebp, dword ptr [ebx]
            //   488b4d00             | dec                 eax
            //   4833cc               | test                ebp, ebp

        $sequence_3 = { 4c8be7 4c8bf7 49c1fe05 4c8d3dffb60000 }
            // n = 4, score = 100
            //   4c8be7               | mov                 dword ptr [ecx + 0x10c], esi
            //   4c8bf7               | dec                 eax
            //   49c1fe05             | mov                 dword ptr [ecx + 0x150], eax
            //   4c8d3dffb60000       | xor                 eax, eax

        $sequence_4 = { 488d05fb0a0100 eb04 4883c014 8918 e8???????? 4c8d15e30a0100 4885c0 }
            // n = 7, score = 100
            //   488d05fb0a0100       | add                 ebp, 0x18
            //   eb04                 | mov                 edx, ebx
            //   4883c014             | mov                 esi, 1
            //   8918                 | dec                 eax
            //   e8????????           |                     
            //   4c8d15e30a0100       | and                 dword ptr [ebx + 8], 0
            //   4885c0               | dec                 eax

        $sequence_5 = { 7440 66448923 8a45d8 4b8b8cf8e0d00100 88443109 8a45d9 }
            // n = 6, score = 100
            //   7440                 | mov                 esp, eax
            //   66448923             | test                eax, eax
            //   8a45d8               | je                  0xb89
            //   4b8b8cf8e0d00100     | dec                 eax
            //   88443109             | mov                 ecx, dword ptr [esp + 0x50]
            //   8a45d9               | dec                 eax

        $sequence_6 = { e9???????? 488d0d45010000 e9???????? 4883ec28 488d0d12910000 e8???????? 488d0d39010000 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   488d0d45010000       | dec                 eax
            //   e9????????           |                     
            //   4883ec28             | mov                 esi, ebx
            //   488d0d12910000       | dec                 eax
            //   e8????????           |                     
            //   488d0d39010000       | sar                 esi, 5

        $sequence_7 = { 488bca 48c1f905 4c8d0533760100 83e21f }
            // n = 4, score = 100
            //   488bca               | dec                 eax
            //   48c1f905             | sub                 esp, 0x20
            //   4c8d0533760100       | dec                 eax
            //   83e21f               | mov                 ebx, ecx

        $sequence_8 = { 4889442420 e8???????? 488d8380000000 803800 741d 4c8d0df2bc0000 41b802000000 }
            // n = 7, score = 100
            //   4889442420           | cmp                 ch, 2
            //   e8????????           |                     
            //   488d8380000000       | dec                 esp
            //   803800               | lea                 eax, [0x17561]
            //   741d                 | dec                 esp
            //   4c8d0df2bc0000       | arpl                ax, bx
            //   41b802000000         | inc                 ecx

        $sequence_9 = { 894704 e9???????? 488d0d351f0100 48394c2458 7427 }
            // n = 5, score = 100
            //   894704               | je                  0xc1b
            //   e9????????           |                     
            //   488d0d351f0100       | dec                 eax
            //   48394c2458           | lea                 edx, [0xa10b]
            //   7427                 | dec                 eax

    condition:
        7 of them and filesize < 282624
}
