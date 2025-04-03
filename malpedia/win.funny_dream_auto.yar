rule win_funny_dream_auto {

    meta:
        id = "6DNuzc8GCeeIPDzt1f7Dly"
        fingerprint = "v1_sha256_cb215be87db33b154ffd783569bce8db609ba8b5cdc9d518db32c5fd6b7cb19c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.funny_dream."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.funny_dream"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff15???????? 2bc6 8d9560feffff 50 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   2bc6                 | sub                 eax, esi
            //   8d9560feffff         | lea                 edx, [ebp - 0x1a0]
            //   50                   | push                eax

        $sequence_1 = { c745fc00000000 8d4f04 c74704???????? e8???????? }
            // n = 4, score = 300
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8d4f04               | lea                 ecx, [edi + 4]
            //   c74704????????       |                     
            //   e8????????           |                     

        $sequence_2 = { 8b1d???????? 7457 ffd3 3d33270000 754e }
            // n = 5, score = 300
            //   8b1d????????         |                     
            //   7457                 | je                  0x59
            //   ffd3                 | call                ebx
            //   3d33270000           | cmp                 eax, 0x2733
            //   754e                 | jne                 0x50

        $sequence_3 = { 7414 8b3d???????? 8d8d78ffffff 51 50 ffd7 85c0 }
            // n = 7, score = 300
            //   7414                 | je                  0x16
            //   8b3d????????         |                     
            //   8d8d78ffffff         | lea                 ecx, [ebp - 0x88]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax

        $sequence_4 = { ff15???????? 85c0 0f8ee5000000 6a00 b80d000000 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8ee5000000         | jle                 0xeb
            //   6a00                 | push                0
            //   b80d000000           | mov                 eax, 0xd

        $sequence_5 = { 89855affffff 6689855effffff 8d8550ffffff 50 660fd68552ffffff ff15???????? }
            // n = 6, score = 300
            //   89855affffff         | mov                 dword ptr [ebp - 0xa6], eax
            //   6689855effffff       | mov                 word ptr [ebp - 0xa2], ax
            //   8d8550ffffff         | lea                 eax, [ebp - 0xb0]
            //   50                   | push                eax
            //   660fd68552ffffff     | movq                qword ptr [ebp - 0xae], xmm0
            //   ff15????????         |                     

        $sequence_6 = { e8???????? 8b742414 83c408 85c0 748d 68???????? 50 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   748d                 | je                  0xffffff8f
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_7 = { 03d8 8d5101 0f1f440000 8a01 41 84c0 }
            // n = 6, score = 300
            //   03d8                 | add                 ebx, eax
            //   8d5101               | lea                 edx, [ecx + 1]
            //   0f1f440000           | nop                 dword ptr [eax + eax]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al

        $sequence_8 = { 8b9de8f7ffff 8b85fcfbffff 84c0 7514 80fc5a 0fb6db b901000000 }
            // n = 7, score = 300
            //   8b9de8f7ffff         | mov                 ebx, dword ptr [ebp - 0x818]
            //   8b85fcfbffff         | mov                 eax, dword ptr [ebp - 0x404]
            //   84c0                 | test                al, al
            //   7514                 | jne                 0x16
            //   80fc5a               | cmp                 ah, 0x5a
            //   0fb6db               | movzx               ebx, bl
            //   b901000000           | mov                 ecx, 1

        $sequence_9 = { 8b85c4fdffff 89441f05 8b85b8fdffff 89441f09 8b85bcfdffff 89441f0d 83c711 }
            // n = 7, score = 300
            //   8b85c4fdffff         | mov                 eax, dword ptr [ebp - 0x23c]
            //   89441f05             | mov                 dword ptr [edi + ebx + 5], eax
            //   8b85b8fdffff         | mov                 eax, dword ptr [ebp - 0x248]
            //   89441f09             | mov                 dword ptr [edi + ebx + 9], eax
            //   8b85bcfdffff         | mov                 eax, dword ptr [ebp - 0x244]
            //   89441f0d             | mov                 dword ptr [edi + ebx + 0xd], eax
            //   83c711               | add                 edi, 0x11

    condition:
        7 of them and filesize < 393216
}
