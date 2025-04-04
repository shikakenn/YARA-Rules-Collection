rule win_soundbite_auto {

    meta:
        id = "72QVPNeoRKcHhZkuv9POVJ"
        fingerprint = "v1_sha256_d07ea48c839908887a0a5f9ab78be91fc08852ce51b809ff0c620d5b56719109"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.soundbite."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.soundbite"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { bb???????? e8???????? e8???????? 68???????? ff15???????? 33c0 50 }
            // n = 7, score = 100
            //   bb????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   50                   | push                eax

        $sequence_1 = { 8d45f4 64a300000000 c745fc00000000 8b4518 }
            // n = 4, score = 100
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]

        $sequence_2 = { 8b5714 895614 8b5718 895618 8b571c 89561c 8b5720 }
            // n = 7, score = 100
            //   8b5714               | mov                 edx, dword ptr [edi + 0x14]
            //   895614               | mov                 dword ptr [esi + 0x14], edx
            //   8b5718               | mov                 edx, dword ptr [edi + 0x18]
            //   895618               | mov                 dword ptr [esi + 0x18], edx
            //   8b571c               | mov                 edx, dword ptr [edi + 0x1c]
            //   89561c               | mov                 dword ptr [esi + 0x1c], edx
            //   8b5720               | mov                 edx, dword ptr [edi + 0x20]

        $sequence_3 = { 8b4510 3bf3 7457 57 }
            // n = 4, score = 100
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   3bf3                 | cmp                 esi, ebx
            //   7457                 | je                  0x59
            //   57                   | push                edi

        $sequence_4 = { 6683bc8e7e0a000000 7533 0fb690614f4200 6683bc967e0a000000 7530 83e804 83f803 }
            // n = 7, score = 100
            //   6683bc8e7e0a000000     | cmp    word ptr [esi + ecx*4 + 0xa7e], 0
            //   7533                 | jne                 0x35
            //   0fb690614f4200       | movzx               edx, byte ptr [eax + 0x424f61]
            //   6683bc967e0a000000     | cmp    word ptr [esi + edx*4 + 0xa7e], 0
            //   7530                 | jne                 0x32
            //   83e804               | sub                 eax, 4
            //   83f803               | cmp                 eax, 3

        $sequence_5 = { c645fc0a 8bbdf8fcffff 3bcb 0f83c9000000 8bd6 3bfa }
            // n = 6, score = 100
            //   c645fc0a             | mov                 byte ptr [ebp - 4], 0xa
            //   8bbdf8fcffff         | mov                 edi, dword ptr [ebp - 0x308]
            //   3bcb                 | cmp                 ecx, ebx
            //   0f83c9000000         | jae                 0xcf
            //   8bd6                 | mov                 edx, esi
            //   3bfa                 | cmp                 edi, edx

        $sequence_6 = { 3bc1 0f87200a0000 ff2485f1ad4100 33c0 838de8fdffffff 89858cfdffff 8985a4fdffff }
            // n = 7, score = 100
            //   3bc1                 | cmp                 eax, ecx
            //   0f87200a0000         | ja                  0xa26
            //   ff2485f1ad4100       | jmp                 dword ptr [eax*4 + 0x41adf1]
            //   33c0                 | xor                 eax, eax
            //   838de8fdffffff       | or                  dword ptr [ebp - 0x218], 0xffffffff
            //   89858cfdffff         | mov                 dword ptr [ebp - 0x274], eax
            //   8985a4fdffff         | mov                 dword ptr [ebp - 0x25c], eax

        $sequence_7 = { 899d04ffffff c685f4feffff00 8d5001 8d642400 }
            // n = 4, score = 100
            //   899d04ffffff         | mov                 dword ptr [ebp - 0xfc], ebx
            //   c685f4feffff00       | mov                 byte ptr [ebp - 0x10c], 0
            //   8d5001               | lea                 edx, [eax + 1]
            //   8d642400             | lea                 esp, [esp]

        $sequence_8 = { 8d1491 8b0c02 03c8 8b75e0 8b55f4 890c16 85c9 }
            // n = 7, score = 100
            //   8d1491               | lea                 edx, [ecx + edx*4]
            //   8b0c02               | mov                 ecx, dword ptr [edx + eax]
            //   03c8                 | add                 ecx, eax
            //   8b75e0               | mov                 esi, dword ptr [ebp - 0x20]
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   890c16               | mov                 dword ptr [esi + edx], ecx
            //   85c9                 | test                ecx, ecx

        $sequence_9 = { e9???????? b830750000 85db 7e09 57 e8???????? 83c404 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   b830750000           | mov                 eax, 0x7530
            //   85db                 | test                ebx, ebx
            //   7e09                 | jle                 0xb
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

    condition:
        7 of them and filesize < 409600
}
