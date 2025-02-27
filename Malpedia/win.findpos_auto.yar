rule win_findpos_auto {

    meta:
        id = "21F6MrSS2KZQzxVZlb6KQ3"
        fingerprint = "v1_sha256_16968f111dc679e93555d1d3b7ae27dea3f4769dc763c7bf583a162ef6a1f34f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.findpos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.findpos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 59 8b45f4 03c3 8945f4 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   03c3                 | add                 eax, ebx
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

        $sequence_1 = { 59 8b45f4 03c3 8945f4 2bfb }
            // n = 5, score = 100
            //   59                   | pop                 ecx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   03c3                 | add                 eax, ebx
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   2bfb                 | sub                 edi, ebx

        $sequence_2 = { 8b4514 40 c745ec325a4000 894df8 8945fc 64a100000000 }
            // n = 6, score = 100
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   40                   | inc                 eax
            //   c745ec325a4000       | mov                 dword ptr [ebp - 0x14], 0x405a32
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   64a100000000         | mov                 eax, dword ptr fs:[0]

        $sequence_3 = { 53 8b5d10 56 57 8b3d???????? 6a3c }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b3d????????         |                     
            //   6a3c                 | push                0x3c

        $sequence_4 = { 8d7608 660fd60f 8d7f08 8b048d28544000 ffe0 }
            // n = 5, score = 100
            //   8d7608               | lea                 esi, [esi + 8]
            //   660fd60f             | movq                qword ptr [edi], xmm1
            //   8d7f08               | lea                 edi, [edi + 8]
            //   8b048d28544000       | mov                 eax, dword ptr [ecx*4 + 0x405428]
            //   ffe0                 | jmp                 eax

        $sequence_5 = { 51 8b8de8fbffff 8d95ecfbffff e8???????? 83c40c 85c0 743c }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8b8de8fbffff         | mov                 ecx, dword ptr [ebp - 0x418]
            //   8d95ecfbffff         | lea                 edx, [ebp - 0x414]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   743c                 | je                  0x3e

        $sequence_6 = { 50 50 8d85f8feffff 50 68???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   50                   | push                eax
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_7 = { 8ac6 243f 884dfa 8845fb }
            // n = 4, score = 100
            //   8ac6                 | mov                 al, dh
            //   243f                 | and                 al, 0x3f
            //   884dfa               | mov                 byte ptr [ebp - 6], cl
            //   8845fb               | mov                 byte ptr [ebp - 5], al

        $sequence_8 = { 6803000010 56 ff15???????? 83f8ff 0f8481000000 8b45f8 }
            // n = 6, score = 100
            //   6803000010           | push                0x10000003
            //   56                   | push                esi
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   0f8481000000         | je                  0x87
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_9 = { 85c0 7429 8bbdf4efffff 33f6 c1ef02 85ff 741a }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7429                 | je                  0x2b
            //   8bbdf4efffff         | mov                 edi, dword ptr [ebp - 0x100c]
            //   33f6                 | xor                 esi, esi
            //   c1ef02               | shr                 edi, 2
            //   85ff                 | test                edi, edi
            //   741a                 | je                  0x1c

    condition:
        7 of them and filesize < 286720
}
