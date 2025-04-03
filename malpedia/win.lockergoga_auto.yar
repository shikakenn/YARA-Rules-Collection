rule win_lockergoga_auto {

    meta:
        id = "7em3qaaZcXqeNLrOoMdwlP"
        fingerprint = "v1_sha256_c582e783be4f8c1eccf17c3665e883eb649b80d6c64ac8df726791d94d7fb2de"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.lockergoga."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lockergoga"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? e9???????? c16d0c1f 8bc1 99 8bc8 c745d40f000000 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   e9????????           |                     
            //   c16d0c1f             | shr                 dword ptr [ebp + 0xc], 0x1f
            //   8bc1                 | mov                 eax, ecx
            //   99                   | cdq                 
            //   8bc8                 | mov                 ecx, eax
            //   c745d40f000000       | mov                 dword ptr [ebp - 0x2c], 0xf

        $sequence_1 = { 6a01 895dec e8???????? 8d4b08 c703???????? c6411900 c74120ffffffff }
            // n = 7, score = 400
            //   6a01                 | push                1
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   e8????????           |                     
            //   8d4b08               | lea                 ecx, [ebx + 8]
            //   c703????????         |                     
            //   c6411900             | mov                 byte ptr [ecx + 0x19], 0
            //   c74120ffffffff       | mov                 dword ptr [ecx + 0x20], 0xffffffff

        $sequence_2 = { e8???????? 8be5 5d c20c00 ffb51cffffff 8bcf e8???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   ffb51cffffff         | push                dword ptr [ebp - 0xe4]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     

        $sequence_3 = { ff10 8b4e3c 83f910 722c 8b4628 41 81f900100000 }
            // n = 7, score = 400
            //   ff10                 | call                dword ptr [eax]
            //   8b4e3c               | mov                 ecx, dword ptr [esi + 0x3c]
            //   83f910               | cmp                 ecx, 0x10
            //   722c                 | jb                  0x2e
            //   8b4628               | mov                 eax, dword ptr [esi + 0x28]
            //   41                   | inc                 ecx
            //   81f900100000         | cmp                 ecx, 0x1000

        $sequence_4 = { 8d45f4 64a300000000 8bf1 8b06 ff90a4000000 85c0 7423 }
            // n = 7, score = 400
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bf1                 | mov                 esi, ecx
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   ff90a4000000         | call                dword ptr [eax + 0xa4]
            //   85c0                 | test                eax, eax
            //   7423                 | je                  0x25

        $sequence_5 = { f7ea 035584 c1fa05 8bc2 c1e81f 03c2 7458 }
            // n = 7, score = 400
            //   f7ea                 | imul                edx
            //   035584               | add                 edx, dword ptr [ebp - 0x7c]
            //   c1fa05               | sar                 edx, 5
            //   8bc2                 | mov                 eax, edx
            //   c1e81f               | shr                 eax, 0x1f
            //   03c2                 | add                 eax, edx
            //   7458                 | je                  0x5a

        $sequence_6 = { eb0f 57 8d4dc8 e8???????? 8b45cc 8945f0 807d0700 }
            // n = 7, score = 400
            //   eb0f                 | jmp                 0x11
            //   57                   | push                edi
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   e8????????           |                     
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   807d0700             | cmp                 byte ptr [ebp + 7], 0

        $sequence_7 = { 8b4830 85c9 7409 8b11 83c028 50 ff521c }
            // n = 7, score = 400
            //   8b4830               | mov                 ecx, dword ptr [eax + 0x30]
            //   85c9                 | test                ecx, ecx
            //   7409                 | je                  0xb
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   83c028               | add                 eax, 0x28
            //   50                   | push                eax
            //   ff521c               | call                dword ptr [edx + 0x1c]

        $sequence_8 = { e8???????? 807e1000 7562 8b4e04 8bc7 8a10 3a11 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   807e1000             | cmp                 byte ptr [esi + 0x10], 0
            //   7562                 | jne                 0x64
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   8bc7                 | mov                 eax, edi
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   3a11                 | cmp                 dl, byte ptr [ecx]

        $sequence_9 = { e8???????? 8d4dbc e8???????? 8d8d2cffffff e8???????? 8b4df4 64890d00000000 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]
            //   e8????????           |                     
            //   8d8d2cffffff         | lea                 ecx, [ebp - 0xd4]
            //   e8????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

    condition:
        7 of them and filesize < 2588672
}
