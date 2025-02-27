rule win_action_rat_auto {

    meta:
        id = "1CcY3wVmKVGxZb9gno2BMB"
        fingerprint = "v1_sha256_804b12281cf1f625ad4f62982be2e6f06ae13a4b27a9fb038471c045c4dd26b6"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.action_rat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.action_rat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 33c5 8945f0 50 8d45f4 64a300000000 894de8 c745e400000000 }
            // n = 7, score = 100
            //   33c5                 | xor                 eax, ebp
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0

        $sequence_1 = { 85c9 7533 8b5508 83c210 52 e8???????? 83c404 }
            // n = 7, score = 100
            //   85c9                 | test                ecx, ecx
            //   7533                 | jne                 0x35
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   83c210               | add                 edx, 0x10
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_2 = { 85c9 740d 68???????? 8d4dd4 e8???????? 8d4dec e8???????? }
            // n = 7, score = 100
            //   85c9                 | test                ecx, ecx
            //   740d                 | je                  0xf
            //   68????????           |                     
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   e8????????           |                     
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   e8????????           |                     

        $sequence_3 = { 50 8b8d84fbffff 51 8d8d64fcffff e8???????? 50 8b958cfbffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b8d84fbffff         | mov                 ecx, dword ptr [ebp - 0x47c]
            //   51                   | push                ecx
            //   8d8d64fcffff         | lea                 ecx, [ebp - 0x39c]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8b958cfbffff         | mov                 edx, dword ptr [ebp - 0x474]

        $sequence_4 = { 8bec 83ec08 894dfc 8b45fc 8b08 e8???????? }
            // n = 6, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec08               | sub                 esp, 8
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   e8????????           |                     

        $sequence_5 = { 43 0010 b543 0010 0007 07 }
            // n = 6, score = 100
            //   43                   | inc                 ebx
            //   0010                 | add                 byte ptr [eax], dl
            //   b543                 | mov                 ch, 0x43
            //   0010                 | add                 byte ptr [eax], dl
            //   0007                 | add                 byte ptr [edi], al
            //   07                   | pop                 es

        $sequence_6 = { c645fc03 83ec28 8bf4 896580 8d4de4 51 e8???????? }
            // n = 7, score = 100
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   83ec28               | sub                 esp, 0x28
            //   8bf4                 | mov                 esi, esp
            //   896580               | mov                 dword ptr [ebp - 0x80], esp
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_7 = { 8a08 884dff 8b5508 8a02 8845fe 0fb64dff }
            // n = 6, score = 100
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   884dff               | mov                 byte ptr [ebp - 1], cl
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8a02                 | mov                 al, byte ptr [edx]
            //   8845fe               | mov                 byte ptr [ebp - 2], al
            //   0fb64dff             | movzx               ecx, byte ptr [ebp - 1]

        $sequence_8 = { 52 8b4dfc 83c134 e8???????? 8b4508 83c03c 50 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c134               | add                 ecx, 0x34
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c03c               | add                 eax, 0x3c
            //   50                   | push                eax

        $sequence_9 = { 8d8d4cffffff e8???????? 8d4dc0 e8???????? 50 8d4dc0 e8???????? }
            // n = 7, score = 100
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 480256
}
