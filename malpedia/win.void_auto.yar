rule win_void_auto {

    meta:
        id = "63BBvC5jeEUtxvVyEtrkC3"
        fingerprint = "v1_sha256_9f2df3bf5647831ce19a5214f5a12a4e7816575938889bc15e27938cfd4b8dad"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.void."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.void"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 8d85d8fbffff 50 8d8d7cfbffff e8???????? 8b95ecfbffff c645fc18 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d85d8fbffff         | lea                 eax, [ebp - 0x428]
            //   50                   | push                eax
            //   8d8d7cfbffff         | lea                 ecx, [ebp - 0x484]
            //   e8????????           |                     
            //   8b95ecfbffff         | mov                 edx, dword ptr [ebp - 0x414]
            //   c645fc18             | mov                 byte ptr [ebp - 4], 0x18

        $sequence_1 = { 50 51 ff7310 8d4b04 e8???????? 8b4b0c 8bd0 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ff7310               | push                dword ptr [ebx + 0x10]
            //   8d4b04               | lea                 ecx, [ebx + 4]
            //   e8????????           |                     
            //   8b4b0c               | mov                 ecx, dword ptr [ebx + 0xc]
            //   8bd0                 | mov                 edx, eax

        $sequence_2 = { 50 e8???????? 8b4508 83c028 8b4df4 64890d00000000 59 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c028               | add                 eax, 0x28
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx

        $sequence_3 = { 83f810 0f85a1000000 8d8544ffffff 50 8d4d94 e8???????? 53 }
            // n = 7, score = 200
            //   83f810               | cmp                 eax, 0x10
            //   0f85a1000000         | jne                 0xa7
            //   8d8544ffffff         | lea                 eax, [ebp - 0xbc]
            //   50                   | push                eax
            //   8d4d94               | lea                 ecx, [ebp - 0x6c]
            //   e8????????           |                     
            //   53                   | push                ebx

        $sequence_4 = { 56 e8???????? 8a4da0 ff759c 0fb6c1 66c1e108 660bc8 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   8a4da0               | mov                 cl, byte ptr [ebp - 0x60]
            //   ff759c               | push                dword ptr [ebp - 0x64]
            //   0fb6c1               | movzx               eax, cl
            //   66c1e108             | shl                 cx, 8
            //   660bc8               | or                  cx, ax

        $sequence_5 = { 56 e8???????? 83c410 ff742420 53 56 e8???????? }
            // n = 7, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   53                   | push                ebx
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_6 = { 33880c040000 338f0c030000 339808040000 338e0c020000 338a0c010000 339f08030000 339e08020000 }
            // n = 7, score = 200
            //   33880c040000         | xor                 ecx, dword ptr [eax + 0x40c]
            //   338f0c030000         | xor                 ecx, dword ptr [edi + 0x30c]
            //   339808040000         | xor                 ebx, dword ptr [eax + 0x408]
            //   338e0c020000         | xor                 ecx, dword ptr [esi + 0x20c]
            //   338a0c010000         | xor                 ecx, dword ptr [edx + 0x10c]
            //   339f08030000         | xor                 ebx, dword ptr [edi + 0x308]
            //   339e08020000         | xor                 ebx, dword ptr [esi + 0x208]

        $sequence_7 = { 50 8d4dc4 e8???????? 8d45dc c645fc01 50 8d4e3c }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d4dc4               | lea                 ecx, [ebp - 0x3c]
            //   e8????????           |                     
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   50                   | push                eax
            //   8d4e3c               | lea                 ecx, [esi + 0x3c]

    condition:
        7 of them and filesize < 2744320
}
