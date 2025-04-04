rule win_zupdax_auto {

    meta:
        id = "1aZCl4fg12lrUeF83iHWsN"
        fingerprint = "v1_sha256_c678dda4eb233d445c52eec76463d1638934195de484c67d217556190a9036d4"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.zupdax."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zupdax"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 55 8b6c2408 56 57 33c9 33f6 33ff }
            // n = 7, score = 300
            //   55                   | push                ebp
            //   8b6c2408             | mov                 ebp, dword ptr [esp + 8]
            //   56                   | push                esi
            //   57                   | push                edi
            //   33c9                 | xor                 ecx, ecx
            //   33f6                 | xor                 esi, esi
            //   33ff                 | xor                 edi, edi

        $sequence_1 = { 895e28 895e2c e8???????? 8b460c 83c404 3bc3 }
            // n = 6, score = 300
            //   895e28               | mov                 dword ptr [esi + 0x28], ebx
            //   895e2c               | mov                 dword ptr [esi + 0x2c], ebx
            //   e8????????           |                     
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   83c404               | add                 esp, 4
            //   3bc3                 | cmp                 eax, ebx

        $sequence_2 = { 894714 8b4618 895618 894718 33db 83c61c }
            // n = 6, score = 300
            //   894714               | mov                 dword ptr [edi + 0x14], eax
            //   8b4618               | mov                 eax, dword ptr [esi + 0x18]
            //   895618               | mov                 dword ptr [esi + 0x18], edx
            //   894718               | mov                 dword ptr [edi + 0x18], eax
            //   33db                 | xor                 ebx, ebx
            //   83c61c               | add                 esi, 0x1c

        $sequence_3 = { 895e28 895e2c e8???????? 8b460c }
            // n = 4, score = 300
            //   895e28               | mov                 dword ptr [esi + 0x28], ebx
            //   895e2c               | mov                 dword ptr [esi + 0x2c], ebx
            //   e8????????           |                     
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]

        $sequence_4 = { 895e10 895e14 e8???????? 83c404 5f 5b }
            // n = 6, score = 300
            //   895e10               | mov                 dword ptr [esi + 0x10], ebx
            //   895e14               | mov                 dword ptr [esi + 0x14], ebx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx

        $sequence_5 = { 81e6ff000080 7908 4e 81ce00ffffff 46 8a1c06 881c01 }
            // n = 7, score = 300
            //   81e6ff000080         | and                 esi, 0x800000ff
            //   7908                 | jns                 0xa
            //   4e                   | dec                 esi
            //   81ce00ffffff         | or                  esi, 0xffffff00
            //   46                   | inc                 esi
            //   8a1c06               | mov                 bl, byte ptr [esi + eax]
            //   881c01               | mov                 byte ptr [ecx + eax], bl

        $sequence_6 = { 33c9 33f6 33ff 394c2414 765b }
            // n = 5, score = 300
            //   33c9                 | xor                 ecx, ecx
            //   33f6                 | xor                 esi, esi
            //   33ff                 | xor                 edi, edi
            //   394c2414             | cmp                 dword ptr [esp + 0x14], ecx
            //   765b                 | jbe                 0x5d

        $sequence_7 = { 50 895e24 895e28 895e2c e8???????? 8b460c }
            // n = 6, score = 300
            //   50                   | push                eax
            //   895e24               | mov                 dword ptr [esi + 0x24], ebx
            //   895e28               | mov                 dword ptr [esi + 0x28], ebx
            //   895e2c               | mov                 dword ptr [esi + 0x2c], ebx
            //   e8????????           |                     
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]

        $sequence_8 = { 7419 8b4c2408 8b7e10 51 }
            // n = 4, score = 300
            //   7419                 | je                  0x1b
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   8b7e10               | mov                 edi, dword ptr [esi + 0x10]
            //   51                   | push                ecx

        $sequence_9 = { ff15???????? 8d442444 83c0fe 668b4802 83c002 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   8d442444             | lea                 eax, [esp + 0x44]
            //   83c0fe               | add                 eax, -2
            //   668b4802             | mov                 cx, word ptr [eax + 2]
            //   83c002               | add                 eax, 2

    condition:
        7 of them and filesize < 1032192
}
