rule win_expiro_auto {

    meta:
        id = "3Tk6jxpvfFB4Eec3bt4wEg"
        fingerprint = "v1_sha256_9d4a4b6071f8efe24f30549b3b2d217f52995878f6039fe924a8169a6f93625b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.expiro."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.expiro"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b550c 8b349a b9???????? 8bc6 8da42400000000 668b10 663b11 }
            // n = 7, score = 100
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   8b349a               | mov                 esi, dword ptr [edx + ebx*4]
            //   b9????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   8da42400000000       | lea                 esp, [esp]
            //   668b10               | mov                 dx, word ptr [eax]
            //   663b11               | cmp                 dx, word ptr [ecx]

        $sequence_1 = { 83c404 803d????????00 0f8543010000 68???????? e8???????? 83c404 8d8424e4020000 }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   803d????????00       |                     
            //   0f8543010000         | jne                 0x149
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d8424e4020000       | lea                 eax, [esp + 0x2e4]

        $sequence_2 = { 8d442414 50 56 33c0 897c241c }
            // n = 5, score = 100
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   50                   | push                eax
            //   56                   | push                esi
            //   33c0                 | xor                 eax, eax
            //   897c241c             | mov                 dword ptr [esp + 0x1c], edi

        $sequence_3 = { c78424d400000007000000 899c24d0000000 e8???????? 6a08 b8???????? 8d8c24c0000000 }
            // n = 6, score = 100
            //   c78424d400000007000000     | mov    dword ptr [esp + 0xd4], 7
            //   899c24d0000000       | mov                 dword ptr [esp + 0xd0], ebx
            //   e8????????           |                     
            //   6a08                 | push                8
            //   b8????????           |                     
            //   8d8c24c0000000       | lea                 ecx, [esp + 0xc0]

        $sequence_4 = { 837e1408 722a 8b06 eb28 85ed 75f2 896e10 }
            // n = 7, score = 100
            //   837e1408             | cmp                 dword ptr [esi + 0x14], 8
            //   722a                 | jb                  0x2c
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   eb28                 | jmp                 0x2a
            //   85ed                 | test                ebp, ebp
            //   75f2                 | jne                 0xfffffff4
            //   896e10               | mov                 dword ptr [esi + 0x10], ebp

        $sequence_5 = { 52 e8???????? 85c0 752b 68???????? eb29 68???????? }
            // n = 7, score = 100
            //   52                   | push                edx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   752b                 | jne                 0x2d
            //   68????????           |                     
            //   eb29                 | jmp                 0x2b
            //   68????????           |                     

        $sequence_6 = { 7407 50 ff15???????? 8ac3 e9???????? 57 ff15???????? }
            // n = 7, score = 100
            //   7407                 | je                  9
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8ac3                 | mov                 al, bl
            //   e9????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_7 = { 75f5 2bc2 d1f8 50 8d442458 8d742420 e8???????? }
            // n = 7, score = 100
            //   75f5                 | jne                 0xfffffff7
            //   2bc2                 | sub                 eax, edx
            //   d1f8                 | sar                 eax, 1
            //   50                   | push                eax
            //   8d442458             | lea                 eax, [esp + 0x58]
            //   8d742420             | lea                 esi, [esp + 0x20]
            //   e8????????           |                     

        $sequence_8 = { c744242c07000000 897c2428 6689542418 8d7102 668b11 83c102 663bd7 }
            // n = 7, score = 100
            //   c744242c07000000     | mov                 dword ptr [esp + 0x2c], 7
            //   897c2428             | mov                 dword ptr [esp + 0x28], edi
            //   6689542418           | mov                 word ptr [esp + 0x18], dx
            //   8d7102               | lea                 esi, [ecx + 2]
            //   668b11               | mov                 dx, word ptr [ecx]
            //   83c102               | add                 ecx, 2
            //   663bd7               | cmp                 dx, di

        $sequence_9 = { 83c404 33c0 668944244c 6a04 897c2464 895c2460 e8???????? }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   668944244c           | mov                 word ptr [esp + 0x4c], ax
            //   6a04                 | push                4
            //   897c2464             | mov                 dword ptr [esp + 0x64], edi
            //   895c2460             | mov                 dword ptr [esp + 0x60], ebx
            //   e8????????           |                     

    condition:
        7 of them and filesize < 3776512
}
