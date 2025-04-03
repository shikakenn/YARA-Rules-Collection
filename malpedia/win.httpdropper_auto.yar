rule win_httpdropper_auto {

    meta:
        id = "5drGTI3dMcgWO3F40nNZQS"
        fingerprint = "v1_sha256_1f304e411e6e19a3397e572e7a13609bae133af12f0a3672cddde2eef3a5cdf3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.httpdropper."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.httpdropper"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 51 ff15???????? 85c0 0f85b9000000 68ff030000 }
            // n = 5, score = 200
            //   51                   | not                 ecx
            //   ff15????????         |                     
            //   85c0                 | dec                 eax
            //   0f85b9000000         | lea                 edi, [ecx - 1]
            //   68ff030000           | dec                 eax

        $sequence_1 = { b803010000 899580f0ffff 8b95c0f0ffff 898568f0ffff 898584f0ffff }
            // n = 5, score = 200
            //   b803010000           | inc                 esp
            //   899580f0ffff         | mov                 eax, dword ptr [ebp - 0x20]
            //   8b95c0f0ffff         | inc                 esp
            //   898568f0ffff         | mov                 eax, dword ptr [esp + 0x40]
            //   898584f0ffff         | inc                 ecx

        $sequence_2 = { 7435 b9???????? e8???????? 8bd0 90 }
            // n = 5, score = 200
            //   7435                 | inc                 eax
            //   b9????????           |                     
            //   e8????????           |                     
            //   8bd0                 | xor                 edx, edx
            //   90                   | dec                 eax

        $sequence_3 = { 746f 803d????????00 b9???????? 7419 }
            // n = 4, score = 200
            //   746f                 | lea                 ecx, [0x22139]
            //   803d????????00       |                     
            //   b9????????           |                     
            //   7419                 | dec                 eax

        $sequence_4 = { 83ffff 7516 5f 5b }
            // n = 4, score = 200
            //   83ffff               | mov                 ecx, eax
            //   7516                 | inc                 ecx
            //   5f                   | mov                 eax, 1
            //   5b                   | dec                 eax

        $sequence_5 = { e8???????? 8be5 5d c3 8d85ecfdffff 8d5001 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8be5                 | je                  0xa
            //   5d                   | test                eax, eax
            //   c3                   | je                  0xffffffa5
            //   8d85ecfdffff         | dec                 eax
            //   8d5001               | mov                 ecx, edi

        $sequence_6 = { c60000 40 2bd0 8d7432fb }
            // n = 4, score = 200
            //   c60000               | lea                 eax, [ebp - 0x214]
            //   40                   | lea                 edx, [eax + 1]
            //   2bd0                 | mov                 eax, 0x103
            //   8d7432fb             | mov                 dword ptr [ebp - 0xf80], edx

        $sequence_7 = { 8bce c1f905 8b0c8d60aa0310 83e61f }
            // n = 4, score = 200
            //   8bce                 | mov                 ecx, dword ptr [esp + 0x80]
            //   c1f905               | mov                 esp, ebp
            //   8b0c8d60aa0310       | pop                 ebp
            //   83e61f               | ret                 

        $sequence_8 = { 4883ec38 48c7442420feffffff 4c8d05740e0200 488d15350c0200 488d0dca9a0200 }
            // n = 5, score = 100
            //   4883ec38             | nop                 word ptr [eax + eax]
            //   48c7442420feffffff     | dec    eax
            //   4c8d05740e0200       | sub                 esp, 0x38
            //   488d15350c0200       | dec                 eax
            //   488d0dca9a0200       | mov                 dword ptr [esp + 0x20], 0xfffffffe

        $sequence_9 = { 33c0 488bda 41b900100000 f2ae 33d2 }
            // n = 5, score = 100
            //   33c0                 | mov                 byte ptr [esp + 0x28], 0
            //   488bda               | lea                 esi, [eax + 0x10]
            //   41b900100000         | inc                 ecx
            //   f2ae                 | shl                 edx, 8
            //   33d2                 | movzx               eax, cl

        $sequence_10 = { 33c0 488bd9 c644242800 8d7010 }
            // n = 4, score = 100
            //   33c0                 | dec                 esp
            //   488bd9               | lea                 eax, [0x20e74]
            //   c644242800           | dec                 eax
            //   8d7010               | lea                 edx, [0x20c35]

        $sequence_11 = { 41c1e208 0fb6c1 4403d0 418bd0 c1ea18 }
            // n = 5, score = 100
            //   41c1e208             | dec                 eax
            //   0fb6c1               | lea                 ecx, [0x29aca]
            //   4403d0               | xor                 eax, eax
            //   418bd0               | dec                 eax
            //   c1ea18               | mov                 ebx, ecx

        $sequence_12 = { e8???????? 488b8b58400000 4885c9 7405 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   488b8b58400000       | inc                 esp
            //   4885c9               | add                 edx, eax
            //   7405                 | inc                 ecx

        $sequence_13 = { 85c0 74a3 488bcf e8???????? 448b45e0 }
            // n = 5, score = 100
            //   85c0                 | mov                 edx, eax
            //   74a3                 | shr                 edx, 0x18
            //   488bcf               | xor                 eax, eax
            //   e8????????           |                     
            //   448b45e0             | dec                 eax

        $sequence_14 = { e8???????? 448be8 8bf0 6666660f1f840000000000 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   448be8               | inc                 esp
            //   8bf0                 | mov                 ebp, eax
            //   6666660f1f840000000000     | mov    esi, eax

        $sequence_15 = { 448b442440 41ffc0 33d2 488bc8 e8???????? 41b801000000 }
            // n = 6, score = 100
            //   448b442440           | mov                 ebx, edx
            //   41ffc0               | inc                 ecx
            //   33d2                 | mov                 ecx, 0x1000
            //   488bc8               | repne scasb         al, byte ptr es:[edi]
            //   e8????????           |                     
            //   41b801000000         | xor                 edx, edx

    condition:
        7 of them and filesize < 524288
}
