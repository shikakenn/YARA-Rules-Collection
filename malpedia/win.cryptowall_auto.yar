rule win_cryptowall_auto {

    meta:
        id = "2nh56XM73yP4auEYO31RTg"
        fingerprint = "v1_sha256_ce5a2f67f32819e2223821b9858e69dbea24618850279ae1bc1fe9c840f1999e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.cryptowall."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptowall"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a00 6a40 6a01 6a01 6a00 6a00 8d55e8 }
            // n = 7, score = 2100
            //   6a00                 | push                0
            //   6a40                 | push                0x40
            //   6a01                 | push                1
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d55e8               | lea                 edx, [ebp - 0x18]

        $sequence_1 = { 8b55f4 6689044a ebd0 8b450c 8b4df4 }
            // n = 5, score = 2100
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   6689044a             | mov                 word ptr [edx + ecx*2], ax
            //   ebd0                 | jmp                 0xffffffd2
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_2 = { 83f861 7c13 0fbe4d08 83f97a 7f0a 0fbe5508 83ea20 }
            // n = 7, score = 2100
            //   83f861               | cmp                 eax, 0x61
            //   7c13                 | jl                  0x15
            //   0fbe4d08             | movsx               ecx, byte ptr [ebp + 8]
            //   83f97a               | cmp                 ecx, 0x7a
            //   7f0a                 | jg                  0xc
            //   0fbe5508             | movsx               edx, byte ptr [ebp + 8]
            //   83ea20               | sub                 edx, 0x20

        $sequence_3 = { 52 e8???????? 83c408 8b0d???????? 8981d8000000 }
            // n = 5, score = 2100
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b0d????????         |                     
            //   8981d8000000         | mov                 dword ptr [ecx + 0xd8], eax

        $sequence_4 = { 740d 8b45fc 2d00080000 8945fc ebe5 8b45fc }
            // n = 6, score = 2100
            //   740d                 | je                  0xf
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   2d00080000           | sub                 eax, 0x800
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ebe5                 | jmp                 0xffffffe7
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_5 = { 8b45fc 2d00080000 8945fc ebe5 8b45fc 8be5 }
            // n = 6, score = 2100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   2d00080000           | sub                 eax, 0x800
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ebe5                 | jmp                 0xffffffe7
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8be5                 | mov                 esp, ebp

        $sequence_6 = { 55 8bec 51 837d0800 7441 837d0c00 }
            // n = 6, score = 2100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7441                 | je                  0x43
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0

        $sequence_7 = { 52 e8???????? 83c408 8b0d???????? 89819c000000 }
            // n = 5, score = 2100
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b0d????????         |                     
            //   89819c000000         | mov                 dword ptr [ecx + 0x9c], eax

        $sequence_8 = { 55 8bec 8b450c 8d4c0002 51 }
            // n = 5, score = 2100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8d4c0002             | lea                 ecx, [eax + eax + 2]
            //   51                   | push                ecx

        $sequence_9 = { e8???????? 83c404 8b5508 8b4204 50 8b4d08 8b5108 }
            // n = 7, score = 2100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b5108               | mov                 edx, dword ptr [ecx + 8]

    condition:
        7 of them and filesize < 417792
}
