rule win_smarteyes_auto {

    meta:
        id = "60VrOJf8HUL2sHy9VaNtgY"
        fingerprint = "v1_sha256_c5287c273b80d8410483f16228152973a803d8ac51015792b4ca7695eb66f818"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.smarteyes."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.smarteyes"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3bf0 7303 8975f8 53 bb04040000 53 e8???????? }
            // n = 7, score = 100
            //   3bf0                 | cmp                 esi, eax
            //   7303                 | jae                 5
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   53                   | push                ebx
            //   bb04040000           | mov                 ebx, 0x404
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_1 = { 53 50 e8???????? 59 59 85c0 750d }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   750d                 | jne                 0xf

        $sequence_2 = { 56 e8???????? 8bc6 c1f805 8b0485c0f50210 83e61f c1e606 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   c1f805               | sar                 eax, 5
            //   8b0485c0f50210       | mov                 eax, dword ptr [eax*4 + 0x1002f5c0]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6

        $sequence_3 = { f785c400000000800000 7407 68???????? eb1c 80bdc600000001 750e 66837d8009 }
            // n = 7, score = 100
            //   f785c400000000800000     | test    dword ptr [ebp + 0xc4], 0x8000
            //   7407                 | je                  9
            //   68????????           |                     
            //   eb1c                 | jmp                 0x1e
            //   80bdc600000001       | cmp                 byte ptr [ebp + 0xc6], 1
            //   750e                 | jne                 0x10
            //   66837d8009           | cmp                 word ptr [ebp - 0x80], 9

        $sequence_4 = { 8d85a0010000 50 8d4584 56 50 e8???????? 8d85bc030000 }
            // n = 7, score = 100
            //   8d85a0010000         | lea                 eax, [ebp + 0x1a0]
            //   50                   | push                eax
            //   8d4584               | lea                 eax, [ebp - 0x7c]
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d85bc030000         | lea                 eax, [ebp + 0x3bc]

        $sequence_5 = { 8b4508 53 56 85c0 0f84f5000000 66833800 0f84eb000000 }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   53                   | push                ebx
            //   56                   | push                esi
            //   85c0                 | test                eax, eax
            //   0f84f5000000         | je                  0xfb
            //   66833800             | cmp                 word ptr [eax], 0
            //   0f84eb000000         | je                  0xf1

        $sequence_6 = { b800000004 e9???????? 85c0 7504 84d2 74ee 8bc3 }
            // n = 7, score = 100
            //   b800000004           | mov                 eax, 0x4000000
            //   e9????????           |                     
            //   85c0                 | test                eax, eax
            //   7504                 | jne                 6
            //   84d2                 | test                dl, dl
            //   74ee                 | je                  0xfffffff0
            //   8bc3                 | mov                 eax, ebx

        $sequence_7 = { 85c0 7525 8d442418 50 8d442420 50 ff15???????? }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7525                 | jne                 0x27
            //   8d442418             | lea                 eax, [esp + 0x18]
            //   50                   | push                eax
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_8 = { e8???????? 85c0 0f8465010000 8d85c8faffff 8d5001 8a08 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8465010000         | je                  0x16b
            //   8d85c8faffff         | lea                 eax, [ebp - 0x538]
            //   8d5001               | lea                 edx, [eax + 1]
            //   8a08                 | mov                 cl, byte ptr [eax]

        $sequence_9 = { c6041800 8b45f0 eb02 33c0 5e c9 c3 }
            // n = 7, score = 100
            //   c6041800             | mov                 byte ptr [eax + ebx], 0
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 429056
}
