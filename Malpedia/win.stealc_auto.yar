rule win_stealc_auto {

    meta:
        id = "57vKodqjOoXoygOs99pnQ"
        fingerprint = "v1_sha256_1bbc82a373b409e3dad4afed525c9d3527cdf24f15e799642d4692134ce52442"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.stealc."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealc"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 83c460 e8???????? 83c40c }
            // n = 4, score = 600
            //   e8????????           |                     
            //   83c460               | add                 esp, 0x60
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { ff15???????? 85c0 7507 c685e0feffff43 }
            // n = 4, score = 600
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   c685e0feffff43       | mov                 byte ptr [ebp - 0x120], 0x43

        $sequence_2 = { e8???????? e8???????? 83c418 6a3c }
            // n = 4, score = 600
            //   e8????????           |                     
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   6a3c                 | push                0x3c

        $sequence_3 = { 50 e8???????? e8???????? 83c474 }
            // n = 4, score = 600
            //   50                   | push                eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   83c474               | add                 esp, 0x74

        $sequence_4 = { e8???????? e8???????? 81c480000000 e9???????? }
            // n = 4, score = 600
            //   e8????????           |                     
            //   e8????????           |                     
            //   81c480000000         | add                 esp, 0x80
            //   e9????????           |                     

        $sequence_5 = { 68???????? e8???????? e8???????? 83c474 }
            // n = 4, score = 600
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   83c474               | add                 esp, 0x74

        $sequence_6 = { 50 e8???????? e8???????? 81c484000000 }
            // n = 4, score = 600
            //   50                   | push                eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   81c484000000         | add                 esp, 0x84

        $sequence_7 = { 8d45fc 50 ff75f4 e8???????? 59 59 8d85f0feffff }
            // n = 7, score = 400
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]

        $sequence_8 = { b9e8030000 33c0 f3aa 8d850ca5ffff 8945fc 8b7dfc b9e8030000 }
            // n = 7, score = 400
            //   b9e8030000           | mov                 ecx, 0x3e8
            //   33c0                 | xor                 eax, eax
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   8d850ca5ffff         | lea                 eax, [ebp - 0x5af4]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   b9e8030000           | mov                 ecx, 0x3e8

        $sequence_9 = { 8d75f4 e8???????? 8b45d0 e8???????? 8d7de8 8d75d0 }
            // n = 6, score = 400
            //   8d75f4               | lea                 esi, [ebp - 0xc]
            //   e8????????           |                     
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   e8????????           |                     
            //   8d7de8               | lea                 edi, [ebp - 0x18]
            //   8d75d0               | lea                 esi, [ebp - 0x30]

    condition:
        7 of them and filesize < 4891648
}
