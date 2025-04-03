rule win_pgift_auto {

    meta:
        id = "3cEMJKDHZa53rbZUGKFGIS"
        fingerprint = "v1_sha256_86543d2a9c2965bb35bf9078bd182bce16bae717918e12d47f187ce1755d9b8f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.pgift."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pgift"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c645fc03 e8???????? ff7510 8d4de8 }
            // n = 4, score = 100
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   e8????????           |                     
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8d4de8               | lea                 ecx, [ebp - 0x18]

        $sequence_1 = { e8???????? 8d7e01 57 ebac }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8d7e01               | lea                 edi, [esi + 1]
            //   57                   | push                edi
            //   ebac                 | jmp                 0xffffffae

        $sequence_2 = { 53 6a11 ff15???????? 8bd8 8d45ec }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   6a11                 | push                0x11
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   8d45ec               | lea                 eax, [ebp - 0x14]

        $sequence_3 = { 53 6a01 6800000040 ff75ec ff15???????? 8bd8 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   6a01                 | push                1
            //   6800000040           | push                0x40000000
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_4 = { 7408 ff4510 83c710 eb99 8b4e14 }
            // n = 5, score = 100
            //   7408                 | je                  0xa
            //   ff4510               | inc                 dword ptr [ebp + 0x10]
            //   83c710               | add                 edi, 0x10
            //   eb99                 | jmp                 0xffffff9b
            //   8b4e14               | mov                 ecx, dword ptr [esi + 0x14]

        $sequence_5 = { 89450c 8d45e4 53 50 8d4594 50 }
            // n = 6, score = 100
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   8d4594               | lea                 eax, [ebp - 0x6c]
            //   50                   | push                eax

        $sequence_6 = { 50 8d4de4 e8???????? 33db 8d8de4feffff 895dfc 895dec }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   8d8de4feffff         | lea                 ecx, [ebp - 0x11c]
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx

        $sequence_7 = { 8d4de8 c645fc01 e8???????? 83f8ff 750f 6a2f 8d4de8 }
            // n = 7, score = 100
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   750f                 | jne                 0x11
            //   6a2f                 | push                0x2f
            //   8d4de8               | lea                 ecx, [ebp - 0x18]

        $sequence_8 = { e9???????? 8b4d08 8bc3 2bc1 c1f802 3bc7 7369 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8bc3                 | mov                 eax, ebx
            //   2bc1                 | sub                 eax, ecx
            //   c1f802               | sar                 eax, 2
            //   3bc7                 | cmp                 eax, edi
            //   7369                 | jae                 0x6b

        $sequence_9 = { e8???????? ff75e8 ff15???????? eb53 8b45ec 3958f8 742f }
            // n = 7, score = 100
            //   e8????????           |                     
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   ff15????????         |                     
            //   eb53                 | jmp                 0x55
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   3958f8               | cmp                 dword ptr [eax - 8], ebx
            //   742f                 | je                  0x31

    condition:
        7 of them and filesize < 98304
}
