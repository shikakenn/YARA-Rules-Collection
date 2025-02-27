rule win_erbium_stealer_auto {

    meta:
        id = "7jYGNg4Q5l8LvvujzCfvg"
        fingerprint = "v1_sha256_bccad5f3f8af9dfd7831cb14cdc529eb8f240bee1d54dd0908880ec160a26124"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.erbium_stealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.erbium_stealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 66833800 75f7 668b4c2450 6685c9 7418 }
            // n = 5, score = 100
            //   66833800             | cmp                 word ptr [eax], 0
            //   75f7                 | jne                 0xfffffff9
            //   668b4c2450           | mov                 cx, word ptr [esp + 0x50]
            //   6685c9               | test                cx, cx
            //   7418                 | je                  0x1a

        $sequence_1 = { 8b4db8 83c102 51 8b55d0 52 }
            // n = 5, score = 100
            //   8b4db8               | mov                 ecx, dword ptr [ebp - 0x48]
            //   83c102               | add                 ecx, 2
            //   51                   | push                ecx
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   52                   | push                edx

        $sequence_2 = { 50 8b4dec 8b55f8 03510c }
            // n = 4, score = 100
            //   50                   | push                eax
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   03510c               | add                 edx, dword ptr [ecx + 0xc]

        $sequence_3 = { 83c208 8955e0 c745dc00000000 eb12 8b45dc }
            // n = 5, score = 100
            //   83c208               | add                 edx, 8
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   c745dc00000000       | mov                 dword ptr [ebp - 0x24], 0
            //   eb12                 | jmp                 0x14
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]

        $sequence_4 = { 0f1f4000 8a10 0fbef2 80ea41 8bce }
            // n = 5, score = 100
            //   0f1f4000             | nop                 dword ptr [eax]
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   0fbef2               | movsx               esi, dl
            //   80ea41               | sub                 dl, 0x41
            //   8bce                 | mov                 ecx, esi

        $sequence_5 = { 894588 89458c 894590 6a00 6a18 8d8d7cffffff }
            // n = 6, score = 100
            //   894588               | mov                 dword ptr [ebp - 0x78], eax
            //   89458c               | mov                 dword ptr [ebp - 0x74], eax
            //   894590               | mov                 dword ptr [ebp - 0x70], eax
            //   6a00                 | push                0
            //   6a18                 | push                0x18
            //   8d8d7cffffff         | lea                 ecx, [ebp - 0x84]

        $sequence_6 = { 52 ff55fc 32c0 e9???????? 6a00 6800100000 68???????? }
            // n = 7, score = 100
            //   52                   | push                edx
            //   ff55fc               | call                dword ptr [ebp - 4]
            //   32c0                 | xor                 al, al
            //   e9????????           |                     
            //   6a00                 | push                0
            //   6800100000           | push                0x1000
            //   68????????           |                     

        $sequence_7 = { 68???????? 8b4df4 51 ff15???????? 8945ac 68???????? 8b55f4 }
            // n = 7, score = 100
            //   68????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8945ac               | mov                 dword ptr [ebp - 0x54], eax
            //   68????????           |                     
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]

        $sequence_8 = { 660f1f440000 40 80b84820400000 75f6 51 }
            // n = 5, score = 100
            //   660f1f440000         | nop                 word ptr [eax + eax]
            //   40                   | inc                 eax
            //   80b84820400000       | cmp                 byte ptr [eax + 0x402048], 0
            //   75f6                 | jne                 0xfffffff8
            //   51                   | push                ecx

        $sequence_9 = { 85c0 753d 6800800000 6a00 8b55f8 52 8b4508 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   753d                 | jne                 0x3f
            //   6800800000           | push                0x8000
            //   6a00                 | push                0
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   52                   | push                edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 33792
}
