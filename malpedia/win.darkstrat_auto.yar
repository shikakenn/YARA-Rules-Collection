rule win_darkstrat_auto {

    meta:
        id = "QOAj0kUgcOYFZkGEDb3ry"
        fingerprint = "v1_sha256_43f15b7abb636194943e13d25cec4711b2a1804bac3ef250b81d118208eb3e9f"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkstrat"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83ff0a 7d22 ff33 68???????? 8d55e0 8bc7 }
            // n = 6, score = 100
            //   83ff0a               | cmp                 edi, 0xa
            //   7d22                 | jge                 0x24
            //   ff33                 | push                dword ptr [ebx]
            //   68????????           |                     
            //   8d55e0               | lea                 edx, [ebp - 0x20]
            //   8bc7                 | mov                 eax, edi

        $sequence_1 = { e8???????? 8d45f4 50 6a00 6a00 6a00 8b45f8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_2 = { 50 b901000000 ba0a000000 b002 e8???????? 8b55c4 8d45fc }
            // n = 7, score = 100
            //   50                   | push                eax
            //   b901000000           | mov                 ecx, 1
            //   ba0a000000           | mov                 edx, 0xa
            //   b002                 | mov                 al, 2
            //   e8????????           |                     
            //   8b55c4               | mov                 edx, dword ptr [ebp - 0x3c]
            //   8d45fc               | lea                 eax, [ebp - 4]

        $sequence_3 = { 68???????? 68???????? 68???????? e8???????? 53 6a50 68???????? }
            // n = 7, score = 100
            //   68????????           |                     
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   53                   | push                ebx
            //   6a50                 | push                0x50
            //   68????????           |                     

        $sequence_4 = { 83caff e8???????? 50 8d854cfeffff ba???????? b950000000 e8???????? }
            // n = 7, score = 100
            //   83caff               | or                  edx, 0xffffffff
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d854cfeffff         | lea                 eax, [ebp - 0x1b4]
            //   ba????????           |                     
            //   b950000000           | mov                 ecx, 0x50
            //   e8????????           |                     

        $sequence_5 = { 64ff30 648920 8bc7 ba???????? e8???????? 33d2 b80a000000 }
            // n = 7, score = 100
            //   64ff30               | push                dword ptr fs:[eax]
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   8bc7                 | mov                 eax, edi
            //   ba????????           |                     
            //   e8????????           |                     
            //   33d2                 | xor                 edx, edx
            //   b80a000000           | mov                 eax, 0xa

        $sequence_6 = { 53 e8???????? 8b06 8b5604 0345f8 1355fc }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   0345f8               | add                 eax, dword ptr [ebp - 8]
            //   1355fc               | adc                 edx, dword ptr [ebp - 4]

        $sequence_7 = { 6a00 56 e8???????? eb0c 8d45d4 50 6a01 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   56                   | push                esi
            //   e8????????           |                     
            //   eb0c                 | jmp                 0xe
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   6a01                 | push                1

        $sequence_8 = { 83e830 03f0 eb0d 25ff000000 83e841 83c00a 03f0 }
            // n = 7, score = 100
            //   83e830               | sub                 eax, 0x30
            //   03f0                 | add                 esi, eax
            //   eb0d                 | jmp                 0xf
            //   25ff000000           | and                 eax, 0xff
            //   83e841               | sub                 eax, 0x41
            //   83c00a               | add                 eax, 0xa
            //   03f0                 | add                 esi, eax

        $sequence_9 = { 52 50 8d55c4 b808000000 e8???????? ff75c4 68???????? }
            // n = 7, score = 100
            //   52                   | push                edx
            //   50                   | push                eax
            //   8d55c4               | lea                 edx, [ebp - 0x3c]
            //   b808000000           | mov                 eax, 8
            //   e8????????           |                     
            //   ff75c4               | push                dword ptr [ebp - 0x3c]
            //   68????????           |                     

    condition:
        7 of them and filesize < 458752
}
