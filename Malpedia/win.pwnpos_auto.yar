rule win_pwnpos_auto {

    meta:
        id = "3FYGCDzDVLUS5jr0rUNvPd"
        fingerprint = "v1_sha256_99cca90c63c7d894b30f59c47917d71bb5281e2d807f6e3da388b67f1d509c2d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.pwnpos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pwnpos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c745f45cb34300 e8???????? cc 8bff 55 8bec 56 }
            // n = 7, score = 100
            //   c745f45cb34300       | mov                 dword ptr [ebp - 0xc], 0x43b35c
            //   e8????????           |                     
            //   cc                   | int3                
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi

        $sequence_1 = { 50 8b4510 51 53 8b5c2428 52 50 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   8b5c2428             | mov                 ebx, dword ptr [esp + 0x28]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_2 = { ebab c745e444b24300 817de450b24300 7311 }
            // n = 4, score = 100
            //   ebab                 | jmp                 0xffffffad
            //   c745e444b24300       | mov                 dword ptr [ebp - 0x1c], 0x43b244
            //   817de450b24300       | cmp                 dword ptr [ebp - 0x1c], 0x43b250
            //   7311                 | jae                 0x13

        $sequence_3 = { 8d442414 c7442448ffffffff 50 8935???????? e8???????? c744244801000000 8b16 }
            // n = 7, score = 100
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   c7442448ffffffff     | mov                 dword ptr [esp + 0x48], 0xffffffff
            //   50                   | push                eax
            //   8935????????         |                     
            //   e8????????           |                     
            //   c744244801000000     | mov                 dword ptr [esp + 0x48], 1
            //   8b16                 | mov                 edx, dword ptr [esi]

        $sequence_4 = { 0fb6c0 50 8b420c ffd0 83f8ff 0f85c2000000 834dec04 }
            // n = 7, score = 100
            //   0fb6c0               | movzx               eax, al
            //   50                   | push                eax
            //   8b420c               | mov                 eax, dword ptr [edx + 0xc]
            //   ffd0                 | call                eax
            //   83f8ff               | cmp                 eax, -1
            //   0f85c2000000         | jne                 0xc8
            //   834dec04             | or                  dword ptr [ebp - 0x14], 4

        $sequence_5 = { 50 27 42 00742742 009c2742008a46 0323 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   27                   | daa                 
            //   42                   | inc                 edx
            //   00742742             | add                 byte ptr [edi + 0x42], dh
            //   009c2742008a46       | add                 byte ptr [edi + 0x468a0042], bl
            //   0323                 | add                 esp, dword ptr [ebx]

        $sequence_6 = { 53 6a65 56 e8???????? 83c40c 85c0 0f849e000000 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   6a65                 | push                0x65
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f849e000000         | je                  0xa4

        $sequence_7 = { 895df4 f6c203 743c 8bd6 c1fa05 8b1495a0774400 83e61f }
            // n = 7, score = 100
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   f6c203               | test                dl, 3
            //   743c                 | je                  0x3e
            //   8bd6                 | mov                 edx, esi
            //   c1fa05               | sar                 edx, 5
            //   8b1495a0774400       | mov                 edx, dword ptr [edx*4 + 0x4477a0]
            //   83e61f               | and                 esi, 0x1f

        $sequence_8 = { c705????????c11a4300 c705????????4d1a4300 c3 8bff }
            // n = 4, score = 100
            //   c705????????c11a4300     |     
            //   c705????????4d1a4300     |     
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi

        $sequence_9 = { e8???????? 8d4c2408 51 8d4c2410 8bf8 c744240ce0ea4300 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d4c2408             | lea                 ecx, [esp + 8]
            //   51                   | push                ecx
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   8bf8                 | mov                 edi, eax
            //   c744240ce0ea4300     | mov                 dword ptr [esp + 0xc], 0x43eae0

    condition:
        7 of them and filesize < 638976
}
