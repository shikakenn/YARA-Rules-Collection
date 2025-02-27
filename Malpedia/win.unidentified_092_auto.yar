rule win_unidentified_092_auto {

    meta:
        id = "711D4sHS8lgf2YDGW4OY9C"
        fingerprint = "v1_sha256_652402e87963cd0c6ff5366fe9ef518c3ad3cc147775da4e4b2ee294d04144ab"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_092."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_092"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8955fc 3bc8 7313 8bcf 89471c e8???????? 8bc7 }
            // n = 7, score = 100
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   3bc8                 | cmp                 ecx, eax
            //   7313                 | jae                 0x15
            //   8bcf                 | mov                 ecx, edi
            //   89471c               | mov                 dword ptr [edi + 0x1c], eax
            //   e8????????           |                     
            //   8bc7                 | mov                 eax, edi

        $sequence_1 = { 8bcf e8???????? 83c404 6a02 6a00 53 }
            // n = 6, score = 100
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   53                   | push                ebx

        $sequence_2 = { 03d6 23cb 8bf0 894d08 8bcf 234df4 094d08 }
            // n = 7, score = 100
            //   03d6                 | add                 edx, esi
            //   23cb                 | and                 ecx, ebx
            //   8bf0                 | mov                 esi, eax
            //   894d08               | mov                 dword ptr [ebp + 8], ecx
            //   8bcf                 | mov                 ecx, edi
            //   234df4               | and                 ecx, dword ptr [ebp - 0xc]
            //   094d08               | or                  dword ptr [ebp + 8], ecx

        $sequence_3 = { e8???????? 8bd7 8bc8 e8???????? 8b45e8 83f808 720d }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bd7                 | mov                 edx, edi
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   83f808               | cmp                 eax, 8
            //   720d                 | jb                  0xf

        $sequence_4 = { 6a00 6a01 8d45eb c645eb29 50 57 }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   8d45eb               | lea                 eax, [ebp - 0x15]
            //   c645eb29             | mov                 byte ptr [ebp - 0x15], 0x29
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_5 = { 0f4345d4 6800040000 50 ff75b4 ff15???????? c645fc00 8b45d0 }
            // n = 7, score = 100
            //   0f4345d4             | cmovae              eax, dword ptr [ebp - 0x2c]
            //   6800040000           | push                0x400
            //   50                   | push                eax
            //   ff75b4               | push                dword ptr [ebp - 0x4c]
            //   ff15????????         |                     
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]

        $sequence_6 = { 33d1 8b4d08 8bf9 03d6 23cb 0bfb 237de4 }
            // n = 7, score = 100
            //   33d1                 | xor                 edx, ecx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8bf9                 | mov                 edi, ecx
            //   03d6                 | add                 edx, esi
            //   23cb                 | and                 ecx, ebx
            //   0bfb                 | or                  edi, ebx
            //   237de4               | and                 edi, dword ptr [ebp - 0x1c]

        $sequence_7 = { 3d00100000 722a f6c11f 0f8500050000 8b41fc 3bc1 0f83f5040000 }
            // n = 7, score = 100
            //   3d00100000           | cmp                 eax, 0x1000
            //   722a                 | jb                  0x2c
            //   f6c11f               | test                cl, 0x1f
            //   0f8500050000         | jne                 0x506
            //   8b41fc               | mov                 eax, dword ptr [ecx - 4]
            //   3bc1                 | cmp                 eax, ecx
            //   0f83f5040000         | jae                 0x4fb

        $sequence_8 = { e8???????? 84c0 7439 68???????? 8d8d80f6ffff e8???????? 8d8d64f6ffff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7439                 | je                  0x3b
            //   68????????           |                     
            //   8d8d80f6ffff         | lea                 ecx, [ebp - 0x980]
            //   e8????????           |                     
            //   8d8d64f6ffff         | lea                 ecx, [ebp - 0x99c]

        $sequence_9 = { c745cc00000000 c645bc00 e8???????? c645fc01 81ff00040000 7d21 be00040000 }
            // n = 7, score = 100
            //   c745cc00000000       | mov                 dword ptr [ebp - 0x34], 0
            //   c645bc00             | mov                 byte ptr [ebp - 0x44], 0
            //   e8????????           |                     
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   81ff00040000         | cmp                 edi, 0x400
            //   7d21                 | jge                 0x23
            //   be00040000           | mov                 esi, 0x400

    condition:
        7 of them and filesize < 10202112
}
