rule win_evilbunny_auto {

    meta:
        id = "7Ui74ztDV5L6izUu6CLLaZ"
        fingerprint = "v1_sha256_1534b24ff80468ad553b2eed5ffad4b00ea68305fd3769acbc60a82e33460626"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.evilbunny."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.evilbunny"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b4df8 894d0c 6aff 8b5508 52 e8???????? 83c408 }
            // n = 7, score = 200
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   894d0c               | mov                 dword ptr [ebp + 0xc], ecx
            //   6aff                 | push                -1
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_1 = { 8b4df4 894d10 e9???????? 8be5 5d c3 43 }
            // n = 7, score = 200
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   894d10               | mov                 dword ptr [ebp + 0x10], ecx
            //   e9????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   43                   | inc                 ebx

        $sequence_2 = { 8b4df4 8b1488 8955cc 8b4508 8b08 8b5110 8b45f4 }
            // n = 7, score = 200
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8b1488               | mov                 edx, dword ptr [eax + ecx*4]
            //   8955cc               | mov                 dword ptr [ebp - 0x34], edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b5110               | mov                 edx, dword ptr [ecx + 0x10]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_3 = { 8bf4 8d45e0 50 6a00 8b4dfc 51 68???????? }
            // n = 7, score = 200
            //   8bf4                 | mov                 esi, esp
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   68????????           |                     

        $sequence_4 = { 8b4508 8945fc c745f800000000 c745f400000000 c745f000000000 8bf4 6803800000 }
            // n = 7, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   8bf4                 | mov                 esi, esp
            //   6803800000           | push                0x8003

        $sequence_5 = { 8bf4 50 ff15???????? 3bf4 e8???????? 8b4dec 83b93008000000 }
            // n = 7, score = 200
            //   8bf4                 | mov                 esi, esp
            //   50                   | push                eax
            //   ff15????????         |                     
            //   3bf4                 | cmp                 esi, esp
            //   e8????????           |                     
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   83b93008000000       | cmp                 dword ptr [ecx + 0x830], 0

        $sequence_6 = { 8b95a8fcffff 89511c 6a00 8b451c 50 8b4d18 }
            // n = 6, score = 200
            //   8b95a8fcffff         | mov                 edx, dword ptr [ebp - 0x358]
            //   89511c               | mov                 dword ptr [ecx + 0x1c], edx
            //   6a00                 | push                0
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]
            //   50                   | push                eax
            //   8b4d18               | mov                 ecx, dword ptr [ebp + 0x18]

        $sequence_7 = { 8d4da8 51 e8???????? 83c40c c645fc03 8d4d88 e8???????? }
            // n = 7, score = 200
            //   8d4da8               | lea                 ecx, [ebp - 0x58]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   8d4d88               | lea                 ecx, [ebp - 0x78]
            //   e8????????           |                     

        $sequence_8 = { 8d8df4feffff 51 e8???????? 83c408 8d95f4feffff 52 e8???????? }
            // n = 7, score = 200
            //   8d8df4feffff         | lea                 ecx, [ebp - 0x10c]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d95f4feffff         | lea                 edx, [ebp - 0x10c]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_9 = { c745fccccccccc 894dfc 68eeeac01f 68???????? 8b4dfc e8???????? 8945f8 }
            // n = 7, score = 200
            //   c745fccccccccc       | mov                 dword ptr [ebp - 4], 0xcccccccc
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   68eeeac01f           | push                0x1fc0eaee
            //   68????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

    condition:
        7 of them and filesize < 1695744
}
