rule win_krbanker_auto {

    meta:
        id = "2CuLvxoORnIuVuYhHzRmma"
        fingerprint = "v1_sha256_3f68b288c9b94489462004d900c99f82c6cc93e611f88ed341834ce27199e0a6"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.krbanker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.krbanker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 51 8b4c2410 57 6a01 }
            // n = 4, score = 400
            //   51                   | push                ecx
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   57                   | push                edi
            //   6a01                 | push                1

        $sequence_1 = { 50 ff5208 8b4e04 33c0 85c9 }
            // n = 5, score = 400
            //   50                   | push                eax
            //   ff5208               | call                dword ptr [edx + 8]
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   33c0                 | xor                 eax, eax
            //   85c9                 | test                ecx, ecx

        $sequence_2 = { 8d7908 7413 8b4818 8d5108 8b4904 }
            // n = 5, score = 400
            //   8d7908               | lea                 edi, [ecx + 8]
            //   7413                 | je                  0x15
            //   8b4818               | mov                 ecx, dword ptr [eax + 0x18]
            //   8d5108               | lea                 edx, [ecx + 8]
            //   8b4904               | mov                 ecx, dword ptr [ecx + 4]

        $sequence_3 = { 8945c0 ff75c0 ff75c4 ff75c8 ff75cc }
            // n = 5, score = 400
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax
            //   ff75c0               | push                dword ptr [ebp - 0x40]
            //   ff75c4               | push                dword ptr [ebp - 0x3c]
            //   ff75c8               | push                dword ptr [ebp - 0x38]
            //   ff75cc               | push                dword ptr [ebp - 0x34]

        $sequence_4 = { 8bf0 83c40c 83feff 0f848f000000 56 57 }
            // n = 6, score = 400
            //   8bf0                 | mov                 esi, eax
            //   83c40c               | add                 esp, 0xc
            //   83feff               | cmp                 esi, -1
            //   0f848f000000         | je                  0x95
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_5 = { 8b4824 33db 49 85c9 0f9cc3 }
            // n = 5, score = 400
            //   8b4824               | mov                 ecx, dword ptr [eax + 0x24]
            //   33db                 | xor                 ebx, ebx
            //   49                   | dec                 ecx
            //   85c9                 | test                ecx, ecx
            //   0f9cc3               | setl                bl

        $sequence_6 = { 53 57 e8???????? 8bf0 83c40c 83feff }
            // n = 6, score = 400
            //   53                   | push                ebx
            //   57                   | push                edi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c40c               | add                 esp, 0xc
            //   83feff               | cmp                 esi, -1

        $sequence_7 = { 6a00 686c000000 6801000000 bb40010000 e8???????? }
            // n = 5, score = 400
            //   6a00                 | push                0
            //   686c000000           | push                0x6c
            //   6801000000           | push                1
            //   bb40010000           | mov                 ebx, 0x140
            //   e8????????           |                     

        $sequence_8 = { 8b4104 894504 8b5108 895508 8b410c }
            // n = 5, score = 400
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   894504               | mov                 dword ptr [ebp + 4], eax
            //   8b5108               | mov                 edx, dword ptr [ecx + 8]
            //   895508               | mov                 dword ptr [ebp + 8], edx
            //   8b410c               | mov                 eax, dword ptr [ecx + 0xc]

        $sequence_9 = { 6801010080 6a00 6870000000 6801000000 bb40010000 }
            // n = 5, score = 400
            //   6801010080           | push                0x80000101
            //   6a00                 | push                0
            //   6870000000           | push                0x70
            //   6801000000           | push                1
            //   bb40010000           | mov                 ebx, 0x140

    condition:
        7 of them and filesize < 1826816
}
