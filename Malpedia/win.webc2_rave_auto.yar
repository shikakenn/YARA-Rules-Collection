rule win_webc2_rave_auto {

    meta:
        id = "4Rc5a7PdQWqe4XOtkldM8I"
        fingerprint = "v1_sha256_d35d8eb6aefe7cc5c299f90e5678dfb9d7a049e0361b4bce0487fde286aa34fe"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.webc2_rave."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_rave"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6aff 8d542438 53 52 6a02 894c2444 }
            // n = 6, score = 100
            //   6aff                 | push                -1
            //   8d542438             | lea                 edx, [esp + 0x38]
            //   53                   | push                ebx
            //   52                   | push                edx
            //   6a02                 | push                2
            //   894c2444             | mov                 dword ptr [esp + 0x44], ecx

        $sequence_1 = { ff15???????? 8b442418 5f 5e 5d 81c420030000 c3 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   81c420030000         | add                 esp, 0x320
            //   c3                   | ret                 

        $sequence_2 = { 8b4e04 51 ffd7 8b4608 3bc3 7409 50 }
            // n = 7, score = 100
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   51                   | push                ecx
            //   ffd7                 | call                edi
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   3bc3                 | cmp                 eax, ebx
            //   7409                 | je                  0xb
            //   50                   | push                eax

        $sequence_3 = { 83ec68 8d442410 50 e8???????? }
            // n = 4, score = 100
            //   83ec68               | sub                 esp, 0x68
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 8b442414 c6043000 85db 7409 53 e8???????? 83c404 }
            // n = 7, score = 100
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   c6043000             | mov                 byte ptr [eax + esi], 0
            //   85db                 | test                ebx, ebx
            //   7409                 | je                  0xb
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_5 = { 8bf8 83ffff 740d 8b4c2410 6a00 51 56 }
            // n = 7, score = 100
            //   8bf8                 | mov                 edi, eax
            //   83ffff               | cmp                 edi, -1
            //   740d                 | je                  0xf
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   56                   | push                esi

        $sequence_6 = { 750c 68d0070000 45 ff15???????? 83fd0a 7419 }
            // n = 6, score = 100
            //   750c                 | jne                 0xe
            //   68d0070000           | push                0x7d0
            //   45                   | inc                 ebp
            //   ff15????????         |                     
            //   83fd0a               | cmp                 ebp, 0xa
            //   7419                 | je                  0x1b

        $sequence_7 = { 57 b941000000 33c0 8d7c2420 f3ab aa }
            // n = 6, score = 100
            //   57                   | push                edi
            //   b941000000           | mov                 ecx, 0x41
            //   33c0                 | xor                 eax, eax
            //   8d7c2420             | lea                 edi, [esp + 0x20]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_8 = { 8d8c2454010000 68???????? 51 ffd6 897c2418 8d94245c020000 8d842454010000 }
            // n = 7, score = 100
            //   8d8c2454010000       | lea                 ecx, [esp + 0x154]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   897c2418             | mov                 dword ptr [esp + 0x18], edi
            //   8d94245c020000       | lea                 edx, [esp + 0x25c]
            //   8d842454010000       | lea                 eax, [esp + 0x154]

        $sequence_9 = { 50 ffd5 83c408 e9???????? 8b4e10 6aff 8d542438 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ffd5                 | call                ebp
            //   83c408               | add                 esp, 8
            //   e9????????           |                     
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   6aff                 | push                -1
            //   8d542438             | lea                 edx, [esp + 0x38]

    condition:
        7 of them and filesize < 57344
}
