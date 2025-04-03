rule win_biscuit_auto {

    meta:
        id = "4p2AIjKyyyVc0HChj07VpM"
        fingerprint = "v1_sha256_84aba44ada1e956d4a74e202350a88ae7df3ab1612a23de6af2ad0ed5a1e2805"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.biscuit."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.biscuit"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 89542420 8b542410 6a00 51 6a00 52 }
            // n = 6, score = 100
            //   89542420             | mov                 dword ptr [esp + 0x20], edx
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   52                   | push                edx

        $sequence_1 = { 50 ff15???????? 8b35???????? 8d4c240c 51 68???????? 6a00 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   51                   | push                ecx
            //   68????????           |                     
            //   6a00                 | push                0

        $sequence_2 = { ffd6 8b4304 8d55ec 6a04 52 6a02 50 }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   8d55ec               | lea                 edx, [ebp - 0x14]
            //   6a04                 | push                4
            //   52                   | push                edx
            //   6a02                 | push                2
            //   50                   | push                eax

        $sequence_3 = { 2b9584feffff 899598feffff 8b858cfeffff 3b8598feffff 0f87d4000000 8b8d8cfeffff }
            // n = 6, score = 100
            //   2b9584feffff         | sub                 edx, dword ptr [ebp - 0x17c]
            //   899598feffff         | mov                 dword ptr [ebp - 0x168], edx
            //   8b858cfeffff         | mov                 eax, dword ptr [ebp - 0x174]
            //   3b8598feffff         | cmp                 eax, dword ptr [ebp - 0x168]
            //   0f87d4000000         | ja                  0xda
            //   8b8d8cfeffff         | mov                 ecx, dword ptr [ebp - 0x174]

        $sequence_4 = { 8b8d1cb7ffff bf???????? 8bb524b7ffff 33d2 899544b6ffff }
            // n = 5, score = 100
            //   8b8d1cb7ffff         | mov                 ecx, dword ptr [ebp - 0x48e4]
            //   bf????????           |                     
            //   8bb524b7ffff         | mov                 esi, dword ptr [ebp - 0x48dc]
            //   33d2                 | xor                 edx, edx
            //   899544b6ffff         | mov                 dword ptr [ebp - 0x49bc], edx

        $sequence_5 = { 83fefd 897508 7605 e8???????? 8b4b04 33d2 3bca }
            // n = 7, score = 100
            //   83fefd               | cmp                 esi, -3
            //   897508               | mov                 dword ptr [ebp + 8], esi
            //   7605                 | jbe                 7
            //   e8????????           |                     
            //   8b4b04               | mov                 ecx, dword ptr [ebx + 4]
            //   33d2                 | xor                 edx, edx
            //   3bca                 | cmp                 ecx, edx

        $sequence_6 = { ff15???????? 6a64 ff15???????? e9???????? 5f 5e }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   6a64                 | push                0x64
            //   ff15????????         |                     
            //   e9????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_7 = { 85f6 7533 fec8 56 8841ff 8bcb e8???????? }
            // n = 7, score = 100
            //   85f6                 | test                esi, esi
            //   7533                 | jne                 0x35
            //   fec8                 | dec                 al
            //   56                   | push                esi
            //   8841ff               | mov                 byte ptr [ecx - 1], al
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_8 = { 8b9530daffff 83c9ff 33c0 f2ae f7d1 2bf9 8bf7 }
            // n = 7, score = 100
            //   8b9530daffff         | mov                 edx, dword ptr [ebp - 0x25d0]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   8bf7                 | mov                 esi, edi

        $sequence_9 = { a1???????? 50 6a00 8b8d30b8ffff 51 }
            // n = 5, score = 100
            //   a1????????           |                     
            //   50                   | push                eax
            //   6a00                 | push                0
            //   8b8d30b8ffff         | mov                 ecx, dword ptr [ebp - 0x47d0]
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 180224
}
