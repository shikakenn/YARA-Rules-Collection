rule win_avast_disabler_auto {

    meta:
        id = "2pmxJE5ZQuCH9hy9yfIraL"
        fingerprint = "v1_sha256_19754a7bc503b1b28bdfc059b6eb230f6f3e29b2e990d8ace51bd954a83ec439"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.avast_disabler."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.avast_disabler"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 85c0 7404 3bc1 7515 0f31 35???????? }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7404                 | je                  6
            //   3bc1                 | cmp                 eax, ecx
            //   7515                 | jne                 0x17
            //   0f31                 | rdtsc               
            //   35????????           |                     

        $sequence_1 = { 7534 837c371400 752d 89443714 6a08 8d45f4 50 }
            // n = 7, score = 100
            //   7534                 | jne                 0x36
            //   837c371400           | cmp                 dword ptr [edi + esi + 0x14], 0
            //   752d                 | jne                 0x2f
            //   89443714             | mov                 dword ptr [edi + esi + 0x14], eax
            //   6a08                 | push                8
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax

        $sequence_2 = { b94ee640bb 85c0 7404 3bc1 7515 }
            // n = 5, score = 100
            //   b94ee640bb           | mov                 ecx, 0xbb40e64e
            //   85c0                 | test                eax, eax
            //   7404                 | je                  6
            //   3bc1                 | cmp                 eax, ecx
            //   7515                 | jne                 0x17

        $sequence_3 = { 2b4c3718 51 53 53 50 e8???????? 8b4dfc }
            // n = 7, score = 100
            //   2b4c3718             | sub                 ecx, dword ptr [edi + esi + 0x18]
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_4 = { 50 ff15???????? 6a01 8d45f8 50 ff750c ff15???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff15????????         |                     

        $sequence_5 = { 33c0 40 394510 7534 837c371400 752d }
            // n = 6, score = 100
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   394510               | cmp                 dword ptr [ebp + 0x10], eax
            //   7534                 | jne                 0x36
            //   837c371400           | cmp                 dword ptr [edi + esi + 0x14], 0
            //   752d                 | jne                 0x2f

        $sequence_6 = { 8b5c3718 83c112 03d9 837d1000 }
            // n = 4, score = 100
            //   8b5c3718             | mov                 ebx, dword ptr [edi + esi + 0x18]
            //   83c112               | add                 ecx, 0x12
            //   03d9                 | add                 ebx, ecx
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0

        $sequence_7 = { 75a9 5f 5e 5b 5d c21000 55 }
            // n = 7, score = 100
            //   75a9                 | jne                 0xffffffab
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c21000               | ret                 0x10
            //   55                   | push                ebp

        $sequence_8 = { 51 803d????????00 7520 c605????????01 }
            // n = 4, score = 100
            //   51                   | push                ecx
            //   803d????????00       |                     
            //   7520                 | jne                 0x22
            //   c605????????01       |                     

        $sequence_9 = { 5f 5e 5b 8be5 5d c20c00 3b0d???????? }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   3b0d????????         |                     

    condition:
        7 of them and filesize < 41984
}
