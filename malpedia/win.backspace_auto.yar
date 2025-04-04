rule win_backspace_auto {

    meta:
        id = "6WbtimOikqXGKtw5XOmdt4"
        fingerprint = "v1_sha256_1f557e82713be82d4effefb67945984b55368207555daca9d42390f29b2b045a"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.backspace."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.backspace"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 40 ebea ff75f4 889c0574ffffff 8d8574ffffff 50 6a01 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   ebea                 | jmp                 0xffffffec
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   889c0574ffffff       | mov                 byte ptr [ebp + eax - 0x8c], bl
            //   8d8574ffffff         | lea                 eax, [ebp - 0x8c]
            //   50                   | push                eax
            //   6a01                 | push                1

        $sequence_1 = { 59 50 ffd6 8bd8 8b450c 6a00 }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8bd8                 | mov                 ebx, eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   6a00                 | push                0

        $sequence_2 = { 8d85ecfdffff 59 57 50 ff15???????? }
            // n = 5, score = 100
            //   8d85ecfdffff         | lea                 eax, [ebp - 0x214]
            //   59                   | pop                 ecx
            //   57                   | push                edi
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_3 = { 57 56 68???????? ff7508 6a50 68???????? e8???????? }
            // n = 7, score = 100
            //   57                   | push                edi
            //   56                   | push                esi
            //   68????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a50                 | push                0x50
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_4 = { c68548ffffff0f c68549ffffff10 c6854affffff11 c6854bffffff12 c6854cffffff13 c6854dffffff14 }
            // n = 6, score = 100
            //   c68548ffffff0f       | mov                 byte ptr [ebp - 0xb8], 0xf
            //   c68549ffffff10       | mov                 byte ptr [ebp - 0xb7], 0x10
            //   c6854affffff11       | mov                 byte ptr [ebp - 0xb6], 0x11
            //   c6854bffffff12       | mov                 byte ptr [ebp - 0xb5], 0x12
            //   c6854cffffff13       | mov                 byte ptr [ebp - 0xb4], 0x13
            //   c6854dffffff14       | mov                 byte ptr [ebp - 0xb3], 0x14

        $sequence_5 = { 59 85c0 59 7576 a0???????? 6a7f 888580fdffff }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   59                   | pop                 ecx
            //   7576                 | jne                 0x78
            //   a0????????           |                     
            //   6a7f                 | push                0x7f
            //   888580fdffff         | mov                 byte ptr [ebp - 0x280], al

        $sequence_6 = { 888580fdffff 59 33c0 8dbd81fdffff }
            // n = 4, score = 100
            //   888580fdffff         | mov                 byte ptr [ebp - 0x280], al
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   8dbd81fdffff         | lea                 edi, [ebp - 0x27f]

        $sequence_7 = { ff35???????? e8???????? 2b35???????? 83c40c 3bf3 7f1a 391d???????? }
            // n = 7, score = 100
            //   ff35????????         |                     
            //   e8????????           |                     
            //   2b35????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   3bf3                 | cmp                 esi, ebx
            //   7f1a                 | jg                  0x1c
            //   391d????????         |                     

        $sequence_8 = { c3 55 8bec b808200000 e8???????? 53 56 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b808200000           | mov                 eax, 0x2008
            //   e8????????           |                     
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_9 = { 85c0 742b 53 ff15???????? 50 }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   742b                 | je                  0x2d
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   50                   | push                eax

    condition:
        7 of them and filesize < 131072
}
