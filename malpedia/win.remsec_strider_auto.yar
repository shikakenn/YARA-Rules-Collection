rule win_remsec_strider_auto {

    meta:
        id = "6F5tZKEQTG6KLwz1YGfdfr"
        fingerprint = "v1_sha256_5867115fb4def3b071a615d256fa1eed563d65b07c2fc4fbbe85633ada999202"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.remsec_strider."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.remsec_strider"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c9 c20800 33c0 40 83f920 }
            // n = 5, score = 200
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   83f920               | cmp                 ecx, 0x20

        $sequence_1 = { 50 8d8558faffff 68c8000000 50 ff15???????? 50 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   8d8558faffff         | lea                 eax, [ebp - 0x5a8]
            //   68c8000000           | push                0xc8
            //   50                   | push                eax
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_2 = { 85c0 7444 8b4818 85c9 7405 }
            // n = 5, score = 200
            //   85c0                 | test                eax, eax
            //   7444                 | je                  0x46
            //   8b4818               | mov                 ecx, dword ptr [eax + 0x18]
            //   85c9                 | test                ecx, ecx
            //   7405                 | je                  7

        $sequence_3 = { 57 ff5608 85c0 74a7 33c0 40 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   ff5608               | call                dword ptr [esi + 8]
            //   85c0                 | test                eax, eax
            //   74a7                 | je                  0xffffffa9
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax

        $sequence_4 = { 6a0c 58 c3 83f927 7412 83f950 }
            // n = 6, score = 200
            //   6a0c                 | push                0xc
            //   58                   | pop                 eax
            //   c3                   | ret                 
            //   83f927               | cmp                 ecx, 0x27
            //   7412                 | je                  0x14
            //   83f950               | cmp                 ecx, 0x50

        $sequence_5 = { 7433 48 742c 48 7413 48 7409 }
            // n = 7, score = 200
            //   7433                 | je                  0x35
            //   48                   | dec                 eax
            //   742c                 | je                  0x2e
            //   48                   | dec                 eax
            //   7413                 | je                  0x15
            //   48                   | dec                 eax
            //   7409                 | je                  0xb

        $sequence_6 = { 50 e8???????? 83c418 8d85ecfeffff 50 ff15???????? }
            // n = 6, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   8d85ecfeffff         | lea                 eax, [ebp - 0x114]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_7 = { dfe0 ddd9 750a f6c441 }
            // n = 4, score = 200
            //   dfe0                 | fnstsw              ax
            //   ddd9                 | fstp                st(1)
            //   750a                 | jne                 0xc
            //   f6c441               | test                ah, 0x41

        $sequence_8 = { 49 7414 49 7411 49 49 7409 }
            // n = 7, score = 200
            //   49                   | dec                 ecx
            //   7414                 | je                  0x16
            //   49                   | dec                 ecx
            //   7411                 | je                  0x13
            //   49                   | dec                 ecx
            //   49                   | dec                 ecx
            //   7409                 | je                  0xb

        $sequence_9 = { c20400 56 8bf1 6808040000 8d4614 }
            // n = 5, score = 200
            //   c20400               | ret                 4
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   6808040000           | push                0x408
            //   8d4614               | lea                 eax, [esi + 0x14]

    condition:
        7 of them and filesize < 344064
}
