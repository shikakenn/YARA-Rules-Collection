rule win_ryuk_stealer_auto {

    meta:
        id = "4bwlT4kciYY3Zhw8YWMoSR"
        fingerprint = "v1_sha256_f104c51f76af6a34fecb95d90a97bc0fef4b38e853341fac8b68ac59b1274295"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.ryuk_stealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk_stealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff15???????? 8bf0 ff15???????? 85c0 7518 85f6 7414 }
            // n = 7, score = 800
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7518                 | jne                 0x1a
            //   85f6                 | test                esi, esi
            //   7414                 | je                  0x16

        $sequence_1 = { 8bcb 0f44f2 42 8d7902 }
            // n = 4, score = 800
            //   8bcb                 | mov                 ecx, ebx
            //   0f44f2               | cmove               esi, edx
            //   42                   | inc                 edx
            //   8d7902               | lea                 edi, [ecx + 2]

        $sequence_2 = { 83ff01 755d 8bcb e8???????? }
            // n = 4, score = 800
            //   83ff01               | cmp                 edi, 1
            //   755d                 | jne                 0x5f
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_3 = { f7f9 81c2a8610000 52 ff15???????? }
            // n = 4, score = 800
            //   f7f9                 | idiv                ecx
            //   81c2a8610000         | add                 edx, 0x61a8
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_4 = { 99 b9a0860100 f7f9 81c2a8610000 52 }
            // n = 5, score = 800
            //   99                   | cdq                 
            //   b9a0860100           | mov                 ecx, 0x186a0
            //   f7f9                 | idiv                ecx
            //   81c2a8610000         | add                 edx, 0x61a8
            //   52                   | push                edx

        $sequence_5 = { f7f1 8bf2 e8???????? 8bc8 33d2 8bc6 f7f1 }
            // n = 7, score = 800
            //   f7f1                 | div                 ecx
            //   8bf2                 | mov                 esi, edx
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   33d2                 | xor                 edx, edx
            //   8bc6                 | mov                 eax, esi
            //   f7f1                 | div                 ecx

        $sequence_6 = { c1e902 f3a5 8bca 83e103 f3a4 6a64 8d44245c }
            // n = 7, score = 800
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bca                 | mov                 ecx, edx
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   6a64                 | push                0x64
            //   8d44245c             | lea                 eax, [esp + 0x5c]

        $sequence_7 = { 8a443701 3c2f 7408 3c2d }
            // n = 4, score = 800
            //   8a443701             | mov                 al, byte ptr [edi + esi + 1]
            //   3c2f                 | cmp                 al, 0x2f
            //   7408                 | je                  0xa
            //   3c2d                 | cmp                 al, 0x2d

        $sequence_8 = { ff15???????? 83f805 740a b9???????? }
            // n = 4, score = 800
            //   ff15????????         |                     
            //   83f805               | cmp                 eax, 5
            //   740a                 | je                  0xc
            //   b9????????           |                     

        $sequence_9 = { 8d45e0 50 8d85b4fdffff 50 }
            // n = 4, score = 800
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   8d85b4fdffff         | lea                 eax, [ebp - 0x24c]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 368640
}
