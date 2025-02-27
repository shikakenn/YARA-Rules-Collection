rule win_royalcli_auto {

    meta:
        id = "5exMeTWjv2tTephyat9UH1"
        fingerprint = "v1_sha256_3f942fc64e71d9989fa602e154f4016ccbdc8b8d4e7f9551bd6f613b1bb3b100"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.royalcli."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royalcli"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d8dfcfeffff 68???????? 51 e8???????? 83c408 e9???????? 8bc6 }
            // n = 7, score = 100
            //   8d8dfcfeffff         | lea                 ecx, [ebp - 0x104]
            //   68????????           |                     
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   e9????????           |                     
            //   8bc6                 | mov                 eax, esi

        $sequence_1 = { 8b9db0feffff 83c410 85c0 0f8458feffff 8b95e8feffff 8b85ecfeffff 8bcf }
            // n = 7, score = 100
            //   8b9db0feffff         | mov                 ebx, dword ptr [ebp - 0x150]
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   0f8458feffff         | je                  0xfffffe5e
            //   8b95e8feffff         | mov                 edx, dword ptr [ebp - 0x118]
            //   8b85ecfeffff         | mov                 eax, dword ptr [ebp - 0x114]
            //   8bcf                 | mov                 ecx, edi

        $sequence_2 = { eb1d 0fb6043e c1e802 8a9020144100 }
            // n = 4, score = 100
            //   eb1d                 | jmp                 0x1f
            //   0fb6043e             | movzx               eax, byte ptr [esi + edi]
            //   c1e802               | shr                 eax, 2
            //   8a9020144100         | mov                 dl, byte ptr [eax + 0x411420]

        $sequence_3 = { 8d85f4feffff 50 ffd6 5e 8b4dfc 33cd b801000000 }
            // n = 7, score = 100
            //   8d85f4feffff         | lea                 eax, [ebp - 0x10c]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   5e                   | pop                 esi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp
            //   b801000000           | mov                 eax, 1

        $sequence_4 = { 889c3dc0fdffff 47 8bd6 8bf1 }
            // n = 4, score = 100
            //   889c3dc0fdffff       | mov                 byte ptr [ebp + edi - 0x240], bl
            //   47                   | inc                 edi
            //   8bd6                 | mov                 edx, esi
            //   8bf1                 | mov                 esi, ecx

        $sequence_5 = { 80bc0500ffffff5c 7403 48 79f3 40 b9fa000000 }
            // n = 6, score = 100
            //   80bc0500ffffff5c     | cmp                 byte ptr [ebp + eax - 0x100], 0x5c
            //   7403                 | je                  5
            //   48                   | dec                 eax
            //   79f3                 | jns                 0xfffffff5
            //   40                   | inc                 eax
            //   b9fa000000           | mov                 ecx, 0xfa

        $sequence_6 = { 52 ff15???????? 8bc6 8b4dfc 33cd }
            // n = 5, score = 100
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8bc6                 | mov                 eax, esi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp

        $sequence_7 = { 8bf2 f3a5 8bc8 83e103 f3a4 8bbd84f7ffff 85ff }
            // n = 7, score = 100
            //   8bf2                 | mov                 esi, edx
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8bbd84f7ffff         | mov                 edi, dword ptr [ebp - 0x87c]
            //   85ff                 | test                edi, edi

        $sequence_8 = { 7521 8b55fc 6a04 8d4df8 51 }
            // n = 5, score = 100
            //   7521                 | jne                 0x23
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   6a04                 | push                4
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   51                   | push                ecx

        $sequence_9 = { 8b4508 53 56 68???????? 50 8bf1 e8???????? }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   53                   | push                ebx
            //   56                   | push                esi
            //   68????????           |                     
            //   50                   | push                eax
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     

    condition:
        7 of them and filesize < 204800
}
