rule win_unidentified_006_auto {

    meta:
        id = "4WF6gnuHp4ngUpZ1CHTD2r"
        fingerprint = "v1_sha256_dd723dd2c53afa22a9c28d9c9c06ec724a63cc0cfcf78b59a425b4cdf0fd8bc1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_006."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_006"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3907 7417 833e00 7408 ff36 e8???????? 59 }
            // n = 7, score = 100
            //   3907                 | cmp                 dword ptr [edi], eax
            //   7417                 | je                  0x19
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7408                 | je                  0xa
            //   ff36                 | push                dword ptr [esi]
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_1 = { 6a00 8d45fc 897dfc 50 8d45f8 50 6a00 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   50                   | push                eax
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_2 = { 85c9 7410 8b55f4 85d2 7409 e8???????? 894708 }
            // n = 7, score = 100
            //   85c9                 | test                ecx, ecx
            //   7410                 | je                  0x12
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   85d2                 | test                edx, edx
            //   7409                 | je                  0xb
            //   e8????????           |                     
            //   894708               | mov                 dword ptr [edi + 8], eax

        $sequence_3 = { 8bf0 57 56 e8???????? 83c410 33c0 }
            // n = 6, score = 100
            //   8bf0                 | mov                 esi, eax
            //   57                   | push                edi
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 85f6 7410 57 8b7d0c 2bf8 }
            // n = 5, score = 100
            //   85f6                 | test                esi, esi
            //   7410                 | je                  0x12
            //   57                   | push                edi
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   2bf8                 | sub                 edi, eax

        $sequence_5 = { 0fb6875c204000 47 03c6 83c603 25ff000000 }
            // n = 5, score = 100
            //   0fb6875c204000       | movzx               eax, byte ptr [edi + 0x40205c]
            //   47                   | inc                 edi
            //   03c6                 | add                 eax, esi
            //   83c603               | add                 esi, 3
            //   25ff000000           | and                 eax, 0xff

        $sequence_6 = { eb45 8b7510 85f6 743c }
            // n = 4, score = 100
            //   eb45                 | jmp                 0x47
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   85f6                 | test                esi, esi
            //   743c                 | je                  0x3e

        $sequence_7 = { 8b4dfc 83c40c 8bf7 8bd7 85c9 7421 83ff0c }
            // n = 7, score = 100
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c40c               | add                 esp, 0xc
            //   8bf7                 | mov                 esi, edi
            //   8bd7                 | mov                 edx, edi
            //   85c9                 | test                ecx, ecx
            //   7421                 | je                  0x23
            //   83ff0c               | cmp                 edi, 0xc

        $sequence_8 = { 33ff 53 ff15???????? 53 ff15???????? }
            // n = 5, score = 100
            //   33ff                 | xor                 edi, edi
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_9 = { 57 6a40 8bc2 33ff 6800300000 50 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   6a40                 | push                0x40
            //   8bc2                 | mov                 eax, edx
            //   33ff                 | xor                 edi, edi
            //   6800300000           | push                0x3000
            //   50                   | push                eax

    condition:
        7 of them and filesize < 40960
}
