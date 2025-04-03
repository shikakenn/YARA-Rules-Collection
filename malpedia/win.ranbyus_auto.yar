rule win_ranbyus_auto {

    meta:
        id = "Ksd7kREIg2bfmsELNNNIV"
        fingerprint = "v1_sha256_330e6be70ed45bf6b2dbed5046fb65bb22576b8352f6395b54bf453a6f591094"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.ranbyus."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ranbyus"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { a1???????? 85c0 751c 6a04 e8???????? }
            // n = 5, score = 1100
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   751c                 | jne                 0x1e
            //   6a04                 | push                4
            //   e8????????           |                     

        $sequence_1 = { 6a01 6a00 68???????? 68???????? 68???????? e8???????? }
            // n = 6, score = 1100
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   68????????           |                     
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_2 = { e8???????? 59 8b4e05 89410b 8b4605 39780b 7407 }
            // n = 7, score = 1100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4e05               | mov                 ecx, dword ptr [esi + 5]
            //   89410b               | mov                 dword ptr [ecx + 0xb], eax
            //   8b4605               | mov                 eax, dword ptr [esi + 5]
            //   39780b               | cmp                 dword ptr [eax + 0xb], edi
            //   7407                 | je                  9

        $sequence_3 = { 57 e8???????? 8b7f28 59 }
            // n = 4, score = 1100
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b7f28               | mov                 edi, dword ptr [edi + 0x28]
            //   59                   | pop                 ecx

        $sequence_4 = { 0bc8 51 e8???????? 8bf8 59 85ff 7422 }
            // n = 7, score = 1100
            //   0bc8                 | or                  ecx, eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   59                   | pop                 ecx
            //   85ff                 | test                edi, edi
            //   7422                 | je                  0x24

        $sequence_5 = { a807 752a c1e802 85c0 }
            // n = 4, score = 1100
            //   a807                 | test                al, 7
            //   752a                 | jne                 0x2c
            //   c1e802               | shr                 eax, 2
            //   85c0                 | test                eax, eax

        $sequence_6 = { c20400 53 55 6a0c 8be9 e8???????? 8bd8 }
            // n = 7, score = 1100
            //   c20400               | ret                 4
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   6a0c                 | push                0xc
            //   8be9                 | mov                 ebp, ecx
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_7 = { e8???????? e8???????? 8bce e8???????? 6a03 }
            // n = 5, score = 1100
            //   e8????????           |                     
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   6a03                 | push                3

        $sequence_8 = { 5e eb02 33c0 83630400 83630800 }
            // n = 5, score = 1100
            //   5e                   | pop                 esi
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   83630400             | and                 dword ptr [ebx + 4], 0
            //   83630800             | and                 dword ptr [ebx + 8], 0

        $sequence_9 = { 5f 5e 5b 5d c21000 57 ff760c }
            // n = 7, score = 1100
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c21000               | ret                 0x10
            //   57                   | push                edi
            //   ff760c               | push                dword ptr [esi + 0xc]

    condition:
        7 of them and filesize < 638976
}
