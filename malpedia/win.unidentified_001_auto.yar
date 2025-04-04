rule win_unidentified_001_auto {

    meta:
        id = "6eEzkfEGfWuvyaV0U5v6nb"
        fingerprint = "v1_sha256_81eac2ebab9009f83937098bc70d4667382c46b0593ed411973170676729479d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_001."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_001"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 741c 83e80a 0f84c6fcffff 2def000000 }
            // n = 4, score = 100
            //   741c                 | je                  0x1e
            //   83e80a               | sub                 eax, 0xa
            //   0f84c6fcffff         | je                  0xfffffccc
            //   2def000000           | sub                 eax, 0xef

        $sequence_1 = { 8d85d4fdffff 50 56 e8???????? 85c0 75da 32c0 }
            // n = 7, score = 100
            //   8d85d4fdffff         | lea                 eax, [ebp - 0x22c]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   75da                 | jne                 0xffffffdc
            //   32c0                 | xor                 al, al

        $sequence_2 = { 832600 ff7508 e8???????? 85c0 7d0d 3d02400080 7406 }
            // n = 7, score = 100
            //   832600               | and                 dword ptr [esi], 0
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7d0d                 | jge                 0xf
            //   3d02400080           | cmp                 eax, 0x80004002
            //   7406                 | je                  8

        $sequence_3 = { 56 ff5078 85c0 7d0c 68???????? 56 50 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff5078               | call                dword ptr [eax + 0x78]
            //   85c0                 | test                eax, eax
            //   7d0c                 | jge                 0xe
            //   68????????           |                     
            //   56                   | push                esi
            //   50                   | push                eax

        $sequence_4 = { 8b4d10 85c9 7405 e8???????? 8bc6 5e c9 }
            // n = 7, score = 100
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   85c9                 | test                ecx, ecx
            //   7405                 | je                  7
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c9                   | leave               

        $sequence_5 = { 8bec 83ec34 53 56 57 6800040000 6a00 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec34               | sub                 esp, 0x34
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   6800040000           | push                0x400
            //   6a00                 | push                0

        $sequence_6 = { 57 e8???????? 8d45d4 50 6a07 57 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   6a07                 | push                7
            //   57                   | push                edi

        $sequence_7 = { 0f8468feffff 3d4b475a00 0f845dfeffff 3d4d4f5a00 0f8507f9ffff 8325????????00 e9???????? }
            // n = 7, score = 100
            //   0f8468feffff         | je                  0xfffffe6e
            //   3d4b475a00           | cmp                 eax, 0x5a474b
            //   0f845dfeffff         | je                  0xfffffe63
            //   3d4d4f5a00           | cmp                 eax, 0x5a4f4d
            //   0f8507f9ffff         | jne                 0xfffff90d
            //   8325????????00       |                     
            //   e9????????           |                     

        $sequence_8 = { 0f85ebfcffff c705????????13000000 e9???????? c705????????06000000 e9???????? }
            // n = 5, score = 100
            //   0f85ebfcffff         | jne                 0xfffffcf1
            //   c705????????13000000     |     
            //   e9????????           |                     
            //   c705????????06000000     |     
            //   e9????????           |                     

        $sequence_9 = { 3bc1 7767 74d3 2d434d5200 }
            // n = 4, score = 100
            //   3bc1                 | cmp                 eax, ecx
            //   7767                 | ja                  0x69
            //   74d3                 | je                  0xffffffd5
            //   2d434d5200           | sub                 eax, 0x524d43

    condition:
        7 of them and filesize < 65536
}
