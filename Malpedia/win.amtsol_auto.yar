rule win_amtsol_auto {

    meta:
        id = "1kspXPcXe2uPkPlnuc0CMe"
        fingerprint = "v1_sha256_0a770dc5a932b1002072b79c5d73e29f3137e050ecc56387df95b6b6024c1535"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.amtsol."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.amtsol"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d85e8fbffff 50 e8???????? 83c40c 6a10 5f 3bc7 }
            // n = 7, score = 100
            //   8d85e8fbffff         | lea                 eax, [ebp - 0x418]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a10                 | push                0x10
            //   5f                   | pop                 edi
            //   3bc7                 | cmp                 eax, edi

        $sequence_1 = { 8dbe54030000 8bcf e8???????? 8d8e8c030000 }
            // n = 4, score = 100
            //   8dbe54030000         | lea                 edi, [esi + 0x354]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8d8e8c030000         | lea                 ecx, [esi + 0x38c]

        $sequence_2 = { ff75f0 e8???????? 59 395df4 7409 ff75f4 e8???????? }
            // n = 7, score = 100
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   395df4               | cmp                 dword ptr [ebp - 0xc], ebx
            //   7409                 | je                  0xb
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     

        $sequence_3 = { 83c40c 8946e8 85c0 752b 015d0c 47 3b7df8 }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8946e8               | mov                 dword ptr [esi - 0x18], eax
            //   85c0                 | test                eax, eax
            //   752b                 | jne                 0x2d
            //   015d0c               | add                 dword ptr [ebp + 0xc], ebx
            //   47                   | inc                 edi
            //   3b7df8               | cmp                 edi, dword ptr [ebp - 8]

        $sequence_4 = { 8bd8 035df0 8b45f0 33c3 2345f8 6a14 3345f0 }
            // n = 7, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   035df0               | add                 ebx, dword ptr [ebp - 0x10]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   33c3                 | xor                 eax, ebx
            //   2345f8               | and                 eax, dword ptr [ebp - 8]
            //   6a14                 | push                0x14
            //   3345f0               | xor                 eax, dword ptr [ebp - 0x10]

        $sequence_5 = { 8b757c 8b8580000000 8945dc 33db 895de4 895dd8 33ff }
            // n = 7, score = 100
            //   8b757c               | mov                 esi, dword ptr [ebp + 0x7c]
            //   8b8580000000         | mov                 eax, dword ptr [ebp + 0x80]
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   33db                 | xor                 ebx, ebx
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   895dd8               | mov                 dword ptr [ebp - 0x28], ebx
            //   33ff                 | xor                 edi, edi

        $sequence_6 = { 57 e8???????? 59 59 85c0 740d 8bf8 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   8bf8                 | mov                 edi, eax

        $sequence_7 = { 837d0800 53 56 8bf1 0f84aa000000 8b5d0c 85db }
            // n = 7, score = 100
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   0f84aa000000         | je                  0xb0
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   85db                 | test                ebx, ebx

        $sequence_8 = { 50 8d459c 50 68???????? e8???????? 83c414 3bc3 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   3bc3                 | cmp                 eax, ebx

        $sequence_9 = { 85c0 7428 837dfc00 7413 0fb745f8 50 ff75fc }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7428                 | je                  0x2a
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   7413                 | je                  0x15
            //   0fb745f8             | movzx               eax, word ptr [ebp - 8]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 335872
}
