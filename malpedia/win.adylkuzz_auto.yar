rule win_adylkuzz_auto {

    meta:
        id = "3bZtxzLilM8Pcw8RGBBJrk"
        fingerprint = "v1_sha256_a5ced23a2b6a73ae95a9a6a65000eaf7907a66a0c142cf3646367ed2ee46dd3d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.adylkuzz."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adylkuzz"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 89ea 89f0 81ca29000200 e8???????? 8b542408 89c5 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89ea                 | mov                 edx, ebp
            //   89f0                 | mov                 eax, esi
            //   81ca29000200         | or                  edx, 0x20029
            //   e8????????           |                     
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   89c5                 | mov                 ebp, eax

        $sequence_1 = { 0f8579ffffff 8b4508 89442404 8b85d4feffff 890424 e8???????? 85c0 }
            // n = 7, score = 100
            //   0f8579ffffff         | jne                 0xffffff7f
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   8b85d4feffff         | mov                 eax, dword ptr [ebp - 0x12c]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_2 = { f5 663bf6 f7c7b40e1e7c 33c3 85d9 f9 6681ff3c41 }
            // n = 7, score = 100
            //   f5                   | cmc                 
            //   663bf6               | cmp                 si, si
            //   f7c7b40e1e7c         | test                edi, 0x7c1e0eb4
            //   33c3                 | xor                 eax, ebx
            //   85d9                 | test                ecx, ebx
            //   f9                   | stc                 
            //   6681ff3c41           | cmp                 di, 0x413c

        $sequence_3 = { c744240800000000 89442404 e8???????? 83c41c 5b 5e 5f }
            // n = 7, score = 100
            //   c744240800000000     | mov                 dword ptr [esp + 8], 0
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi

        $sequence_4 = { e9???????? 3dfc000000 7610 3bab98000000 7208 89f0 83c880 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   3dfc000000           | cmp                 eax, 0xfc
            //   7610                 | jbe                 0x12
            //   3bab98000000         | cmp                 ebp, dword ptr [ebx + 0x98]
            //   7208                 | jb                  0xa
            //   89f0                 | mov                 eax, esi
            //   83c880               | or                  eax, 0xffffff80

        $sequence_5 = { c744241001000000 89c7 eb20 8b4500 8d5008 89d8 e8???????? }
            // n = 7, score = 100
            //   c744241001000000     | mov                 dword ptr [esp + 0x10], 1
            //   89c7                 | mov                 edi, eax
            //   eb20                 | jmp                 0x22
            //   8b4500               | mov                 eax, dword ptr [ebp]
            //   8d5008               | lea                 edx, [eax + 8]
            //   89d8                 | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_6 = { c7431001000000 89f7 31c0 83c9ff 89f2 f2ae 89d8 }
            // n = 7, score = 100
            //   c7431001000000       | mov                 dword ptr [ebx + 0x10], 1
            //   89f7                 | mov                 edi, esi
            //   31c0                 | xor                 eax, eax
            //   83c9ff               | or                  ecx, 0xffffffff
            //   89f2                 | mov                 edx, esi
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   89d8                 | mov                 eax, ebx

        $sequence_7 = { e8???????? 85c0 7473 89d8 8b33 e8???????? 31d2 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7473                 | je                  0x75
            //   89d8                 | mov                 eax, ebx
            //   8b33                 | mov                 esi, dword ptr [ebx]
            //   e8????????           |                     
            //   31d2                 | xor                 edx, edx

        $sequence_8 = { f8 6681fd5547 34ad fec8 32d8 8dadfeffffff 3be1 }
            // n = 7, score = 100
            //   f8                   | clc                 
            //   6681fd5547           | cmp                 bp, 0x4755
            //   34ad                 | xor                 al, 0xad
            //   fec8                 | dec                 al
            //   32d8                 | xor                 bl, al
            //   8dadfeffffff         | lea                 ebp, [ebp - 2]
            //   3be1                 | cmp                 esp, ecx

        $sequence_9 = { eb24 8d4aff 31c0 85d1 751b c6437523 0fbdd2 }
            // n = 7, score = 100
            //   eb24                 | jmp                 0x26
            //   8d4aff               | lea                 ecx, [edx - 1]
            //   31c0                 | xor                 eax, eax
            //   85d1                 | test                ecx, edx
            //   751b                 | jne                 0x1d
            //   c6437523             | mov                 byte ptr [ebx + 0x75], 0x23
            //   0fbdd2               | bsr                 edx, edx

    condition:
        7 of them and filesize < 6438912
}
