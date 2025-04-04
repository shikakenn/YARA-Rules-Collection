rule win_icefog_auto {

    meta:
        id = "5wou0nqcqkZNt1Qws9xtzZ"
        fingerprint = "v1_sha256_487424ea94183e95a7a3963011eba4b3e92a928a4a25ab7f953a01dda9030416"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.icefog."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icefog"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 68???????? 56 52 e8???????? 83c414 e9???????? 33c0 }
            // n = 7, score = 200
            //   68????????           |                     
            //   56                   | push                esi
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 50 8b82a8000000 6a00 51 50 e8???????? 8b45fc }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8b82a8000000         | mov                 eax, dword ptr [edx + 0xa8]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_2 = { ba00060000 660bc2 6689431c 8b45fc 5f 894314 894324 }
            // n = 7, score = 200
            //   ba00060000           | mov                 edx, 0x600
            //   660bc2               | or                  ax, dx
            //   6689431c             | mov                 word ptr [ebx + 0x1c], ax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   5f                   | pop                 edi
            //   894314               | mov                 dword ptr [ebx + 0x14], eax
            //   894324               | mov                 dword ptr [ebx + 0x24], eax

        $sequence_3 = { 8b460c 8bda 99 03c8 8b4614 13da 99 }
            // n = 7, score = 200
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   8bda                 | mov                 ebx, edx
            //   99                   | cdq                 
            //   03c8                 | add                 ecx, eax
            //   8b4614               | mov                 eax, dword ptr [esi + 0x14]
            //   13da                 | adc                 ebx, edx
            //   99                   | cdq                 

        $sequence_4 = { e9???????? 8a4602 83c602 84c0 7416 8d642400 3c2a }
            // n = 7, score = 200
            //   e9????????           |                     
            //   8a4602               | mov                 al, byte ptr [esi + 2]
            //   83c602               | add                 esi, 2
            //   84c0                 | test                al, al
            //   7416                 | je                  0x18
            //   8d642400             | lea                 esp, [esp]
            //   3c2a                 | cmp                 al, 0x2a

        $sequence_5 = { 8b4304 6a01 50 897df4 e8???????? 8b03 83c414 }
            // n = 7, score = 200
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   6a01                 | push                1
            //   50                   | push                eax
            //   897df4               | mov                 dword ptr [ebp - 0xc], edi
            //   e8????????           |                     
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   83c414               | add                 esp, 0x14

        $sequence_6 = { e8???????? 83c40c 5d c3 b8???????? c3 a1???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   b8????????           |                     
            //   c3                   | ret                 
            //   a1????????           |                     

        $sequence_7 = { e8???????? 83c40c 8bf8 eb03 8b5df0 8b45fc 85c0 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8bf8                 | mov                 edi, eax
            //   eb03                 | jmp                 5
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   85c0                 | test                eax, eax

        $sequence_8 = { 51 e8???????? 53 8bf0 8995b0feffff e8???????? 8bc8 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   e8????????           |                     
            //   53                   | push                ebx
            //   8bf0                 | mov                 esi, eax
            //   8995b0feffff         | mov                 dword ptr [ebp - 0x150], edx
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_9 = { 50 68???????? 56 e8???????? 8bd8 83c420 85db }
            // n = 7, score = 200
            //   50                   | push                eax
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   83c420               | add                 esp, 0x20
            //   85db                 | test                ebx, ebx

    condition:
        7 of them and filesize < 1187840
}
