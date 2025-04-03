rule win_stuxnet_auto {

    meta:
        id = "5MdPnK9HmkdLPYE1oYawCZ"
        fingerprint = "v1_sha256_2029a68bba02441740da4f3ef9a391375e59b29e674666cb41a7f24fda7b29c9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.stuxnet."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stuxnet"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? ff7508 8b45ec 8b4008 ff75f0 03c6 50 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax

        $sequence_1 = { a1???????? 85c0 7507 b805400080 eb39 56 ff7518 }
            // n = 7, score = 200
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   b805400080           | mov                 eax, 0x80004005
            //   eb39                 | jmp                 0x3b
            //   56                   | push                esi
            //   ff7518               | push                dword ptr [ebp + 0x18]

        $sequence_2 = { ff760c e8???????? 59 6bdb38 8b4508 03d8 895e14 }
            // n = 7, score = 200
            //   ff760c               | push                dword ptr [esi + 0xc]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   6bdb38               | imul                ebx, ebx, 0x38
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   03d8                 | add                 ebx, eax
            //   895e14               | mov                 dword ptr [esi + 0x14], ebx

        $sequence_3 = { e8???????? eb08 ff7508 e8???????? 59 8b4df4 64890d00000000 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   eb08                 | jmp                 0xa
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_4 = { b8???????? c3 b8???????? e8???????? 56 8b7508 57 }
            // n = 7, score = 200
            //   b8????????           |                     
            //   c3                   | ret                 
            //   b8????????           |                     
            //   e8????????           |                     
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   57                   | push                edi

        $sequence_5 = { 6a24 e8???????? 59 8945ec 33f6 46 8975fc }
            // n = 7, score = 200
            //   6a24                 | push                0x24
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   33f6                 | xor                 esi, esi
            //   46                   | inc                 esi
            //   8975fc               | mov                 dword ptr [ebp - 4], esi

        $sequence_6 = { e8???????? 84c0 744b 68???????? 8d442440 50 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   744b                 | je                  0x4d
            //   68????????           |                     
            //   8d442440             | lea                 eax, [esp + 0x40]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { e8???????? 8945ec 8d45a8 50 e8???????? 8365fc00 8d45c4 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8d45a8               | lea                 eax, [ebp - 0x58]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   8d45c4               | lea                 eax, [ebp - 0x3c]

        $sequence_8 = { ff75e8 ff15???????? 3bc3 7505 e8???????? ffd0 85c0 }
            // n = 7, score = 200
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   ff15????????         |                     
            //   3bc3                 | cmp                 eax, ebx
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8d55d8 52 ff7510 ff750c ff7508 51 50 }
            // n = 7, score = 200
            //   8d55d8               | lea                 edx, [ebp - 0x28]
            //   52                   | push                edx
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   50                   | push                eax

    condition:
        7 of them and filesize < 2495488
}
