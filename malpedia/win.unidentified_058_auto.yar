rule win_unidentified_058_auto {

    meta:
        id = "5BlUMtVmpcBWXoFSvDKk9f"
        fingerprint = "v1_sha256_6fcdcaa99e58b3f3a7cd7f02d4e9515bb2260cce588c992588f9226a5eb8cea1"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_058"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 8b4634 8b4078 baeaf0cf00 e8???????? baffffff1f 8b4634 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4634               | mov                 eax, dword ptr [esi + 0x34]
            //   8b4078               | mov                 eax, dword ptr [eax + 0x78]
            //   baeaf0cf00           | mov                 edx, 0xcff0ea
            //   e8????????           |                     
            //   baffffff1f           | mov                 edx, 0x1fffffff
            //   8b4634               | mov                 eax, dword ptr [esi + 0x34]

        $sequence_1 = { e8???????? 8b4dfc 41 8b55f8 83c204 8b06 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   41                   | inc                 ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   83c204               | add                 edx, 4
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   e8????????           |                     

        $sequence_2 = { 0f85f3000000 80bbe903000000 0f84e6000000 8bd6 8bc3 e8???????? 80b8a402000000 }
            // n = 7, score = 100
            //   0f85f3000000         | jne                 0xf9
            //   80bbe903000000       | cmp                 byte ptr [ebx + 0x3e9], 0
            //   0f84e6000000         | je                  0xec
            //   8bd6                 | mov                 edx, esi
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   80b8a402000000       | cmp                 byte ptr [eax + 0x2a4], 0

        $sequence_3 = { e8???????? 5b c3 badaeafd00 8bc3 e8???????? ba88aee400 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   badaeafd00           | mov                 edx, 0xfdeada
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   ba88aee400           | mov                 edx, 0xe4ae88

        $sequence_4 = { d1fa 7903 83d200 0155f7 8b4dfb 8b55f7 8b18 }
            // n = 7, score = 100
            //   d1fa                 | sar                 edx, 1
            //   7903                 | jns                 5
            //   83d200               | adc                 edx, 0
            //   0155f7               | add                 dword ptr [ebp - 9], edx
            //   8b4dfb               | mov                 ecx, dword ptr [ebp - 5]
            //   8b55f7               | mov                 edx, dword ptr [ebp - 9]
            //   8b18                 | mov                 ebx, dword ptr [eax]

        $sequence_5 = { 9b 8b85c8feffff 2b85c0feffff 89852cfeffff db852cfeffff d99d48ffffff 9b }
            // n = 7, score = 100
            //   9b                   | wait                
            //   8b85c8feffff         | mov                 eax, dword ptr [ebp - 0x138]
            //   2b85c0feffff         | sub                 eax, dword ptr [ebp - 0x140]
            //   89852cfeffff         | mov                 dword ptr [ebp - 0x1d4], eax
            //   db852cfeffff         | fild                dword ptr [ebp - 0x1d4]
            //   d99d48ffffff         | fstp                dword ptr [ebp - 0xb8]
            //   9b                   | wait                

        $sequence_6 = { ff5140 8b460c 50 8b4618 50 8b461c 50 }
            // n = 7, score = 100
            //   ff5140               | call                dword ptr [ecx + 0x40]
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   50                   | push                eax
            //   8b4618               | mov                 eax, dword ptr [esi + 0x18]
            //   50                   | push                eax
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   50                   | push                eax

        $sequence_7 = { 8bc6 e8???????? ba62000000 8bc6 e8???????? ba14000000 8bc6 }
            // n = 7, score = 100
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   ba62000000           | mov                 edx, 0x62
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   ba14000000           | mov                 edx, 0x14
            //   8bc6                 | mov                 eax, esi

        $sequence_8 = { 037db4 037dec 897db4 ff4df0 eb36 8b45b4 03c7 }
            // n = 7, score = 100
            //   037db4               | add                 edi, dword ptr [ebp - 0x4c]
            //   037dec               | add                 edi, dword ptr [ebp - 0x14]
            //   897db4               | mov                 dword ptr [ebp - 0x4c], edi
            //   ff4df0               | dec                 dword ptr [ebp - 0x10]
            //   eb36                 | jmp                 0x38
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   03c7                 | add                 eax, edi

        $sequence_9 = { db459c 83c4fc d91c24 9b 6a00 680000b442 8bc6 }
            // n = 7, score = 100
            //   db459c               | fild                dword ptr [ebp - 0x64]
            //   83c4fc               | add                 esp, -4
            //   d91c24               | fstp                dword ptr [esp]
            //   9b                   | wait                
            //   6a00                 | push                0
            //   680000b442           | push                0x42b40000
            //   8bc6                 | mov                 eax, esi

    condition:
        7 of them and filesize < 6348800
}
