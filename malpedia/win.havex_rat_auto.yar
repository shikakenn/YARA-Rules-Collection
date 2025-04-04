rule win_havex_rat_auto {

    meta:
        id = "MWbSobSU6VpgZ6lgcwu1u"
        fingerprint = "v1_sha256_051d7a160bda27ce92537b0acc638ab1e006b209a8b64890cf910d9cca719a54"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.havex_rat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.havex_rat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff4dc8 8d4701 8906 83ee04 837dc800 7dcd }
            // n = 6, score = 100
            //   ff4dc8               | dec                 dword ptr [ebp - 0x38]
            //   8d4701               | lea                 eax, [edi + 1]
            //   8906                 | mov                 dword ptr [esi], eax
            //   83ee04               | sub                 esi, 4
            //   837dc800             | cmp                 dword ptr [ebp - 0x38], 0
            //   7dcd                 | jge                 0xffffffcf

        $sequence_1 = { e8???????? 33ff 895dfc 47 68???????? 8d8d6cffffff }
            // n = 6, score = 100
            //   e8????????           |                     
            //   33ff                 | xor                 edi, edi
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   47                   | inc                 edi
            //   68????????           |                     
            //   8d8d6cffffff         | lea                 ecx, [ebp - 0x94]

        $sequence_2 = { c74128e41b0510 c7413c901b0510 e8???????? 5e c3 8d4e28 c706???????? }
            // n = 7, score = 100
            //   c74128e41b0510       | mov                 dword ptr [ecx + 0x28], 0x10051be4
            //   c7413c901b0510       | mov                 dword ptr [ecx + 0x3c], 0x10051b90
            //   e8????????           |                     
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8d4e28               | lea                 ecx, [esi + 0x28]
            //   c706????????         |                     

        $sequence_3 = { ff750c ff7508 50 8b4510 e8???????? 83c414 c9 }
            // n = 7, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   50                   | push                eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   c9                   | leave               

        $sequence_4 = { ff4dd8 8945ec 8b4dec c7430428000000 eb37 8b03 83780400 }
            // n = 7, score = 100
            //   ff4dd8               | dec                 dword ptr [ebp - 0x28]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   c7430428000000       | mov                 dword ptr [ebx + 4], 0x28
            //   eb37                 | jmp                 0x39
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   83780400             | cmp                 dword ptr [eax + 4], 0

        $sequence_5 = { 68???????? 8d8da8f7ffff e8???????? c645fc03 eb98 8d85c4f7ffff }
            // n = 6, score = 100
            //   68????????           |                     
            //   8d8da8f7ffff         | lea                 ecx, [ebp - 0x858]
            //   e8????????           |                     
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   eb98                 | jmp                 0xffffff9a
            //   8d85c4f7ffff         | lea                 eax, [ebp - 0x83c]

        $sequence_6 = { 83c040 50 e8???????? 83c414 8b8d84010000 5f 33cd }
            // n = 7, score = 100
            //   83c040               | add                 eax, 0x40
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8b8d84010000         | mov                 ecx, dword ptr [ebp + 0x184]
            //   5f                   | pop                 edi
            //   33cd                 | xor                 ecx, ebp

        $sequence_7 = { 56 8bf0 837e1808 57 7205 8b4604 eb03 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   837e1808             | cmp                 dword ptr [esi + 0x18], 8
            //   57                   | push                edi
            //   7205                 | jb                  7
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   eb03                 | jmp                 5

        $sequence_8 = { 039798c90000 8b7ddc 0fb77c7b3c 897de0 81c7990c0000 c1e704 030437 }
            // n = 7, score = 100
            //   039798c90000         | add                 edx, dword ptr [edi + 0xc998]
            //   8b7ddc               | mov                 edi, dword ptr [ebp - 0x24]
            //   0fb77c7b3c           | movzx               edi, word ptr [ebx + edi*2 + 0x3c]
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi
            //   81c7990c0000         | add                 edi, 0xc99
            //   c1e704               | shl                 edi, 4
            //   030437               | add                 eax, dword ptr [edi + esi]

        $sequence_9 = { ffd6 83f801 74f3 6a01 ffd5 53 }
            // n = 6, score = 100
            //   ffd6                 | call                esi
            //   83f801               | cmp                 eax, 1
            //   74f3                 | je                  0xfffffff5
            //   6a01                 | push                1
            //   ffd5                 | call                ebp
            //   53                   | push                ebx

    condition:
        7 of them and filesize < 892928
}
