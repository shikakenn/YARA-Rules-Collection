rule win_unidentified_074_auto {

    meta:
        id = "4TKipkRRmO2GawVX1eLa24"
        fingerprint = "v1_sha256_6dab9e5ae43cc86eae4e300f173218fa8732c7df5d913a5bb2fedc84e5de19c3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_074."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_074"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7417 0fb732 8bcb b8???????? 663930 }
            // n = 5, score = 200
            //   7417                 | je                  0x19
            //   0fb732               | movzx               esi, word ptr [edx]
            //   8bcb                 | mov                 ecx, ebx
            //   b8????????           |                     
            //   663930               | cmp                 word ptr [eax], si

        $sequence_1 = { 33c0 c78524e7ffff07000000 66898510e7ffff 8d85f8e6ffff 50 8d8540e7ffff }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   c78524e7ffff07000000     | mov    dword ptr [ebp - 0x18dc], 7
            //   66898510e7ffff       | mov                 word ptr [ebp - 0x18f0], ax
            //   8d85f8e6ffff         | lea                 eax, [ebp - 0x1908]
            //   50                   | push                eax
            //   8d8540e7ffff         | lea                 eax, [ebp - 0x18c0]

        $sequence_2 = { 8b07 eb02 8bc7 8b55e0 }
            // n = 4, score = 200
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   eb02                 | jmp                 4
            //   8bc7                 | mov                 eax, edi
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]

        $sequence_3 = { 68???????? c60300 e8???????? 8d8d58e7ffff e8???????? }
            // n = 5, score = 200
            //   68????????           |                     
            //   c60300               | mov                 byte ptr [ebx], 0
            //   e8????????           |                     
            //   8d8d58e7ffff         | lea                 ecx, [ebp - 0x18a8]
            //   e8????????           |                     

        $sequence_4 = { 894dfc 8b7e10 c745f001000000 8b4310 40 }
            // n = 5, score = 200
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b7e10               | mov                 edi, dword ptr [esi + 0x10]
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]
            //   40                   | inc                 eax

        $sequence_5 = { c78524e7ffff07000000 66898510e7ffff 8d85f8e6ffff 50 8d8540e7ffff c78520e7ffff00000000 50 }
            // n = 7, score = 200
            //   c78524e7ffff07000000     | mov    dword ptr [ebp - 0x18dc], 7
            //   66898510e7ffff       | mov                 word ptr [ebp - 0x18f0], ax
            //   8d85f8e6ffff         | lea                 eax, [ebp - 0x1908]
            //   50                   | push                eax
            //   8d8540e7ffff         | lea                 eax, [ebp - 0x18c0]
            //   c78520e7ffff00000000     | mov    dword ptr [ebp - 0x18e0], 0
            //   50                   | push                eax

        $sequence_6 = { 7504 33c9 eb18 8d8d88e7ffff 8d5102 668b01 }
            // n = 6, score = 200
            //   7504                 | jne                 6
            //   33c9                 | xor                 ecx, ecx
            //   eb18                 | jmp                 0x1a
            //   8d8d88e7ffff         | lea                 ecx, [ebp - 0x1878]
            //   8d5102               | lea                 edx, [ecx + 2]
            //   668b01               | mov                 ax, word ptr [ecx]

        $sequence_7 = { 68???????? 50 e8???????? 8b4dfc 83c424 f7d8 }
            // n = 6, score = 200
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c424               | add                 esp, 0x24
            //   f7d8                 | neg                 eax

        $sequence_8 = { 50 ffb578dfffff e8???????? 33c0 c7858cdfffff07000000 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   ffb578dfffff         | push                dword ptr [ebp - 0x2088]
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   c7858cdfffff07000000     | mov    dword ptr [ebp - 0x2074], 7

        $sequence_9 = { e8???????? c743140f000000 c7431000000000 c60300 8b9584e7ffff 83fa10 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   c743140f000000       | mov                 dword ptr [ebx + 0x14], 0xf
            //   c7431000000000       | mov                 dword ptr [ebx + 0x10], 0
            //   c60300               | mov                 byte ptr [ebx], 0
            //   8b9584e7ffff         | mov                 edx, dword ptr [ebp - 0x187c]
            //   83fa10               | cmp                 edx, 0x10

    condition:
        7 of them and filesize < 335872
}
