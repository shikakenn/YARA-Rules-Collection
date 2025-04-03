rule win_numando_auto {

    meta:
        id = "3V4FM0gBLqjLxsXQMxhPUo"
        fingerprint = "v1_sha256_097a58f8787263a83fcc8ee402708311641a82800eeda99b04c28049923c5e21"
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
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.numando"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c640481a ff75fc ff75f8 8d55e0 8b03 e8???????? 8d45e0 }
            // n = 7, score = 100
            //   c640481a             | mov                 byte ptr [eax + 0x48], 0x1a
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   8d55e0               | lea                 edx, [ebp - 0x20]
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   e8????????           |                     
            //   8d45e0               | lea                 eax, [ebp - 0x20]

        $sequence_1 = { e8???????? 50 e8???????? 8b45fc c6809902000000 8b45fc 8b90a8020000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c6809902000000       | mov                 byte ptr [eax + 0x299], 0
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b90a8020000         | mov                 edx, dword ptr [eax + 0x2a8]

        $sequence_2 = { e8???????? 33d2 8bc3 8b08 ff91e8000000 c683d802000001 b201 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   33d2                 | xor                 edx, edx
            //   8bc3                 | mov                 eax, ebx
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff91e8000000         | call                dword ptr [ecx + 0xe8]
            //   c683d802000001       | mov                 byte ptr [ebx + 0x2d8], 1
            //   b201                 | mov                 dl, 1

        $sequence_3 = { 9e 746f 8b4508 8945f8 8b450c 8945fc ffb684020000 }
            // n = 7, score = 100
            //   9e                   | sahf                
            //   746f                 | je                  0x71
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ffb684020000         | push                dword ptr [esi + 0x284]

        $sequence_4 = { ba???????? e8???????? 6a01 8d45b8 50 8d45ec b101 }
            // n = 7, score = 100
            //   ba????????           |                     
            //   e8????????           |                     
            //   6a01                 | push                1
            //   8d45b8               | lea                 eax, [ebp - 0x48]
            //   50                   | push                eax
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   b101                 | mov                 cl, 1

        $sequence_5 = { b90f000000 ba0e000000 8b45fc e8???????? 8b55b0 8d45b4 e8???????? }
            // n = 7, score = 100
            //   b90f000000           | mov                 ecx, 0xf
            //   ba0e000000           | mov                 edx, 0xe
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8b55b0               | mov                 edx, dword ptr [ebp - 0x50]
            //   8d45b4               | lea                 eax, [ebp - 0x4c]
            //   e8????????           |                     

        $sequence_6 = { a5 5f 5e 8b45f4 e8???????? 8b5520 8955ac }
            // n = 7, score = 100
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   8b5520               | mov                 edx, dword ptr [ebp + 0x20]
            //   8955ac               | mov                 dword ptr [ebp - 0x54], edx

        $sequence_7 = { 8bd7 e8???????? 84c0 7424 807df700 751e 8b03 }
            // n = 7, score = 100
            //   8bd7                 | mov                 edx, edi
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7424                 | je                  0x26
            //   807df700             | cmp                 byte ptr [ebp - 9], 0
            //   751e                 | jne                 0x20
            //   8b03                 | mov                 eax, dword ptr [ebx]

        $sequence_8 = { eb02 33c0 84c0 0f8481000000 33c0 55 68???????? }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   84c0                 | test                al, al
            //   0f8481000000         | je                  0x87
            //   33c0                 | xor                 eax, eax
            //   55                   | push                ebp
            //   68????????           |                     

        $sequence_9 = { ffd0 8bd0 a1???????? 8b00 b9???????? e8???????? 83c46c }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8bd0                 | mov                 edx, eax
            //   a1????????           |                     
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   b9????????           |                     
            //   e8????????           |                     
            //   83c46c               | add                 esp, 0x6c

    condition:
        7 of them and filesize < 25870336
}
