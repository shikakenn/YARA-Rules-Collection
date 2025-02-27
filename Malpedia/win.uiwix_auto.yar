rule win_uiwix_auto {

    meta:
        id = "2puUGGqxq8G8QQLsYGjVDc"
        fingerprint = "v1_sha256_b8bd4baa3e0ab4ce7faf230ac74d7a2886f5f026a3fd7ac12866afcb88d35a97"
        version = "1"
        date = "2020-10-14"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.uiwix"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 e8???????? a3???????? 833d????????00 0f86a9020000 ba???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   a3????????           |                     
            //   833d????????00       |                     
            //   0f86a9020000         | jbe                 0x2af
            //   ba????????           |                     

        $sequence_1 = { 8bc8 8bd7 8b4514 e8???????? eb1c 8b5324 52 }
            // n = 7, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   8bd7                 | mov                 edx, edi
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   e8????????           |                     
            //   eb1c                 | jmp                 0x1e
            //   8b5324               | mov                 edx, dword ptr [ebx + 0x24]
            //   52                   | push                edx

        $sequence_2 = { 8bc7 e8???????? 8bd0 8d45bc e8???????? 8b45c0 33d2 }
            // n = 7, score = 100
            //   8bc7                 | mov                 eax, edi
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d45bc               | lea                 eax, [ebp - 0x44]
            //   e8????????           |                     
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]
            //   33d2                 | xor                 edx, edx

        $sequence_3 = { 8d8528feffff e8???????? 8b9528feffff 8d83b0000000 e8???????? 33c9 55 }
            // n = 7, score = 100
            //   8d8528feffff         | lea                 eax, [ebp - 0x1d8]
            //   e8????????           |                     
            //   8b9528feffff         | mov                 edx, dword ptr [ebp - 0x1d8]
            //   8d83b0000000         | lea                 eax, [ebx + 0xb0]
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   55                   | push                ebp

        $sequence_4 = { 50 a1???????? 8b00 ffd0 85c0 0f845a010000 8d4df0 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   a1????????           |                     
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   0f845a010000         | je                  0x160
            //   8d4df0               | lea                 ecx, [ebp - 0x10]

        $sequence_5 = { ba0e000000 e8???????? ff45cc ff4db8 0f85a9feffff 8b45c8 50 }
            // n = 7, score = 100
            //   ba0e000000           | mov                 edx, 0xe
            //   e8????????           |                     
            //   ff45cc               | inc                 dword ptr [ebp - 0x34]
            //   ff4db8               | dec                 dword ptr [ebp - 0x48]
            //   0f85a9feffff         | jne                 0xfffffeaf
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   50                   | push                eax

        $sequence_6 = { e9???????? 0fb7430a 50 b8???????? b901000000 8b15???????? e8???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   0fb7430a             | movzx               eax, word ptr [ebx + 0xa]
            //   50                   | push                eax
            //   b8????????           |                     
            //   b901000000           | mov                 ecx, 1
            //   8b15????????         |                     
            //   e8????????           |                     

        $sequence_7 = { 314608 8b8b34010000 8b5374 8b4608 e8???????? 314604 8b8b38010000 }
            // n = 7, score = 100
            //   314608               | xor                 dword ptr [esi + 8], eax
            //   8b8b34010000         | mov                 ecx, dword ptr [ebx + 0x134]
            //   8b5374               | mov                 edx, dword ptr [ebx + 0x74]
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   e8????????           |                     
            //   314604               | xor                 dword ptr [esi + 4], eax
            //   8b8b38010000         | mov                 ecx, dword ptr [ebx + 0x138]

        $sequence_8 = { 83c21e 89530c 8b03 0fb74816 03ca 0fb74018 03c8 }
            // n = 7, score = 100
            //   83c21e               | add                 edx, 0x1e
            //   89530c               | mov                 dword ptr [ebx + 0xc], edx
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   0fb74816             | movzx               ecx, word ptr [eax + 0x16]
            //   03ca                 | add                 ecx, edx
            //   0fb74018             | movzx               eax, word ptr [eax + 0x18]
            //   03c8                 | add                 ecx, eax

        $sequence_9 = { 7e40 8b45f8 8945f0 837df000 740b 8b55f0 83ea04 }
            // n = 7, score = 100
            //   7e40                 | jle                 0x42
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0
            //   740b                 | je                  0xd
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   83ea04               | sub                 edx, 4

    condition:
        7 of them and filesize < 491520
}
