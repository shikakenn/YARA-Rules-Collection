rule win_morphine_auto {

    meta:
        id = "5AmLLWS1H7EB7zMmgD7v4i"
        fingerprint = "v1_sha256_67ed9eeb1b2758b54d43659382a99e25607497b1678ec8fb9dbfd3dd3dce925b"
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
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.morphine"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 64ff30 648920 8d45fc 8bf3 }
            // n = 4, score = 400
            //   64ff30               | push                dword ptr fs:[eax]
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   8bf3                 | mov                 esi, ebx

        $sequence_1 = { b910000000 80fb58 0f84d4f3ffff b90a000000 80fb55 0f84c6f3ffff e9???????? }
            // n = 7, score = 400
            //   b910000000           | mov                 ecx, 0x10
            //   80fb58               | cmp                 bl, 0x58
            //   0f84d4f3ffff         | je                  0xfffff3da
            //   b90a000000           | mov                 ecx, 0xa
            //   80fb55               | cmp                 bl, 0x55
            //   0f84c6f3ffff         | je                  0xfffff3cc
            //   e9????????           |                     

        $sequence_2 = { 833d????????00 0f84b9000000 8b1d???????? 8b03 a3???????? }
            // n = 5, score = 400
            //   833d????????00       |                     
            //   0f84b9000000         | je                  0xbf
            //   8b1d????????         |                     
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   a3????????           |                     

        $sequence_3 = { 8b45fc c780840000000c584200 8b45fc 899898000000 8b45fc }
            // n = 5, score = 400
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c780840000000c584200     | mov    dword ptr [eax + 0x84], 0x42580c
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   899898000000         | mov                 dword ptr [eax + 0x98], ebx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_4 = { 8b45dc 50 8d45fc 50 8d8ddcfeffff 0fb795d8feffff 0fb785d4feffff }
            // n = 7, score = 400
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   8d8ddcfeffff         | lea                 ecx, [ebp - 0x124]
            //   0fb795d8feffff       | movzx               edx, word ptr [ebp - 0x128]
            //   0fb785d4feffff       | movzx               eax, word ptr [ebp - 0x12c]

        $sequence_5 = { 648920 8bc6 e8???????? 683f000f00 6a00 6a00 e8???????? }
            // n = 7, score = 400
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   683f000f00           | push                0xf003f
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_6 = { 8d45ec 50 8b45e8 50 8d85e8fbffff 50 57 }
            // n = 7, score = 400
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   50                   | push                eax
            //   8d85e8fbffff         | lea                 eax, [ebp - 0x418]
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_7 = { ba???????? e8???????? eb1a 8bc6 ba???????? e8???????? }
            // n = 6, score = 400
            //   ba????????           |                     
            //   e8????????           |                     
            //   eb1a                 | jmp                 0x1c
            //   8bc6                 | mov                 eax, esi
            //   ba????????           |                     
            //   e8????????           |                     

        $sequence_8 = { ff530c 8b4de8 b22f 8b45d0 e8???????? 33c0 }
            // n = 6, score = 400
            //   ff530c               | call                dword ptr [ebx + 0xc]
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   b22f                 | mov                 dl, 0x2f
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { 0f8582010000 0fb64703 3c01 7527 ff7704 e8???????? 8bd0 }
            // n = 7, score = 400
            //   0f8582010000         | jne                 0x188
            //   0fb64703             | movzx               eax, byte ptr [edi + 3]
            //   3c01                 | cmp                 al, 1
            //   7527                 | jne                 0x29
            //   ff7704               | push                dword ptr [edi + 4]
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax

    condition:
        7 of them and filesize < 835584
}
