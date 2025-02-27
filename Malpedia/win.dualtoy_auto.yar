rule win_dualtoy_auto {

    meta:
        id = "7GAsAtEkOZOrnZiu2VVS7S"
        fingerprint = "v1_sha256_d1945e1220deb38f5f8b2297965527a4090139ebfc25901ffc6d8437feb7cc5d"
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
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dualtoy"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bc8 8b5304 8b45cc 8b401c 8b18 ff531c e9???????? }
            // n = 7, score = 300
            //   8bc8                 | mov                 ecx, eax
            //   8b5304               | mov                 edx, dword ptr [ebx + 4]
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   8b401c               | mov                 eax, dword ptr [eax + 0x1c]
            //   8b18                 | mov                 ebx, dword ptr [eax]
            //   ff531c               | call                dword ptr [ebx + 0x1c]
            //   e9????????           |                     

        $sequence_1 = { 50 8b430c 8945b0 c645b40b 8d55b0 33c9 b8???????? }
            // n = 7, score = 300
            //   50                   | push                eax
            //   8b430c               | mov                 eax, dword ptr [ebx + 0xc]
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   c645b40b             | mov                 byte ptr [ebp - 0x4c], 0xb
            //   8d55b0               | lea                 edx, [ebp - 0x50]
            //   33c9                 | xor                 ecx, ecx
            //   b8????????           |                     

        $sequence_2 = { 750c 8bc6 8b5508 e8???????? 7433 8b55f8 8bc3 }
            // n = 7, score = 300
            //   750c                 | jne                 0xe
            //   8bc6                 | mov                 eax, esi
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   7433                 | je                  0x35
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8bc3                 | mov                 eax, ebx

        $sequence_3 = { b9???????? 8b06 8d5064 8b4318 e8???????? 84c0 }
            // n = 6, score = 300
            //   b9????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8d5064               | lea                 edx, [eax + 0x64]
            //   8b4318               | mov                 eax, dword ptr [ebx + 0x18]
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_4 = { 84c0 0f84c4000000 8b45ec 8b4008 8945dc 8b5dec 8bd3 }
            // n = 7, score = 300
            //   84c0                 | test                al, al
            //   0f84c4000000         | je                  0xca
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8b5dec               | mov                 ebx, dword ptr [ebp - 0x14]
            //   8bd3                 | mov                 edx, ebx

        $sequence_5 = { b9???????? b201 a1???????? e8???????? e8???????? 85c9 }
            // n = 6, score = 300
            //   b9????????           |                     
            //   b201                 | mov                 dl, 1
            //   a1????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   85c9                 | test                ecx, ecx

        $sequence_6 = { eb0a 8b0c24 8b5128 2b542428 8954242c 837c242c00 0f85fa000000 }
            // n = 7, score = 300
            //   eb0a                 | jmp                 0xc
            //   8b0c24               | mov                 ecx, dword ptr [esp]
            //   8b5128               | mov                 edx, dword ptr [ecx + 0x28]
            //   2b542428             | sub                 edx, dword ptr [esp + 0x28]
            //   8954242c             | mov                 dword ptr [esp + 0x2c], edx
            //   837c242c00           | cmp                 dword ptr [esp + 0x2c], 0
            //   0f85fa000000         | jne                 0x100

        $sequence_7 = { ff919c000000 0fb645f7 2c3c 7469 2c21 7465 8d45f0 }
            // n = 7, score = 300
            //   ff919c000000         | call                dword ptr [ecx + 0x9c]
            //   0fb645f7             | movzx               eax, byte ptr [ebp - 9]
            //   2c3c                 | sub                 al, 0x3c
            //   7469                 | je                  0x6b
            //   2c21                 | sub                 al, 0x21
            //   7465                 | je                  0x67
            //   8d45f0               | lea                 eax, [ebp - 0x10]

        $sequence_8 = { 83c40c 894604 c7461000000000 c7461400000000 8bd3 80e2fc 8bc6 }
            // n = 7, score = 300
            //   83c40c               | add                 esp, 0xc
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   c7461400000000       | mov                 dword ptr [esi + 0x14], 0
            //   8bd3                 | mov                 edx, ebx
            //   80e2fc               | and                 dl, 0xfc
            //   8bc6                 | mov                 eax, esi

        $sequence_9 = { 8345e404 817df000010000 7ce7 8b4df0 8d848d58fbffff 8945e0 }
            // n = 6, score = 300
            //   8345e404             | add                 dword ptr [ebp - 0x1c], 4
            //   817df000010000       | cmp                 dword ptr [ebp - 0x10], 0x100
            //   7ce7                 | jl                  0xffffffe9
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8d848d58fbffff       | lea                 eax, [ebp + ecx*4 - 0x4a8]
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax

    condition:
        7 of them and filesize < 1474560
}
