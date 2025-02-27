rule win_infy_auto {

    meta:
        id = "5d6T7NUb2k37f3A7T0mf8T"
        fingerprint = "v1_sha256_351bd4b7525a7ff94f0f3657e8ee347d6c2c31664e11c42093ff09157f2eb43d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.infy."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.infy"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8a0d???????? 0f8748020000 84c9 0fb682c0984000 }
            // n = 4, score = 200
            //   8a0d????????         |                     
            //   0f8748020000         | ja                  0x24e
            //   84c9                 | test                cl, cl
            //   0fb682c0984000       | movzx               eax, byte ptr [edx + 0x4098c0]

        $sequence_1 = { 7412 50 e8???????? f685b0fdffff10 0f94c0 eb02 33c0 }
            // n = 7, score = 200
            //   7412                 | je                  0x14
            //   50                   | push                eax
            //   e8????????           |                     
            //   f685b0fdffff10       | test                byte ptr [ebp - 0x250], 0x10
            //   0f94c0               | sete                al
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { ff5324 807b2800 7407 8bc3 e8???????? }
            // n = 5, score = 200
            //   ff5324               | call                dword ptr [ebx + 0x24]
            //   807b2800             | cmp                 byte ptr [ebx + 0x28], 0
            //   7407                 | je                  9
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_3 = { ff4af8 e8???????? 8b55ec 8d2494 58 5a }
            // n = 6, score = 200
            //   ff4af8               | dec                 dword ptr [edx - 8]
            //   e8????????           |                     
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8d2494               | lea                 esp, [esp + edx*4]
            //   58                   | pop                 eax
            //   5a                   | pop                 edx

        $sequence_4 = { 751b 8d45d0 8945f4 8d55f4 }
            // n = 4, score = 200
            //   751b                 | jne                 0x1d
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8d55f4               | lea                 edx, [ebp - 0xc]

        $sequence_5 = { 833d????????00 740e 8d55d0 52 6a01 }
            // n = 5, score = 200
            //   833d????????00       |                     
            //   740e                 | je                  0x10
            //   8d55d0               | lea                 edx, [ebp - 0x30]
            //   52                   | push                edx
            //   6a01                 | push                1

        $sequence_6 = { 7226 8b35???????? 0fb74b1a 8d91300b0000 39d7 }
            // n = 5, score = 200
            //   7226                 | jb                  0x28
            //   8b35????????         |                     
            //   0fb74b1a             | movzx               ecx, word ptr [ebx + 0x1a]
            //   8d91300b0000         | lea                 edx, [ecx + 0xb30]
            //   39d7                 | cmp                 edi, edx

        $sequence_7 = { 85d2 744c 66837af601 7409 50 }
            // n = 5, score = 200
            //   85d2                 | test                edx, edx
            //   744c                 | je                  0x4e
            //   66837af601           | cmp                 word ptr [edx - 0xa], 1
            //   7409                 | je                  0xb
            //   50                   | push                eax

        $sequence_8 = { 3b45d8 0f8681feffff 5f 5e 5b }
            // n = 5, score = 200
            //   3b45d8               | cmp                 eax, dword ptr [ebp - 0x28]
            //   0f8681feffff         | jbe                 0xfffffe87
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_9 = { 6a00 66837ef602 7418 89cf 89f0 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   66837ef602           | cmp                 word ptr [esi - 0xa], 2
            //   7418                 | je                  0x1a
            //   89cf                 | mov                 edi, ecx
            //   89f0                 | mov                 eax, esi

    condition:
        7 of them and filesize < 147456
}
