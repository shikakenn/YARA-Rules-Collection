rule win_rovnix_auto {

    meta:
        id = "1lQ4rPBQ4O1qRrf5eCiSGo"
        fingerprint = "v1_sha256_ed6329dc4f284f83c7abc03edae1041f365607dbb53bb190660ed33f6a939524"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.rovnix."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rovnix"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c1e902 ad 2bc3 ab e2fa }
            // n = 5, score = 900
            //   c1e902               | shr                 ecx, 2
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   2bc3                 | sub                 eax, ebx
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   e2fa                 | loop                0xfffffffc

        $sequence_1 = { 8bf8 83c335 c1e902 ad }
            // n = 4, score = 900
            //   8bf8                 | mov                 edi, eax
            //   83c335               | add                 ebx, 0x35
            //   c1e902               | shr                 ecx, 2
            //   ad                   | lodsd               eax, dword ptr [esi]

        $sequence_2 = { 6a00 ffd2 89442408 8bcf }
            // n = 4, score = 900
            //   6a00                 | push                0
            //   ffd2                 | call                edx
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   8bcf                 | mov                 ecx, edi

        $sequence_3 = { 8b15???????? 83e7f0 89542418 83c710 }
            // n = 4, score = 900
            //   8b15????????         |                     
            //   83e7f0               | and                 edi, 0xfffffff0
            //   89542418             | mov                 dword ptr [esp + 0x18], edx
            //   83c710               | add                 edi, 0x10

        $sequence_4 = { 7405 57 6a00 ffd2 }
            // n = 4, score = 900
            //   7405                 | je                  7
            //   57                   | push                edi
            //   6a00                 | push                0
            //   ffd2                 | call                edx

        $sequence_5 = { bf40090000 be???????? 8b15???????? 83e7f0 }
            // n = 4, score = 500
            //   bf40090000           | mov                 edi, 0x940
            //   be????????           |                     
            //   8b15????????         |                     
            //   83e7f0               | and                 edi, 0xfffffff0

        $sequence_6 = { 8d4e1c 8908 8b4508 c7461801000000 8b4804 8906 }
            // n = 6, score = 400
            //   8d4e1c               | lea                 ecx, [esi + 0x1c]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   c7461801000000       | mov                 dword ptr [esi + 0x18], 1
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   8906                 | mov                 dword ptr [esi], eax

        $sequence_7 = { c745cc18000000 8975d0 c745d800020000 8975d4 }
            // n = 4, score = 400
            //   c745cc18000000       | mov                 dword ptr [ebp - 0x34], 0x18
            //   8975d0               | mov                 dword ptr [ebp - 0x30], esi
            //   c745d800020000       | mov                 dword ptr [ebp - 0x28], 0x200
            //   8975d4               | mov                 dword ptr [ebp - 0x2c], esi

        $sequence_8 = { c745d800020000 8975d4 8975dc 8975e0 }
            // n = 4, score = 400
            //   c745d800020000       | mov                 dword ptr [ebp - 0x28], 0x200
            //   8975d4               | mov                 dword ptr [ebp - 0x2c], esi
            //   8975dc               | mov                 dword ptr [ebp - 0x24], esi
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi

        $sequence_9 = { c1e802 25ff000000 8d4cc624 8b01 }
            // n = 4, score = 400
            //   c1e802               | shr                 eax, 2
            //   25ff000000           | and                 eax, 0xff
            //   8d4cc624             | lea                 ecx, [esi + eax*8 + 0x24]
            //   8b01                 | mov                 eax, dword ptr [ecx]

        $sequence_10 = { 7703 83c220 85c0 7404 }
            // n = 4, score = 400
            //   7703                 | ja                  5
            //   83c220               | add                 edx, 0x20
            //   85c0                 | test                eax, eax
            //   7404                 | je                  6

        $sequence_11 = { 8975e4 c745ec40020000 8975e8 8975f0 8975f4 ff15???????? }
            // n = 6, score = 400
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   c745ec40020000       | mov                 dword ptr [ebp - 0x14], 0x240
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   ff15????????         |                     

        $sequence_12 = { 7306 8b00 3bc1 75f3 395e14 }
            // n = 5, score = 400
            //   7306                 | jae                 8
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   3bc1                 | cmp                 eax, ecx
            //   75f3                 | jne                 0xfffffff5
            //   395e14               | cmp                 dword ptr [esi + 0x14], ebx

        $sequence_13 = { 85c0 7405 8d4e1c 8908 }
            // n = 4, score = 400
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   8d4e1c               | lea                 ecx, [esi + 0x1c]
            //   8908                 | mov                 dword ptr [eax], ecx

        $sequence_14 = { 8b5e14 8b7e10 eb06 8b5d0c 8b7d08 8bcf }
            // n = 6, score = 400
            //   8b5e14               | mov                 ebx, dword ptr [esi + 0x14]
            //   8b7e10               | mov                 edi, dword ptr [esi + 0x10]
            //   eb06                 | jmp                 8
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8bcf                 | mov                 ecx, edi

        $sequence_15 = { 85c0 e8???????? 8be5 5d c3 }
            // n = 5, score = 400
            //   85c0                 | test                eax, eax
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_16 = { 23c9 16 85c9 23d2 }
            // n = 4, score = 200
            //   23c9                 | and                 ecx, ecx
            //   16                   | push                ss
            //   85c9                 | test                ecx, ecx
            //   23d2                 | and                 edx, edx

        $sequence_17 = { 23db 81e1ff000000 23c9 83440c0404 }
            // n = 4, score = 200
            //   23db                 | and                 ebx, ebx
            //   81e1ff000000         | and                 ecx, 0xff
            //   23c9                 | and                 ecx, ecx
            //   83440c0404           | add                 dword ptr [esp + ecx + 4], 4

        $sequence_18 = { 5d c3 85c0 e8???????? }
            // n = 4, score = 200
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   85c0                 | test                eax, eax
            //   e8????????           |                     

        $sequence_19 = { 5d c3 85c9 e8???????? }
            // n = 4, score = 200
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   85c9                 | test                ecx, ecx
            //   e8????????           |                     

        $sequence_20 = { 55 8bec 85db 85c9 }
            // n = 4, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   85db                 | test                ebx, ebx
            //   85c9                 | test                ecx, ecx

        $sequence_21 = { 2d02ca3b45 05bd6f0e7b 2d3f459239 5a }
            // n = 4, score = 100
            //   2d02ca3b45           | sub                 eax, 0x453bca02
            //   05bd6f0e7b           | add                 eax, 0x7b0e6fbd
            //   2d3f459239           | sub                 eax, 0x3992453f
            //   5a                   | pop                 edx

        $sequence_22 = { 488b8c24d0000000 c744244818000000 488d442470 4889442440 896c2438 488d442460 48896c2430 }
            // n = 7, score = 100
            //   488b8c24d0000000     | mov                 dword ptr [ebx + 0x28], eax
            //   c744244818000000     | dec                 eax
            //   488d442470           | mov                 eax, dword ptr [ebx]
            //   4889442440           | dec                 eax
            //   896c2438             | mov                 eax, dword ptr [ebx + 8]
            //   488d442460           | mov                 eax, dword ptr [ebx + 0x10]
            //   48896c2430           | dec                 eax

        $sequence_23 = { 747b 488d0543fcffff 488d0d18630000 33d2 48894310 48894320 48894328 }
            // n = 7, score = 100
            //   747b                 | je                  0x7d
            //   488d0543fcffff       | dec                 eax
            //   488d0d18630000       | lea                 eax, [0xfffffc43]
            //   33d2                 | dec                 eax
            //   48894310             | lea                 ecx, [0x6318]
            //   48894320             | xor                 edx, edx
            //   48894328             | dec                 eax

        $sequence_24 = { d6 b772 9af6b95c8decc4 7c8f d6 b772 9af6b95c8decc4 }
            // n = 7, score = 100
            //   d6                   | salc                
            //   b772                 | mov                 bh, 0x72
            //   9af6b95c8decc4       | lcall               0xc4ec:0x8d5cb9f6
            //   7c8f                 | jl                  0xffffff91
            //   d6                   | salc                
            //   b772                 | mov                 bh, 0x72
            //   9af6b95c8decc4       | lcall               0xc4ec:0x8d5cb9f6

        $sequence_25 = { 3425 33ce 3d6aa7d294 61 89fa 94 61 }
            // n = 7, score = 100
            //   3425                 | xor                 al, 0x25
            //   33ce                 | xor                 ecx, esi
            //   3d6aa7d294           | cmp                 eax, 0x94d2a76a
            //   61                   | popal               
            //   89fa                 | mov                 edx, edi
            //   94                   | xchg                eax, esp
            //   61                   | popal               

        $sequence_26 = { e018 0fb61cc0 50 68???????? 6a04 57 }
            // n = 6, score = 100
            //   e018                 | loopne              0x1a
            //   0fb61cc0             | movzx               ebx, byte ptr [eax + eax*8]
            //   50                   | push                eax
            //   68????????           |                     
            //   6a04                 | push                4
            //   57                   | push                edi

        $sequence_27 = { 8bda 4803d8 83e3e0 c1ea05 448bc1 3bd1 0f8683000000 }
            // n = 7, score = 100
            //   8bda                 | dec                 eax
            //   4803d8               | lea                 edx, [esp + 0x30]
            //   83e3e0               | dec                 eax
            //   c1ea05               | lea                 ecx, [esp + 0x40]
            //   448bc1               | inc                 ecx
            //   3bd1                 | mov                 ecx, 0x10
            //   0f8683000000         | dec                 eax

        $sequence_28 = { 4c3b02 750e 448a410b 443a4208 7504 8bc6 eb05 }
            // n = 7, score = 100
            //   4c3b02               | dec                 eax
            //   750e                 | mov                 dword ptr [esp + 0x40], eax
            //   448a410b             | mov                 dword ptr [esp + 0x38], ebp
            //   443a4208             | dec                 eax
            //   7504                 | lea                 eax, [esp + 0x60]
            //   8bc6                 | dec                 eax
            //   eb05                 | mov                 dword ptr [esp + 0x30], ebp

        $sequence_29 = { 85db 8b4d08 85db 85c9 81e1ff000000 }
            // n = 5, score = 100
            //   85db                 | test                ebx, ebx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   85db                 | test                ebx, ebx
            //   85c9                 | test                ecx, ecx
            //   81e1ff000000         | and                 ecx, 0xff

        $sequence_30 = { 4b 46 92 c55151 a2???????? d24b46 }
            // n = 6, score = 100
            //   4b                   | dec                 ebx
            //   46                   | inc                 esi
            //   92                   | xchg                eax, edx
            //   c55151               | lds                 edx, ptr [ecx + 0x51]
            //   a2????????           |                     
            //   d24b46               | ror                 byte ptr [ebx + 0x46], cl

        $sequence_31 = { 6e 17 48 2b6e17 48 8ee2 }
            // n = 6, score = 100
            //   6e                   | outsb               dx, byte ptr [esi]
            //   17                   | pop                 ss
            //   48                   | dec                 eax
            //   2b6e17               | sub                 ebp, dword ptr [esi + 0x17]
            //   48                   | dec                 eax
            //   8ee2                 | mov                 fs, edx

        $sequence_32 = { 488d542430 488d4c2440 e8???????? 41b910000000 488d542450 458d41f1 488d4c2478 }
            // n = 7, score = 100
            //   488d542430           | mov                 ecx, dword ptr [ebx + 0x20]
            //   488d4c2440           | dec                 eax
            //   e8????????           |                     
            //   41b910000000         | mov                 ecx, dword ptr [esp + 0xd0]
            //   488d542450           | mov                 dword ptr [esp + 0x48], 0x18
            //   458d41f1             | dec                 eax
            //   488d4c2478           | lea                 eax, [esp + 0x70]

        $sequence_33 = { ff15???????? 48295c2428 6601742420 6601742422 bb01000000 eb0a bf9a0000c0 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   48295c2428           | lea                 edx, [esp + 0x50]
            //   6601742420           | inc                 ebp
            //   6601742422           | lea                 eax, [ecx - 0xf]
            //   bb01000000           | dec                 eax
            //   eb0a                 | lea                 ecx, [esp + 0x78]
            //   bf9a0000c0           | dec                 esp

        $sequence_34 = { 1f d337 a6 ff08 f26d 17 }
            // n = 6, score = 100
            //   1f                   | pop                 ds
            //   d337                 | sal                 dword ptr [edi], cl
            //   a6                   | cmpsb               byte ptr [esi], byte ptr es:[edi]
            //   ff08                 | dec                 dword ptr [eax]
            //   f26d                 | repne insd          dword ptr es:[edi], dx
            //   17                   | pop                 ss

        $sequence_35 = { 488b03 488905???????? 488b4308 488905???????? 8b4310 8905???????? 488b4b20 }
            // n = 7, score = 100
            //   488b03               | mov                 dword ptr [ebx + 0x10], eax
            //   488905????????       |                     
            //   488b4308             | dec                 eax
            //   488905????????       |                     
            //   8b4310               | mov                 dword ptr [ebx + 0x20], eax
            //   8905????????         |                     
            //   488b4b20             | dec                 eax

    condition:
        7 of them and filesize < 548864
}
