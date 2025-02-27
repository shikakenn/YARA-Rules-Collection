rule win_jaku_auto {

    meta:
        id = "6EzaGdB2uaOeN9lg0asXzz"
        fingerprint = "v1_sha256_48ece9688342db3652fd3070c7f85ee33a0b73ea4b91e59fc03cc271dad9fdd8"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.jaku."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jaku"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff75f0 ff75fc ff7618 e8???????? 83c40c }
            // n = 5, score = 1500
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff7618               | push                dword ptr [esi + 0x18]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { 83ff10 7321 837df800 0f84610e0000 8b45fc ff4df8 }
            // n = 6, score = 1500
            //   83ff10               | cmp                 edi, 0x10
            //   7321                 | jae                 0x23
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   0f84610e0000         | je                  0xe67
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   ff4df8               | dec                 dword ptr [ebp - 8]

        $sequence_2 = { 5e c3 833d????????00 56 8b742408 7505 e8???????? }
            // n = 7, score = 1500
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   833d????????00       |                     
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   7505                 | jne                 7
            //   e8????????           |                     

        $sequence_3 = { 66891441 ff4e78 75b6 ff466c 8b466c 3beb }
            // n = 6, score = 1500
            //   66891441             | mov                 word ptr [ecx + eax*2], dx
            //   ff4e78               | dec                 dword ptr [esi + 0x78]
            //   75b6                 | jne                 0xffffffb8
            //   ff466c               | inc                 dword ptr [esi + 0x6c]
            //   8b466c               | mov                 eax, dword ptr [esi + 0x6c]
            //   3beb                 | cmp                 ebp, ebx

        $sequence_4 = { d3e2 8b4de4 85d1 7404 d1ea ebf8 }
            // n = 6, score = 1500
            //   d3e2                 | shl                 edx, cl
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   85d1                 | test                ecx, edx
            //   7404                 | je                  6
            //   d1ea                 | shr                 edx, 1
            //   ebf8                 | jmp                 0xfffffffa

        $sequence_5 = { 894dcc 750c 81fa54030000 0f8316020000 83ff02 }
            // n = 5, score = 1500
            //   894dcc               | mov                 dword ptr [ebp - 0x34], ecx
            //   750c                 | jne                 0xe
            //   81fa54030000         | cmp                 edx, 0x354
            //   0f8316020000         | jae                 0x21c
            //   83ff02               | cmp                 edi, 2

        $sequence_6 = { 83c418 33db 894618 895df4 c70601000000 e9???????? }
            // n = 6, score = 1500
            //   83c418               | add                 esp, 0x18
            //   33db                 | xor                 ebx, ebx
            //   894618               | mov                 dword ptr [esi + 0x18], eax
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   c70601000000         | mov                 dword ptr [esi], 1
            //   e9????????           |                     

        $sequence_7 = { 5b 8bd3 3bc3 8955ec }
            // n = 4, score = 1500
            //   5b                   | pop                 ebx
            //   8bd3                 | mov                 edx, ebx
            //   3bc3                 | cmp                 eax, ebx
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx

        $sequence_8 = { 68???????? ff15???????? c3 b8???????? e8???????? 83ec2c }
            // n = 6, score = 800
            //   68????????           |                     
            //   ff15????????         |                     
            //   c3                   | ret                 
            //   b8????????           |                     
            //   e8????????           |                     
            //   83ec2c               | sub                 esp, 0x2c

        $sequence_9 = { ff742408 e8???????? c20800 8bc1 }
            // n = 4, score = 600
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     
            //   c20800               | ret                 8
            //   8bc1                 | mov                 eax, ecx

        $sequence_10 = { 5b c3 55 8bec 833d????????00 53 56 }
            // n = 7, score = 500
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   833d????????00       |                     
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_11 = { 6a01 03c3 68???????? 50 e8???????? 83c40c }
            // n = 6, score = 500
            //   6a01                 | push                1
            //   03c3                 | add                 eax, ebx
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_12 = { 53 68000000a0 6a03 53 }
            // n = 4, score = 500
            //   53                   | push                ebx
            //   68000000a0           | push                0xa0000000
            //   6a03                 | push                3
            //   53                   | push                ebx

        $sequence_13 = { 7507 b800308000 eb02 33c0 }
            // n = 4, score = 500
            //   7507                 | jne                 9
            //   b800308000           | mov                 eax, 0x803000
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_14 = { 55 56 57 6880020000 }
            // n = 4, score = 500
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi
            //   6880020000           | push                0x280

        $sequence_15 = { 7508 83c8ff e9???????? 8b839f830000 }
            // n = 4, score = 500
            //   7508                 | jne                 0xa
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     
            //   8b839f830000         | mov                 eax, dword ptr [ebx + 0x839f]

        $sequence_16 = { 75dd 57 e8???????? 59 }
            // n = 4, score = 500
            //   75dd                 | jne                 0xffffffdf
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_17 = { 85ff 741b 3bd0 7f74 7508 8b442418 }
            // n = 6, score = 400
            //   85ff                 | test                edi, edi
            //   741b                 | je                  0x1d
            //   3bd0                 | cmp                 edx, eax
            //   7f74                 | jg                  0x76
            //   7508                 | jne                 0xa
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]

        $sequence_18 = { e8???????? 59 eb57 53 }
            // n = 4, score = 400
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   eb57                 | jmp                 0x59
            //   53                   | push                ebx

        $sequence_19 = { 0245fd 3245fe 8a4dff d2c8 }
            // n = 4, score = 400
            //   0245fd               | add                 al, byte ptr [ebp - 3]
            //   3245fe               | xor                 al, byte ptr [ebp - 2]
            //   8a4dff               | mov                 cl, byte ptr [ebp - 1]
            //   d2c8                 | ror                 al, cl

        $sequence_20 = { 56 e8???????? 59 8b4620 }
            // n = 4, score = 400
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]

        $sequence_21 = { 50 e8???????? 59 8b4e2c }
            // n = 4, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4e2c               | mov                 ecx, dword ptr [esi + 0x2c]

        $sequence_22 = { 016c242c 8b44242c 5f 5e 5d }
            // n = 5, score = 400
            //   016c242c             | add                 dword ptr [esp + 0x2c], ebp
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_23 = { 2b4d08 3bf1 770a 68???????? e8???????? 034d14 2b4508 }
            // n = 7, score = 300
            //   2b4d08               | sub                 ecx, dword ptr [ebp + 8]
            //   3bf1                 | cmp                 esi, ecx
            //   770a                 | ja                  0xc
            //   68????????           |                     
            //   e8????????           |                     
            //   034d14               | add                 ecx, dword ptr [ebp + 0x14]
            //   2b4508               | sub                 eax, dword ptr [ebp + 8]

        $sequence_24 = { 66d3e2 02c3 888677830000 66099675830000 }
            // n = 4, score = 300
            //   66d3e2               | shl                 dx, cl
            //   02c3                 | add                 al, bl
            //   888677830000         | mov                 byte ptr [esi + 0x8377], al
            //   66099675830000       | or                  word ptr [esi + 0x8375], dx

        $sequence_25 = { 85c0 743a 6a58 e8???????? 59 }
            // n = 5, score = 300
            //   85c0                 | test                eax, eax
            //   743a                 | je                  0x3c
            //   6a58                 | push                0x58
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_26 = { 51 6800040000 ff750c 50 ff15???????? 85c0 7527 }
            // n = 7, score = 300
            //   51                   | push                ecx
            //   6800040000           | push                0x400
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7527                 | jne                 0x29

        $sequence_27 = { 6a00 66c745903c00 50 e8???????? }
            // n = 4, score = 200
            //   6a00                 | push                0
            //   66c745903c00         | mov                 word ptr [ebp - 0x70], 0x3c
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_28 = { 6a00 57 e8???????? 8945fc }
            // n = 4, score = 200
            //   6a00                 | push                0
            //   57                   | push                edi
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

    condition:
        7 of them and filesize < 2220032
}
