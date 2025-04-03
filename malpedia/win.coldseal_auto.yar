rule win_coldseal_auto {

    meta:
        id = "40jrEFE8d6Wbyi6HME5q20"
        fingerprint = "v1_sha256_940440de3d1f9903d402565f8e85e5cfa991968a5d3d863aeac5347ddb3af4cf"
        version = "1"
        date = "2023-01-25"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.coldseal."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.coldseal"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 51 8b15???????? ffd2 85c0 }
            // n = 4, score = 1900
            //   51                   | push                ecx
            //   8b15????????         |                     
            //   ffd2                 | call                edx
            //   85c0                 | test                eax, eax

        $sequence_1 = { 51 8b55f4 52 6aff 68???????? }
            // n = 5, score = 1300
            //   51                   | push                ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   52                   | push                edx
            //   6aff                 | push                -1
            //   68????????           |                     

        $sequence_2 = { 8b4508 50 8b0d???????? ffd1 }
            // n = 4, score = 1300
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   8b0d????????         |                     
            //   ffd1                 | call                ecx

        $sequence_3 = { 6aff 68???????? 6a00 8b45f8 }
            // n = 4, score = 1300
            //   6aff                 | push                -1
            //   68????????           |                     
            //   6a00                 | push                0
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_4 = { f77514 8b450c 0fb60c10 03f1 }
            // n = 4, score = 1300
            //   f77514               | div                 dword ptr [ebp + 0x14]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fb60c10             | movzx               ecx, byte ptr [eax + edx]
            //   03f1                 | add                 esi, ecx

        $sequence_5 = { c785f4fbffff00000000 8b85f4fbffff 8945fc c745f800000000 eb09 8b4df8 }
            // n = 6, score = 1300
            //   c785f4fbffff00000000     | mov    dword ptr [ebp - 0x40c], 0
            //   8b85f4fbffff         | mov                 eax, dword ptr [ebp - 0x40c]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   eb09                 | jmp                 0xb
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_6 = { 8b0d???????? ffd1 50 8b15???????? }
            // n = 4, score = 1300
            //   8b0d????????         |                     
            //   ffd1                 | call                ecx
            //   50                   | push                eax
            //   8b15????????         |                     

        $sequence_7 = { 83c001 2bf0 6a01 e8???????? }
            // n = 4, score = 1300
            //   83c001               | add                 eax, 1
            //   2bf0                 | sub                 esi, eax
            //   6a01                 | push                1
            //   e8????????           |                     

        $sequence_8 = { 8b95f4fbffff 898c95f8fbffff e9???????? c785f4fbffff00000000 8b85f4fbffff }
            // n = 5, score = 1300
            //   8b95f4fbffff         | mov                 edx, dword ptr [ebp - 0x40c]
            //   898c95f8fbffff       | mov                 dword ptr [ebp + edx*4 - 0x408], ecx
            //   e9????????           |                     
            //   c785f4fbffff00000000     | mov    dword ptr [ebp - 0x40c], 0
            //   8b85f4fbffff         | mov                 eax, dword ptr [ebp - 0x40c]

        $sequence_9 = { 8b85f4fbffff 039485f8fbffff 81e2ff000080 7908 4a }
            // n = 5, score = 1300
            //   8b85f4fbffff         | mov                 eax, dword ptr [ebp - 0x40c]
            //   039485f8fbffff       | add                 edx, dword ptr [ebp + eax*4 - 0x408]
            //   81e2ff000080         | and                 edx, 0x800000ff
            //   7908                 | jns                 0xa
            //   4a                   | dec                 edx

        $sequence_10 = { 6a00 6a00 8b4d08 51 6a00 6a00 8b15???????? }
            // n = 7, score = 1200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8b15????????         |                     

        $sequence_11 = { 6a24 6a40 8b0d???????? ffd1 8945fc }
            // n = 5, score = 1100
            //   6a24                 | push                0x24
            //   6a40                 | push                0x40
            //   8b0d????????         |                     
            //   ffd1                 | call                ecx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_12 = { 50 e8???????? 50 e8???????? 83c408 8945e0 8955e4 }
            // n = 7, score = 1100
            //   50                   | push                eax
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx

        $sequence_13 = { 6a24 6a40 a1???????? ffd0 }
            // n = 4, score = 1100
            //   6a24                 | push                0x24
            //   6a40                 | push                0x40
            //   a1????????           |                     
            //   ffd0                 | call                eax

        $sequence_14 = { 8955f4 e9???????? 8b4508 0fb608 }
            // n = 4, score = 1100
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   e9????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0fb608               | movzx               ecx, byte ptr [eax]

        $sequence_15 = { 6a04 6800100000 6a04 6a00 8b0d???????? }
            // n = 5, score = 1100
            //   6a04                 | push                4
            //   6800100000           | push                0x1000
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   8b0d????????         |                     

        $sequence_16 = { 52 8b45f4 8b481c 51 e8???????? }
            // n = 5, score = 1000
            //   52                   | push                edx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b481c               | mov                 ecx, dword ptr [eax + 0x1c]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_17 = { 50 8b4de0 51 8b15???????? }
            // n = 4, score = 1000
            //   50                   | push                eax
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   51                   | push                ecx
            //   8b15????????         |                     

        $sequence_18 = { 0fbe45ff 2bd0 8955f8 780f 837df805 }
            // n = 5, score = 1000
            //   0fbe45ff             | movsx               eax, byte ptr [ebp - 1]
            //   2bd0                 | sub                 edx, eax
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   780f                 | js                  0x11
            //   837df805             | cmp                 dword ptr [ebp - 8], 5

        $sequence_19 = { 780f 837df809 7f09 c745e801000000 eb07 c745e800000000 837de800 }
            // n = 7, score = 900
            //   780f                 | js                  0x11
            //   837df809             | cmp                 dword ptr [ebp - 8], 9
            //   7f09                 | jg                  0xb
            //   c745e801000000       | mov                 dword ptr [ebp - 0x18], 1
            //   eb07                 | jmp                 9
            //   c745e800000000       | mov                 dword ptr [ebp - 0x18], 0
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0

        $sequence_20 = { 8b4810 51 8b55f8 8b421c }
            // n = 4, score = 900
            //   8b4810               | mov                 ecx, dword ptr [eax + 0x10]
            //   51                   | push                ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b421c               | mov                 eax, dword ptr [edx + 0x1c]

        $sequence_21 = { 8b421c 50 8b4df4 8b5110 }
            // n = 4, score = 900
            //   8b421c               | mov                 eax, dword ptr [edx + 0x1c]
            //   50                   | push                eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8b5110               | mov                 edx, dword ptr [ecx + 0x10]

        $sequence_22 = { 51 8b55f4 8b421c 50 }
            // n = 4, score = 900
            //   51                   | push                ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8b421c               | mov                 eax, dword ptr [edx + 0x1c]
            //   50                   | push                eax

        $sequence_23 = { e8???????? 83c404 8b4d08 034df8 }
            // n = 4, score = 900
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   034df8               | add                 ecx, dword ptr [ebp - 8]

        $sequence_24 = { 8b4de4 8b513c 8b4508 8d4c1004 }
            // n = 4, score = 900
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   8b513c               | mov                 edx, dword ptr [ecx + 0x3c]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8d4c1004             | lea                 ecx, [eax + edx + 4]

        $sequence_25 = { 8b1401 52 b804000000 6bc806 }
            // n = 4, score = 800
            //   8b1401               | mov                 edx, dword ptr [ecx + eax]
            //   52                   | push                edx
            //   b804000000           | mov                 eax, 4
            //   6bc806               | imul                ecx, eax, 6

        $sequence_26 = { 8b55f8 8955fc eb09 8b45f4 83c001 }
            // n = 5, score = 800
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   eb09                 | jmp                 0xb
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   83c001               | add                 eax, 1

        $sequence_27 = { 6a04 6800100000 6a24 6a00 a1???????? }
            // n = 5, score = 800
            //   6a04                 | push                4
            //   6800100000           | push                0x1000
            //   6a24                 | push                0x24
            //   6a00                 | push                0
            //   a1????????           |                     

        $sequence_28 = { 8b4df4 8b5150 52 8b45f4 8b4834 51 8b55dc }
            // n = 7, score = 800
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8b5150               | mov                 edx, dword ptr [ecx + 0x50]
            //   52                   | push                edx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4834               | mov                 ecx, dword ptr [eax + 0x34]
            //   51                   | push                ecx
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]

        $sequence_29 = { 0fbe4dfe 2bc1 8945f8 780f 837df809 7f09 }
            // n = 6, score = 800
            //   0fbe4dfe             | movsx               ecx, byte ptr [ebp - 2]
            //   2bc1                 | sub                 eax, ecx
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   780f                 | js                  0x11
            //   837df809             | cmp                 dword ptr [ebp - 8], 9
            //   7f09                 | jg                  0xb

        $sequence_30 = { 6a00 6a01 6a14 8b0d???????? ffd1 }
            // n = 5, score = 800
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a14                 | push                0x14
            //   8b0d????????         |                     
            //   ffd1                 | call                ecx

        $sequence_31 = { c745f400000000 8b4df4 894df8 8b55f8 8955fc }
            // n = 5, score = 800
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx

        $sequence_32 = { 8b040a 50 b904000000 6bd103 }
            // n = 4, score = 800
            //   8b040a               | mov                 eax, dword ptr [edx + ecx]
            //   50                   | push                eax
            //   b904000000           | mov                 ecx, 4
            //   6bd103               | imul                edx, ecx, 3

        $sequence_33 = { 50 ff15???????? a3???????? 8ac6 }
            // n = 4, score = 800
            //   50                   | push                eax
            //   ff15????????         |                     
            //   a3????????           |                     
            //   8ac6                 | mov                 al, dh

        $sequence_34 = { 6800100000 a1???????? 50 6a00 8b0d???????? }
            // n = 5, score = 800
            //   6800100000           | push                0x1000
            //   a1????????           |                     
            //   50                   | push                eax
            //   6a00                 | push                0
            //   8b0d????????         |                     

        $sequence_35 = { 51 8b55dc 52 a1???????? ffd0 8945d8 837dd800 }
            // n = 7, score = 800
            //   51                   | push                ecx
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   52                   | push                edx
            //   a1????????           |                     
            //   ffd0                 | call                eax
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   837dd800             | cmp                 dword ptr [ebp - 0x28], 0

        $sequence_36 = { 8bf0 83c601 6a00 e8???????? }
            // n = 4, score = 800
            //   8bf0                 | mov                 esi, eax
            //   83c601               | add                 esi, 1
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_37 = { 8945f8 780f 837df805 7f09 }
            // n = 4, score = 700
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   780f                 | js                  0x11
            //   837df805             | cmp                 dword ptr [ebp - 8], 5
            //   7f09                 | jg                  0xb

        $sequence_38 = { 8945f4 8b4df4 83c101 894df4 e9???????? 5e }
            // n = 6, score = 700
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   83c101               | add                 ecx, 1
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   e9????????           |                     
            //   5e                   | pop                 esi

        $sequence_39 = { f6d8 3ac6 0fadd8 3ac6 }
            // n = 4, score = 500
            //   f6d8                 | neg                 al
            //   3ac6                 | cmp                 al, dh
            //   0fadd8               | shrd                eax, ebx, cl
            //   3ac6                 | cmp                 al, dh

        $sequence_40 = { 56 8955ec 894df0 6a05 6a40 a1???????? }
            // n = 6, score = 500
            //   56                   | push                esi
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   6a05                 | push                5
            //   6a40                 | push                0x40
            //   a1????????           |                     

        $sequence_41 = { 0fafc3 84f7 8ac6 8ac6 }
            // n = 4, score = 500
            //   0fafc3               | imul                eax, ebx
            //   84f7                 | test                bh, dh
            //   8ac6                 | mov                 al, dh
            //   8ac6                 | mov                 al, dh

        $sequence_42 = { 8ac6 8ac6 0fafc3 3ac6 }
            // n = 4, score = 500
            //   8ac6                 | mov                 al, dh
            //   8ac6                 | mov                 al, dh
            //   0fafc3               | imul                eax, ebx
            //   3ac6                 | cmp                 al, dh

        $sequence_43 = { 8ac6 3ac6 3ac6 3ac6 }
            // n = 4, score = 500
            //   8ac6                 | mov                 al, dh
            //   3ac6                 | cmp                 al, dh
            //   3ac6                 | cmp                 al, dh
            //   3ac6                 | cmp                 al, dh

        $sequence_44 = { 86e0 fec8 3ac6 0fafc3 }
            // n = 4, score = 500
            //   86e0                 | xchg                al, ah
            //   fec8                 | dec                 al
            //   3ac6                 | cmp                 al, dh
            //   0fafc3               | imul                eax, ebx

        $sequence_45 = { 8ac6 8ac6 8ac6 d2f8 }
            // n = 4, score = 500
            //   8ac6                 | mov                 al, dh
            //   8ac6                 | mov                 al, dh
            //   8ac6                 | mov                 al, dh
            //   d2f8                 | sar                 al, cl

        $sequence_46 = { 3ac6 3ac6 8ac6 0fc0c4 }
            // n = 4, score = 500
            //   3ac6                 | cmp                 al, dh
            //   3ac6                 | cmp                 al, dh
            //   8ac6                 | mov                 al, dh
            //   0fc0c4               | xadd                ah, al

        $sequence_47 = { c3 e9???????? e8???????? 0fb7c0 50 }
            // n = 5, score = 400
            //   c3                   | ret                 
            //   e9????????           |                     
            //   e8????????           |                     
            //   0fb7c0               | movzx               eax, ax
            //   50                   | push                eax

        $sequence_48 = { ff15???????? 5d c3 8b01 832100 c3 b8???????? }
            // n = 7, score = 400
            //   ff15????????         |                     
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   832100               | and                 dword ptr [ecx], 0
            //   c3                   | ret                 
            //   b8????????           |                     

        $sequence_49 = { 56 e8???????? 59 c3 8b01 8b400c c1e806 }
            // n = 7, score = 400
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   c1e806               | shr                 eax, 6

        $sequence_50 = { ebcb 8bff 55 8bec a1???????? 85c0 7575 }
            // n = 7, score = 400
            //   ebcb                 | jmp                 0xffffffcd
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7575                 | jne                 0x77

        $sequence_51 = { 890d???????? 5d c3 8b01 8b400c 25c0040000 }
            // n = 6, score = 400
            //   890d????????         |                     
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   25c0040000           | and                 eax, 0x4c0

        $sequence_52 = { 8b45fc 8b88a4000000 83c108 51 8b55dc }
            // n = 5, score = 400
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b88a4000000         | mov                 ecx, dword ptr [eax + 0xa4]
            //   83c108               | add                 ecx, 8
            //   51                   | push                ecx
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]

        $sequence_53 = { 83e001 c3 6a10 68???????? e8???????? 8365e400 6a08 }
            // n = 7, score = 400
            //   83e001               | and                 eax, 1
            //   c3                   | ret                 
            //   6a10                 | push                0x10
            //   68????????           |                     
            //   e8????????           |                     
            //   8365e400             | and                 dword ptr [ebp - 0x1c], 0
            //   6a08                 | push                8

        $sequence_54 = { 50 e8???????? 50 6a00 68???????? e8???????? c3 }
            // n = 7, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   50                   | push                eax
            //   6a00                 | push                0
            //   68????????           |                     
            //   e8????????           |                     
            //   c3                   | ret                 

        $sequence_55 = { 5d c3 55 8bec a1???????? 8bc8 334508 }
            // n = 7, score = 400
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   a1????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   334508               | xor                 eax, dword ptr [ebp + 8]

        $sequence_56 = { 50 e8???????? 89852cfcffff 899530fcffff }
            // n = 4, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   89852cfcffff         | mov                 dword ptr [ebp - 0x3d4], eax
            //   899530fcffff         | mov                 dword ptr [ebp - 0x3d0], edx

        $sequence_57 = { 50 e8???????? 89859cfbffff 8995a0fbffff }
            // n = 4, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   89859cfbffff         | mov                 dword ptr [ebp - 0x464], eax
            //   8995a0fbffff         | mov                 dword ptr [ebp - 0x460], edx

        $sequence_58 = { 52 50 e8???????? 89855cfcffff }
            // n = 4, score = 300
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     
            //   89855cfcffff         | mov                 dword ptr [ebp - 0x3a4], eax

        $sequence_59 = { 50 e8???????? 89857cfdffff 899580fdffff }
            // n = 4, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   89857cfdffff         | mov                 dword ptr [ebp - 0x284], eax
            //   899580fdffff         | mov                 dword ptr [ebp - 0x280], edx

        $sequence_60 = { 50 e8???????? 8985f4feffff 8995f8feffff 8b95f4feffff }
            // n = 5, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   8985f4feffff         | mov                 dword ptr [ebp - 0x10c], eax
            //   8995f8feffff         | mov                 dword ptr [ebp - 0x108], edx
            //   8b95f4feffff         | mov                 edx, dword ptr [ebp - 0x10c]

    condition:
        7 of them and filesize < 1190912
}
