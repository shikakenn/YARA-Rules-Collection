rule win_rm3_auto {

    meta:
        id = "K8weQpd5UepGYDWnFuzIT"
        fingerprint = "v1_sha256_1f5fb30680a7291833cb3efcb87bc5516507b42236b00016cdde1fb7cc527979"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.rm3."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rm3"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b4508 3b460c 7247 8b7938 }
            // n = 4, score = 2300
            //   8b4508               | and                 edx, eax
            //   3b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   7247                 | add                 eax, edx
            //   8b7938               | cmp                 dword ptr [ebp + 8], eax

        $sequence_1 = { 8b413c 8d5418ff eb0a 8b4138 8b5608 8d5410ff 48 }
            // n = 7, score = 2300
            //   8b413c               | movzx               eax, word ptr [ecx + 0x14]
            //   8d5418ff             | push                esi
            //   eb0a                 | push                esi
            //   8b4138               | push                edi
            //   8b5608               | lea                 esi, [eax + ecx + 0x18]
            //   8d5410ff             | mov                 eax, dword ptr [ebp + 8]
            //   48                   | mov                 edi, dword ptr [ecx + 0x38]

        $sequence_2 = { 0fb74106 8365f800 53 8945fc 0fb74114 56 }
            // n = 6, score = 2300
            //   0fb74106             | inc                 ecx
            //   8365f800             | mov                 eax, 0x30c
            //   53                   | dec                 eax
            //   8945fc               | test                eax, eax
            //   0fb74114             | dec                 esp
            //   56                   | mov                 esp, eax

        $sequence_3 = { 85c0 7505 3945fc 759f }
            // n = 4, score = 2300
            //   85c0                 | jae                 0xf
            //   7505                 | mov                 eax, dword ptr [ecx + 0x3c]
            //   3945fc               | lea                 edx, [eax + ebx - 1]
            //   759f                 | jmp                 0xc

        $sequence_4 = { 8b7938 8b4608 8b513c 8b5e10 8d4438ff }
            // n = 5, score = 2300
            //   8b7938               | dec                 esp
            //   8b4608               | lea                 eax, [eax - 0x18]
            //   8b513c               | xor                 ebx, ebx
            //   8b5e10               | cmp                 eax, ebx
            //   8d4438ff             | jae                 0x15

        $sequence_5 = { 56 57 8d740818 8b4508 }
            // n = 4, score = 2300
            //   56                   | dec                 ecx
            //   57                   | mov                 esi, eax
            //   8d740818             | dec                 ebp
            //   8b4508               | mov                 ecx, dword ptr [ecx + 0x98]

        $sequence_6 = { 03c2 394508 7303 8975f8 }
            // n = 4, score = 2300
            //   03c2                 | je                  0xcb
            //   394508               | dec                 eax
            //   7303                 | mov                 ecx, ebx
            //   8975f8               | xor                 edx, edx

        $sequence_7 = { 897104 8b4808 ff7004 034c240c }
            // n = 4, score = 2300
            //   897104               | mov                 eax, dword ptr [esi + 8]
            //   8b4808               | mov                 edx, dword ptr [ecx + 0x3c]
            //   ff7004               | mov                 ebx, dword ptr [esi + 0x10]
            //   034c240c             | lea                 eax, [eax + edi - 1]

        $sequence_8 = { 894510 56 8bc3 8d8d68ffffff 8bd6 e8???????? 2907 }
            // n = 7, score = 1800
            //   894510               | lea                 eax, [ebp - 0x88]
            //   56                   | push                eax
            //   8bc3                 | mov                 eax, esi
            //   8d8d68ffffff         | mov                 ebp, esp
            //   8bd6                 | push                ecx
            //   e8????????           |                     
            //   2907                 | and                 dword ptr [ebp - 4], 0

        $sequence_9 = { 8b4514 e8???????? 8b5508 57 8bc3 8d8d58feffff }
            // n = 6, score = 1800
            //   8b4514               | cmp                 edi, eax
            //   e8????????           |                     
            //   8b5508               | jbe                 0x12
            //   57                   | jne                 7
            //   8bc3                 | cmp                 dword ptr [ebp - 4], eax
            //   8d8d58feffff         | jne                 0xffffffa4

        $sequence_10 = { 8b3d???????? 8365fc00 8d45fc 50 6a00 }
            // n = 5, score = 1800
            //   8b3d????????         |                     
            //   8365fc00             | pop                 edi
            //   8d45fc               | pop                 esi
            //   50                   | mov                 dword ptr [ebp - 8], esi
            //   6a00                 | mov                 eax, dword ptr [ebp - 8]

        $sequence_11 = { 897df8 e8???????? 8b4d0c 57 8bc6 8d9558feffff }
            // n = 6, score = 1800
            //   897df8               | mov                 eax, ebx
            //   e8????????           |                     
            //   8b4d0c               | lea                 ecx, [ebp - 0x1a8]
            //   57                   | and                 dword ptr [ebp - 4], 0
            //   8bc6                 | lea                 eax, [ebp - 4]
            //   8d9558feffff         | push                eax

        $sequence_12 = { 8bec 51 8365fc00 56 8d4508 50 }
            // n = 6, score = 1800
            //   8bec                 | jae                 0xa
            //   51                   | mov                 dword ptr [ebp - 8], esi
            //   8365fc00             | mov                 eax, dword ptr [ebp - 8]
            //   56                   | mov                 ebx, dword ptr [esi + 0x10]
            //   8d4508               | lea                 eax, [eax + edi - 1]
            //   50                   | dec                 edi

        $sequence_13 = { e8???????? 2bf3 89750c 0f88b3000000 8d3c1e 8dbcbd58feffff 837dfcff }
            // n = 7, score = 1800
            //   e8????????           |                     
            //   2bf3                 | not                 edi
            //   89750c               | and                 eax, edi
            //   0f88b3000000         | lea                 edi, [ebx + edx - 1]
            //   8d3c1e               | mov                 eax, dword ptr [ebp + 0x14]
            //   8dbcbd58feffff       | mov                 edx, dword ptr [ebp + 8]
            //   837dfcff             | push                edi

        $sequence_14 = { ff750c 8d8d6cfeffff 50 e8???????? 8d8578ffffff 50 8bc6 }
            // n = 7, score = 1800
            //   ff750c               | add                 esi, 0x28
            //   8d8d6cfeffff         | dec                 dword ptr [ebp - 4]
            //   50                   | test                eax, eax
            //   e8????????           |                     
            //   8d8578ffffff         | mov                 eax, dword ptr [esi + 0xc]
            //   50                   | add                 eax, edx
            //   8bc6                 | cmp                 dword ptr [ebp + 8], eax

        $sequence_15 = { 8d9568ffffff e8???????? 85c0 7c15 ff4510 }
            // n = 5, score = 1800
            //   8d9568ffffff         | push                0
            //   e8????????           |                     
            //   85c0                 | push                dword ptr [ebp + 0xc]
            //   7c15                 | lea                 ecx, [ebp - 0x194]
            //   ff4510               | push                eax

        $sequence_16 = { 41bc01000000 eb07 3d002f0000 750c }
            // n = 4, score = 300
            //   41bc01000000         | mov                 ebx, eax
            //   eb07                 | mov                 edi, edx
            //   3d002f0000           | inc                 ecx
            //   750c                 | mov                 esp, 1

        $sequence_17 = { 8d480f e8???????? 448b4f20 4c8b4728 }
            // n = 4, score = 300
            //   8d480f               | mov                 edx, edi
            //   e8????????           |                     
            //   448b4f20             | mov                 ecx, 0x51ff3ea6
            //   4c8b4728             | dec                 eax

        $sequence_18 = { 488bd7 b9a63eff51 e8???????? 4885c0 7423 4c8d442448 33d2 }
            // n = 7, score = 300
            //   488bd7               | add                 edi, eax
            //   b9a63eff51           | movzx               eax, byte ptr [esp + 0x31]
            //   e8????????           |                     
            //   4885c0               | inc                 esp
            //   7423                 | cmp                 esp, eax
            //   4c8d442448           | jb                  0xffffffdb
            //   33d2                 | dec                 eax

        $sequence_19 = { 33d2 41b80c030000 ff15???????? 4885c0 4c8be0 }
            // n = 5, score = 300
            //   33d2                 | mov                 eax, dword ptr [ecx]
            //   41b80c030000         | inc                 ecx
            //   ff15????????         |                     
            //   4885c0               | add                 eax, 1
            //   4c8be0               | dec                 eax

        $sequence_20 = { 4883c604 03f8 0fb6442431 443be0 72cf }
            // n = 5, score = 300
            //   4883c604             | jmp                 9
            //   03f8                 | cmp                 eax, 0x2f00
            //   0fb6442431           | jne                 0x15
            //   443be0               | dec                 eax
            //   72cf                 | add                 esi, 4

        $sequence_21 = { 448d443616 33d2 ff15???????? 4885c0 488bf0 0f84bd000000 488bcb }
            // n = 7, score = 300
            //   448d443616           | xor                 edx, edx
            //   33d2                 | lea                 ecx, [eax + 0xf]
            //   ff15????????         |                     
            //   4885c0               | inc                 esp
            //   488bf0               | mov                 ecx, dword ptr [edi + 0x20]
            //   0f84bd000000         | dec                 esp
            //   488bcb               | mov                 eax, dword ptr [edi + 0x28]

        $sequence_22 = { 8b01 4183c001 4883c104 48014268 }
            // n = 4, score = 300
            //   8b01                 | test                eax, eax
            //   4183c001             | je                  0x2d
            //   4883c104             | dec                 esp
            //   48014268             | lea                 eax, [esp + 0x48]

        $sequence_23 = { 4881ecc0000000 488b0d???????? 418bd8 8bfa }
            // n = 4, score = 300
            //   4881ecc0000000       | dec                 eax
            //   488b0d????????       |                     
            //   418bd8               | sub                 esp, 0xc0
            //   8bfa                 | inc                 ecx

        $sequence_24 = { 83c404 8b0d???????? 50 8b85d4fbffff 50 6a17 }
            // n = 6, score = 100
            //   83c404               | push                dword ptr [eax + 4]
            //   8b0d????????         |                     
            //   50                   | add                 ecx, dword ptr [esp + 0xc]
            //   8b85d4fbffff         | cmp                 dword ptr [ebp + 8], eax
            //   50                   | jae                 5
            //   6a17                 | mov                 dword ptr [ebp - 8], esi

        $sequence_25 = { 8b8500ffffff 8a8c0574ffffff 8a940556ffffff 28ca 88940556ffffff 83c001 }
            // n = 6, score = 100
            //   8b8500ffffff         | mov                 dword ptr [ebp - 0x9c], ecx
            //   8a8c0574ffffff       | lea                 eax, [ebp - 0x24]
            //   8a940556ffffff       | mov                 esi, dword ptr [eax]
            //   28ca                 | mov                 edi, dword ptr [eax + 4]
            //   88940556ffffff       | mov                 ebx, dword ptr [eax + 8]
            //   83c001               | pop                 ebp

        $sequence_26 = { 898d64ffffff e8???????? 8d45dc 8b30 8b7804 8b5808 }
            // n = 6, score = 100
            //   898d64ffffff         | jmp                 0xc
            //   e8????????           |                     
            //   8d45dc               | mov                 eax, dword ptr [ecx + 0x38]
            //   8b30                 | mov                 edx, dword ptr [esi + 8]
            //   8b7804               | mov                 ecx, dword ptr [eax + 0x3c]
            //   8b5808               | add                 ecx, eax

        $sequence_27 = { e8???????? 8b45b4 8b483c 890c24 c744240400000000 8b4db0 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b45b4               | and                 edi, edx
            //   8b483c               | mov                 eax, dword ptr [ebp - 0x60]
            //   890c24               | add                 eax, ebx
            //   c744240400000000     | mov                 ebx, dword ptr [ecx + 0x24]
            //   8b4db0               | mov                 dword ptr [ebp - 0xa4], eax

        $sequence_28 = { 8945b8 894db4 8955b0 897dac 8975a8 0f84b5000000 }
            // n = 6, score = 100
            //   8945b8               | sub                 esp, 0x34
            //   894db4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   8955b0               | mov                 ecx, dword ptr [eax + 0x3c]
            //   897dac               | mov                 dword ptr [esp], ecx
            //   8975a8               | mov                 dword ptr [esp + 4], 0
            //   0f84b5000000         | mov                 ecx, dword ptr [ebp - 0x50]

        $sequence_29 = { 898d6cffffff 899d68ffffff 89bd64ffffff 898560ffffff e9???????? }
            // n = 5, score = 100
            //   898d6cffffff         | jne                 7
            //   899d68ffffff         | cmp                 dword ptr [ebp - 4], eax
            //   89bd64ffffff         | jne                 0xffffffa1
            //   898560ffffff         | mov                 ebx, dword ptr [esi + 0x10]
            //   e9????????           |                     

        $sequence_30 = { 8b45a0 01d8 8b5924 89855cffffff 89d8 }
            // n = 5, score = 100
            //   8b45a0               | mov                 eax, dword ptr [esi + 0xc]
            //   01d8                 | add                 eax, edx
            //   8b5924               | cmp                 dword ptr [ebp + 8], eax
            //   89855cffffff         | jae                 0x11
            //   89d8                 | dec                 eax

        $sequence_31 = { 8b8d6cffffff 894c2404 898558ffffff e8???????? }
            // n = 4, score = 100
            //   8b8d6cffffff         | jb                  0x4c
            //   894c2404             | mov                 edi, dword ptr [ecx + 0x38]
            //   898558ffffff         | test                eax, eax
            //   e8????????           |                     

        $sequence_32 = { 89462c 890c24 c744240400000000 8955d0 e8???????? }
            // n = 5, score = 100
            //   89462c               | push                eax
            //   890c24               | push                0x17
            //   c744240400000000     | mov                 dword ptr [ebp - 0x418], eax
            //   8955d0               | call                ecx
            //   e8????????           |                     

        $sequence_33 = { 898558ffffff 89d8 c1e81f c1eb1d 83e301 }
            // n = 5, score = 100
            //   898558ffffff         | ret                 
            //   89d8                 | push                ebp
            //   c1e81f               | mov                 ebp, esp
            //   c1eb1d               | push                edi
            //   83e301               | push                esi

        $sequence_34 = { 8b15???????? 8985e8fdffff 898de4fdffff ffd2 }
            // n = 4, score = 100
            //   8b15????????         |                     
            //   8985e8fdffff         | add                 esp, 4
            //   898de4fdffff         | push                eax
            //   ffd2                 | mov                 eax, dword ptr [ebp - 0x42c]

        $sequence_35 = { eb16 8a8563ffffff a801 755c eb00 31c0 }
            // n = 6, score = 100
            //   eb16                 | not                 eax
            //   8a8563ffffff         | and                 edx, eax
            //   a801                 | mov                 eax, dword ptr [esi + 0xc]
            //   755c                 | add                 eax, edx
            //   eb00                 | cmp                 dword ptr [ebp + 8], eax
            //   31c0                 | lea                 edx, [eax + ebx - 1]

        $sequence_36 = { c744240400000000 8955d4 e8???????? 8d0d96318702 }
            // n = 4, score = 100
            //   c744240400000000     | push                0
            //   8955d4               | push                0x80000000
            //   e8????????           |                     
            //   8d0d96318702         | push                0

        $sequence_37 = { 8985e8fbffff ffd1 8b0d???????? 6a00 6800000080 6a00 6a00 }
            // n = 7, score = 100
            //   8985e8fbffff         | mov                 eax, dword ptr [ebp - 8]
            //   ffd1                 | add                 esi, 0x28
            //   8b0d????????         |                     
            //   6a00                 | dec                 dword ptr [ebp - 4]
            //   6800000080           | test                eax, eax
            //   6a00                 | mov                 eax, dword ptr [ebp + 8]
            //   6a00                 | cmp                 eax, dword ptr [esi + 0xc]

        $sequence_38 = { 8b3e 83c618 81ff50450000 0f44d6 8b7580 81ff50450000 89c7 }
            // n = 7, score = 100
            //   8b3e                 | mov                 eax, ebx
            //   83c618               | jmp                 0x18
            //   81ff50450000         | mov                 al, byte ptr [ebp - 0x9d]
            //   0f44d6               | test                al, 1
            //   8b7580               | jne                 0x60
            //   81ff50450000         | jmp                 6
            //   89c7                 | xor                 eax, eax

        $sequence_39 = { 8b4870 894de0 8b4874 894de4 8b4868 }
            // n = 5, score = 100
            //   8b4870               | lea                 eax, [eax + edi - 1]
            //   894de0               | dec                 edi
            //   8b4874               | not                 edi
            //   894de4               | and                 eax, edi
            //   8b4868               | lea                 edi, [ebx + edx - 1]

    condition:
        7 of them and filesize < 221184
}
