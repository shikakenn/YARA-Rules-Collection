rule win_unidentified_068_auto {

    meta:
        id = "hfSRbr6fKwneRxnSNfc7z"
        fingerprint = "v1_sha256_cf7d5521a90e4f10a4d7ed99e1e2829b2e957d2aba56d598bf0190ab6bc75eb5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_068."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_068"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 51 8bd1 8b4a08 3b4a04 730d 8b02 8a0401 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8bd1                 | mov                 edx, ecx
            //   8b4a08               | mov                 ecx, dword ptr [edx + 8]
            //   3b4a04               | cmp                 ecx, dword ptr [edx + 4]
            //   730d                 | jae                 0xf
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8a0401               | mov                 al, byte ptr [ecx + eax]

        $sequence_1 = { 8b0f e8???????? 8d7f04 83eb01 75f1 6808030000 56 }
            // n = 7, score = 100
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   e8????????           |                     
            //   8d7f04               | lea                 edi, [edi + 4]
            //   83eb01               | sub                 ebx, 1
            //   75f1                 | jne                 0xfffffff3
            //   6808030000           | push                0x308
            //   56                   | push                esi

        $sequence_2 = { 8d45b4 c645fc02 50 8d45cc 50 8bc1 }
            // n = 6, score = 100
            //   8d45b4               | lea                 eax, [ebp - 0x4c]
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   50                   | push                eax
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   50                   | push                eax
            //   8bc1                 | mov                 eax, ecx

        $sequence_3 = { 894de8 0fb6c8 8b0c8d00e24500 8bc3 c1e808 0fb6c0 330c8500de4500 }
            // n = 7, score = 100
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   0fb6c8               | movzx               ecx, al
            //   8b0c8d00e24500       | mov                 ecx, dword ptr [ecx*4 + 0x45e200]
            //   8bc3                 | mov                 eax, ebx
            //   c1e808               | shr                 eax, 8
            //   0fb6c0               | movzx               eax, al
            //   330c8500de4500       | xor                 ecx, dword ptr [eax*4 + 0x45de00]

        $sequence_4 = { 83f808 73ad 5f 5e 8b4d08 33c0 8b9380000000 }
            // n = 7, score = 100
            //   83f808               | cmp                 eax, 8
            //   73ad                 | jae                 0xffffffaf
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   33c0                 | xor                 eax, eax
            //   8b9380000000         | mov                 edx, dword ptr [ebx + 0x80]

        $sequence_5 = { 5d c3 55 8bec 81ec14020000 8365f800 8d85ecfdffff }
            // n = 7, score = 100
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec14020000         | sub                 esp, 0x214
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   8d85ecfdffff         | lea                 eax, [ebp - 0x214]

        $sequence_6 = { 8b4514 85c0 7410 3918 7505 394804 7407 }
            // n = 7, score = 100
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   85c0                 | test                eax, eax
            //   7410                 | je                  0x12
            //   3918                 | cmp                 dword ptr [eax], ebx
            //   7505                 | jne                 7
            //   394804               | cmp                 dword ptr [eax + 4], ecx
            //   7407                 | je                  9

        $sequence_7 = { 8bd0 c70424???????? e8???????? 59 50 8d4dd0 c645fc08 }
            // n = 7, score = 100
            //   8bd0                 | mov                 edx, eax
            //   c70424????????       |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8

        $sequence_8 = { 3955f0 1bc0 f7d8 40 03c1 6683470203 }
            // n = 6, score = 100
            //   3955f0               | cmp                 dword ptr [ebp - 0x10], edx
            //   1bc0                 | sbb                 eax, eax
            //   f7d8                 | neg                 eax
            //   40                   | inc                 eax
            //   03c1                 | add                 eax, ecx
            //   6683470203           | add                 word ptr [edi + 2], 3

        $sequence_9 = { c70485????????58fe4400 40 a3???????? c3 b9???????? e8???????? 68???????? }
            // n = 7, score = 100
            //   c70485????????58fe4400     |     
            //   40                   | inc                 eax
            //   a3????????           |                     
            //   c3                   | ret                 
            //   b9????????           |                     
            //   e8????????           |                     
            //   68????????           |                     

    condition:
        7 of them and filesize < 862208
}
