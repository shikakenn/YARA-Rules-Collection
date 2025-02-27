rule win_tempedreve_auto {

    meta:
        id = "eXBGtZPHm1xK05nXZG1ec"
        fingerprint = "v1_sha256_ff28ad4e45522fd6ad775c186581b049a8c3b1257f6ade7f519c8365bdcce952"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.tempedreve."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tempedreve"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0f8460020000 8b54242c 8bca c1e918 }
            // n = 4, score = 300
            //   0f8460020000         | je                  0x266
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   8bca                 | mov                 ecx, edx
            //   c1e918               | shr                 ecx, 0x18

        $sequence_1 = { 7511 f6c408 6a01 58 0f45c3 }
            // n = 5, score = 300
            //   7511                 | jne                 0x13
            //   f6c408               | test                ah, 8
            //   6a01                 | push                1
            //   58                   | pop                 eax
            //   0f45c3               | cmovne              eax, ebx

        $sequence_2 = { 8b5d0c 8b4734 8b5110 03c3 3bd0 }
            // n = 5, score = 300
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   8b4734               | mov                 eax, dword ptr [edi + 0x34]
            //   8b5110               | mov                 edx, dword ptr [ecx + 0x10]
            //   03c3                 | add                 eax, ebx
            //   3bd0                 | cmp                 edx, eax

        $sequence_3 = { 8a4102 24c0 3cc0 0f84d8010000 8a45fc }
            // n = 5, score = 300
            //   8a4102               | mov                 al, byte ptr [ecx + 2]
            //   24c0                 | and                 al, 0xc0
            //   3cc0                 | cmp                 al, 0xc0
            //   0f84d8010000         | je                  0x1de
            //   8a45fc               | mov                 al, byte ptr [ebp - 4]

        $sequence_4 = { 8974242c ff15???????? 8d442428 68???????? }
            // n = 4, score = 300
            //   8974242c             | mov                 dword ptr [esp + 0x2c], esi
            //   ff15????????         |                     
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   68????????           |                     

        $sequence_5 = { 6800800000 6a00 ff74243c ff15???????? ff742444 }
            // n = 5, score = 300
            //   6800800000           | push                0x8000
            //   6a00                 | push                0
            //   ff74243c             | push                dword ptr [esp + 0x3c]
            //   ff15????????         |                     
            //   ff742444             | push                dword ptr [esp + 0x44]

        $sequence_6 = { 50 e8???????? 6a40 8d442464 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a40                 | push                0x40
            //   8d442464             | lea                 eax, [esp + 0x64]

        $sequence_7 = { 59 c20c00 a1???????? 85c9 }
            // n = 4, score = 300
            //   59                   | pop                 ecx
            //   c20c00               | ret                 0xc
            //   a1????????           |                     
            //   85c9                 | test                ecx, ecx

        $sequence_8 = { 742e 8b4c2460 8b9610040000 2b542450 }
            // n = 4, score = 200
            //   742e                 | je                  0x30
            //   8b4c2460             | mov                 ecx, dword ptr [esp + 0x60]
            //   8b9610040000         | mov                 edx, dword ptr [esi + 0x410]
            //   2b542450             | sub                 edx, dword ptr [esp + 0x50]

        $sequence_9 = { 72c9 85c0 0f85a9090000 53 }
            // n = 4, score = 200
            //   72c9                 | jb                  0xffffffcb
            //   85c0                 | test                eax, eax
            //   0f85a9090000         | jne                 0x9af
            //   53                   | push                ebx

        $sequence_10 = { 2bfb 75d7 8b8e14040000 8b16 }
            // n = 4, score = 200
            //   2bfb                 | sub                 edi, ebx
            //   75d7                 | jne                 0xffffffd9
            //   8b8e14040000         | mov                 ecx, dword ptr [esi + 0x414]
            //   8b16                 | mov                 edx, dword ptr [esi]

        $sequence_11 = { 7320 8d4d02 8be8 2b6c2428 8a0429 3a01 }
            // n = 6, score = 200
            //   7320                 | jae                 0x22
            //   8d4d02               | lea                 ecx, [ebp + 2]
            //   8be8                 | mov                 ebp, eax
            //   2b6c2428             | sub                 ebp, dword ptr [esp + 0x28]
            //   8a0429               | mov                 al, byte ptr [ecx + ebp]
            //   3a01                 | cmp                 al, byte ptr [ecx]

        $sequence_12 = { 8b442404 8bc8 c1e903 8d440140 c20400 8b44240c }
            // n = 6, score = 200
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8bc8                 | mov                 ecx, eax
            //   c1e903               | shr                 ecx, 3
            //   8d440140             | lea                 eax, [ecx + eax + 0x40]
            //   c20400               | ret                 4
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]

        $sequence_13 = { 740c 3b8e24040000 0f85c9000000 8b542430 }
            // n = 4, score = 200
            //   740c                 | je                  0xe
            //   3b8e24040000         | cmp                 ecx, dword ptr [esi + 0x424]
            //   0f85c9000000         | jne                 0xcf
            //   8b542430             | mov                 edx, dword ptr [esp + 0x30]

        $sequence_14 = { 0f85a9090000 53 8916 8d4e04 }
            // n = 4, score = 200
            //   0f85a9090000         | jne                 0x9af
            //   53                   | push                ebx
            //   8916                 | mov                 dword ptr [esi], edx
            //   8d4e04               | lea                 ecx, [esi + 4]

        $sequence_15 = { 57 0fb6b90030cb00 d1c0 33c7 0fb6b90130cb00 d1c0 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   0fb6b90030cb00       | movzx               edi, byte ptr [ecx + 0xcb3000]
            //   d1c0                 | rol                 eax, 1
            //   33c7                 | xor                 eax, edi
            //   0fb6b90130cb00       | movzx               edi, byte ptr [ecx + 0xcb3001]
            //   d1c0                 | rol                 eax, 1

    condition:
        7 of them and filesize < 155648
}
