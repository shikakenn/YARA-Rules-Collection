rule win_xsplus_auto {

    meta:
        id = "7jA4Esx4431bLFUleIOBCt"
        fingerprint = "v1_sha256_e49d0b0e4b6b18be179499d3f98b92cb7a2ea53651dc18e80a64f9c221a6561b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.xsplus."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xsplus"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b4608 8b7e20 8b36 66394f18 75f2 }
            // n = 5, score = 400
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   8b7e20               | mov                 edi, dword ptr [esi + 0x20]
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   66394f18             | cmp                 word ptr [edi + 0x18], cx
            //   75f2                 | jne                 0xfffffff4

        $sequence_1 = { 51 6801000080 ff15???????? 85c0 7529 8b5518 52 }
            // n = 7, score = 300
            //   51                   | push                ecx
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7529                 | jne                 0x2b
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]
            //   52                   | push                edx

        $sequence_2 = { 6a40 0020 6b40008a 46 }
            // n = 4, score = 300
            //   6a40                 | push                0x40
            //   0020                 | add                 byte ptr [eax], ah
            //   6b40008a             | imul                eax, dword ptr [eax], -0x76
            //   46                   | inc                 esi

        $sequence_3 = { 8b8da4feffff 51 6a00 ff15???????? }
            // n = 4, score = 300
            //   8b8da4feffff         | mov                 ecx, dword ptr [ebp - 0x15c]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_4 = { 52 ff15???????? 6a2e 8d85f8feffff 50 }
            // n = 5, score = 300
            //   52                   | push                edx
            //   ff15????????         |                     
            //   6a2e                 | push                0x2e
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax

        $sequence_5 = { a1???????? c705????????04264000 8935???????? a3???????? ff15???????? a3???????? 83f8ff }
            // n = 7, score = 300
            //   a1????????           |                     
            //   c705????????04264000     |     
            //   8935????????         |                     
            //   a3????????           |                     
            //   ff15????????         |                     
            //   a3????????           |                     
            //   83f8ff               | cmp                 eax, -1

        $sequence_6 = { 837dc400 7505 8b45e0 eb63 }
            // n = 4, score = 300
            //   837dc400             | cmp                 dword ptr [ebp - 0x3c], 0
            //   7505                 | jne                 7
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   eb63                 | jmp                 0x65

        $sequence_7 = { 7453 83bdb8fdffff10 7436 e9???????? 81bdb8fdffff11010000 }
            // n = 5, score = 300
            //   7453                 | je                  0x55
            //   83bdb8fdffff10       | cmp                 dword ptr [ebp - 0x248], 0x10
            //   7436                 | je                  0x38
            //   e9????????           |                     
            //   81bdb8fdffff11010000     | cmp    dword ptr [ebp - 0x248], 0x111

        $sequence_8 = { 8945dc 6a05 8b45dc 50 }
            // n = 4, score = 300
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   6a05                 | push                5
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax

        $sequence_9 = { e9???????? 8975e4 33c0 39b810a84000 0f8491000000 }
            // n = 5, score = 300
            //   e9????????           |                     
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   33c0                 | xor                 eax, eax
            //   39b810a84000         | cmp                 dword ptr [eax + 0x40a810], edi
            //   0f8491000000         | je                  0x97

        $sequence_10 = { a1???????? a3???????? a1???????? c705????????04264000 8935???????? }
            // n = 5, score = 300
            //   a1????????           |                     
            //   a3????????           |                     
            //   a1????????           |                     
            //   c705????????04264000     |     
            //   8935????????         |                     

        $sequence_11 = { ff75e4 ffd3 8986fc010000 897e70 c686c800000043 c6864b01000043 c74668e0a34000 }
            // n = 7, score = 300
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   ffd3                 | call                ebx
            //   8986fc010000         | mov                 dword ptr [esi + 0x1fc], eax
            //   897e70               | mov                 dword ptr [esi + 0x70], edi
            //   c686c800000043       | mov                 byte ptr [esi + 0xc8], 0x43
            //   c6864b01000043       | mov                 byte ptr [esi + 0x14b], 0x43
            //   c74668e0a34000       | mov                 dword ptr [esi + 0x68], 0x40a3e0

        $sequence_12 = { 3945e0 7608 8b45e0 e9???????? c685f8feffff00 b918000000 33c0 }
            // n = 7, score = 300
            //   3945e0               | cmp                 dword ptr [ebp - 0x20], eax
            //   7608                 | jbe                 0xa
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   e9????????           |                     
            //   c685f8feffff00       | mov                 byte ptr [ebp - 0x108], 0
            //   b918000000           | mov                 ecx, 0x18
            //   33c0                 | xor                 eax, eax

        $sequence_13 = { 8bec 83ec2c c745d406000000 6a00 6a00 6809100000 }
            // n = 6, score = 300
            //   8bec                 | mov                 ebp, esp
            //   83ec2c               | sub                 esp, 0x2c
            //   c745d406000000       | mov                 dword ptr [ebp - 0x2c], 6
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6809100000           | push                0x1009

        $sequence_14 = { 51 8b55fc 8b02 8b4dfc 51 ff500c }
            // n = 6, score = 300
            //   51                   | push                ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   ff500c               | call                dword ptr [eax + 0xc]

        $sequence_15 = { ff15???????? 83c40c 8d95fcfeffff 52 ff15???????? 6a00 6880000000 }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   8d95fcfeffff         | lea                 edx, [ebp - 0x104]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6880000000           | push                0x80

        $sequence_16 = { 8b8d90feffff 51 e8???????? 83c404 b801000000 eb02 }
            // n = 6, score = 300
            //   8b8d90feffff         | mov                 ecx, dword ptr [ebp - 0x170]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   b801000000           | mov                 eax, 1
            //   eb02                 | jmp                 4

    condition:
        7 of them and filesize < 597872
}
