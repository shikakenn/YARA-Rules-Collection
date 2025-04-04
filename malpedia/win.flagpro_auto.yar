rule win_flagpro_auto {

    meta:
        id = "6cgWNZHoHTtSsxldYxwgdM"
        fingerprint = "v1_sha256_654c55cf6ed0a2b532ad215de02e3b03b4d1dd22a33c5bbcc5cdd9807575a5d9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.flagpro."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flagpro"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bc3 55 8d2c3f 55 68???????? 8d1409 52 }
            // n = 7, score = 100
            //   8bc3                 | mov                 eax, ebx
            //   55                   | push                ebp
            //   8d2c3f               | lea                 ebp, [edi + edi]
            //   55                   | push                ebp
            //   68????????           |                     
            //   8d1409               | lea                 edx, [ecx + ecx]
            //   52                   | push                edx

        $sequence_1 = { 89b42494000000 899c2490000000 889c2480000000 39ac24b0000000 7210 8b94249c000000 }
            // n = 6, score = 100
            //   89b42494000000       | mov                 dword ptr [esp + 0x94], esi
            //   899c2490000000       | mov                 dword ptr [esp + 0x90], ebx
            //   889c2480000000       | mov                 byte ptr [esp + 0x80], bl
            //   39ac24b0000000       | cmp                 dword ptr [esp + 0xb0], ebp
            //   7210                 | jb                  0x12
            //   8b94249c000000       | mov                 edx, dword ptr [esp + 0x9c]

        $sequence_2 = { 396c2458 720d 8b4c2444 51 e8???????? 83c404 895c2458 }
            // n = 7, score = 100
            //   396c2458             | cmp                 dword ptr [esp + 0x58], ebp
            //   720d                 | jb                  0xf
            //   8b4c2444             | mov                 ecx, dword ptr [esp + 0x44]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   895c2458             | mov                 dword ptr [esp + 0x58], ebx

        $sequence_3 = { 33d2 c68424984501000f 83bc241c01000010 c744245807000000 c744245400000000 6689542444 }
            // n = 6, score = 100
            //   33d2                 | xor                 edx, edx
            //   c68424984501000f     | mov                 byte ptr [esp + 0x14598], 0xf
            //   83bc241c01000010     | cmp                 dword ptr [esp + 0x11c], 0x10
            //   c744245807000000     | mov                 dword ptr [esp + 0x58], 7
            //   c744245400000000     | mov                 dword ptr [esp + 0x54], 0
            //   6689542444           | mov                 word ptr [esp + 0x44], dx

        $sequence_4 = { 895c2474 89742470 c644246000 396c2458 720d 8b4c2444 }
            // n = 6, score = 100
            //   895c2474             | mov                 dword ptr [esp + 0x74], ebx
            //   89742470             | mov                 dword ptr [esp + 0x70], esi
            //   c644246000           | mov                 byte ptr [esp + 0x60], 0
            //   396c2458             | cmp                 dword ptr [esp + 0x58], ebp
            //   720d                 | jb                  0xf
            //   8b4c2444             | mov                 ecx, dword ptr [esp + 0x44]

        $sequence_5 = { 803c083d 0f8470010000 3b4b14 7609 }
            // n = 4, score = 100
            //   803c083d             | cmp                 byte ptr [eax + ecx], 0x3d
            //   0f8470010000         | je                  0x176
            //   3b4b14               | cmp                 ecx, dword ptr [ebx + 0x14]
            //   7609                 | jbe                 0xb

        $sequence_6 = { eb02 8bc5 8b6c2424 c6043800 45 83fd03 896c2424 }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   8bc5                 | mov                 eax, ebp
            //   8b6c2424             | mov                 ebp, dword ptr [esp + 0x24]
            //   c6043800             | mov                 byte ptr [eax + edi], 0
            //   45                   | inc                 ebp
            //   83fd03               | cmp                 ebp, 3
            //   896c2424             | mov                 dword ptr [esp + 0x24], ebp

        $sequence_7 = { e9???????? 8b542408 8d8274bafeff 8b8a70bafeff }
            // n = 4, score = 100
            //   e9????????           |                     
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   8d8274bafeff         | lea                 eax, [edx - 0x1458c]
            //   8b8a70bafeff         | mov                 ecx, dword ptr [edx - 0x14590]

        $sequence_8 = { 8b44241c 8d542434 895c2434 8b08 52 50 8b4148 }
            // n = 7, score = 100
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   8d542434             | lea                 edx, [esp + 0x34]
            //   895c2434             | mov                 dword ptr [esp + 0x34], ebx
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b4148               | mov                 eax, dword ptr [ecx + 0x48]

        $sequence_9 = { 83c404 51 e8???????? 83ec18 }
            // n = 4, score = 100
            //   83c404               | add                 esp, 4
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83ec18               | sub                 esp, 0x18

    condition:
        7 of them and filesize < 1411072
}
