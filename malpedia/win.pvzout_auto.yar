rule win_pvzout_auto {

    meta:
        id = "Ay24qZUQQTNR4Ano8l3GN"
        fingerprint = "v1_sha256_ba6cffc93be56b2981aa18b2dfb2d12dcc79b5b9f031aee7308eec09fd3e12bc"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.pvzout."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pvzout"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0e 75a8 43 2f }
            // n = 4, score = 200
            //   0e                   | push                cs
            //   75a8                 | jne                 0xffffffaa
            //   43                   | inc                 ebx
            //   2f                   | das                 

        $sequence_1 = { 0e 75a8 43 1dea50873a d4a1 }
            // n = 5, score = 200
            //   0e                   | push                cs
            //   75a8                 | jne                 0xffffffaa
            //   43                   | inc                 ebx
            //   1dea50873a           | sbb                 eax, 0x3a8750ea
            //   d4a1                 | aam                 0xa1

        $sequence_2 = { e21c 3e3f 19e9 73f8 dca10ebd24e8 252b0026cb 9e }
            // n = 7, score = 200
            //   e21c                 | loop                0x1e
            //   3e3f                 | aas                 
            //   19e9                 | sbb                 ecx, ebp
            //   73f8                 | jae                 0xfffffffa
            //   dca10ebd24e8         | fsub                qword ptr [ecx - 0x17db42f2]
            //   252b0026cb           | and                 eax, 0xcb26002b
            //   9e                   | sahf                

        $sequence_3 = { 75a8 43 2f 3089f33d80f3 }
            // n = 4, score = 200
            //   75a8                 | jne                 0xffffffaa
            //   43                   | inc                 ebx
            //   2f                   | das                 
            //   3089f33d80f3         | xor                 byte ptr [ecx - 0xc7fc20d], cl

        $sequence_4 = { 03dd 81eb00d00200 83bd8804000000 899d88040000 0f85cb030000 8d8594040000 50 }
            // n = 7, score = 200
            //   03dd                 | add                 ebx, ebp
            //   81eb00d00200         | sub                 ebx, 0x2d000
            //   83bd8804000000       | cmp                 dword ptr [ebp + 0x488], 0
            //   899d88040000         | mov                 dword ptr [ebp + 0x488], ebx
            //   0f85cb030000         | jne                 0x3d1
            //   8d8594040000         | lea                 eax, [ebp + 0x494]
            //   50                   | push                eax

        $sequence_5 = { b8132d0000 50 038588040000 59 0bc9 89850e040000 61 }
            // n = 7, score = 200
            //   b8132d0000           | mov                 eax, 0x2d13
            //   50                   | push                eax
            //   038588040000         | add                 eax, dword ptr [ebp + 0x488]
            //   59                   | pop                 ecx
            //   0bc9                 | or                  ecx, ecx
            //   89850e040000         | mov                 dword ptr [ebp + 0x40e], eax
            //   61                   | popal               

        $sequence_6 = { 01e3 b105 18830d88a01c 51 }
            // n = 4, score = 200
            //   01e3                 | add                 ebx, esp
            //   b105                 | mov                 cl, 5
            //   18830d88a01c         | sbb                 byte ptr [ebx + 0x1ca0880d], al
            //   51                   | push                ecx

        $sequence_7 = { bf95f6810e 75a8 43 1dea50873a d4a1 }
            // n = 5, score = 200
            //   bf95f6810e           | mov                 edi, 0xe81f695
            //   75a8                 | jne                 0xffffffaa
            //   43                   | inc                 ebx
            //   1dea50873a           | sbb                 eax, 0x3a8750ea
            //   d4a1                 | aam                 0xa1

        $sequence_8 = { 5d bbedffffff 03dd 81eb00d00200 83bd8804000000 899d88040000 0f85cb030000 }
            // n = 7, score = 200
            //   5d                   | pop                 ebp
            //   bbedffffff           | mov                 ebx, 0xffffffed
            //   03dd                 | add                 ebx, ebp
            //   81eb00d00200         | sub                 ebx, 0x2d000
            //   83bd8804000000       | cmp                 dword ptr [ebp + 0x488], 0
            //   899d88040000         | mov                 dword ptr [ebp + 0x488], ebx
            //   0f85cb030000         | jne                 0x3d1

        $sequence_9 = { b3d7 5a bf95f6810e 75a8 43 1dea50873a }
            // n = 6, score = 200
            //   b3d7                 | mov                 bl, 0xd7
            //   5a                   | pop                 edx
            //   bf95f6810e           | mov                 edi, 0xe81f695
            //   75a8                 | jne                 0xffffffaa
            //   43                   | inc                 ebx
            //   1dea50873a           | sbb                 eax, 0x3a8750ea

    condition:
        7 of them and filesize < 573440
}
