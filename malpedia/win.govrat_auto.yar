rule win_govrat_auto {

    meta:
        id = "1BsU9BuGFfpvhBnpxUurHX"
        fingerprint = "v1_sha256_c76f210fc8b3b328515ee8d578bc776ba7dc3be5b77e3088a18f7d949286c3a2"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.govrat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.govrat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c1fa05 8b1495609e4300 83e61f c1e606 f644320480 7417 8bd1 }
            // n = 7, score = 200
            //   c1fa05               | sar                 edx, 5
            //   8b1495609e4300       | mov                 edx, dword ptr [edx*4 + 0x439e60]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   f644320480           | test                byte ptr [edx + esi + 4], 0x80
            //   7417                 | je                  0x19
            //   8bd1                 | mov                 edx, ecx

        $sequence_1 = { 5b c3 55 8bec 81ec84010000 a1???????? 33c5 }
            // n = 7, score = 200
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec84010000         | sub                 esp, 0x184
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp

        $sequence_2 = { d1f8 e8???????? 5e c20800 807c240400 7428 837e1808 }
            // n = 7, score = 200
            //   d1f8                 | sar                 eax, 1
            //   e8????????           |                     
            //   5e                   | pop                 esi
            //   c20800               | ret                 8
            //   807c240400           | cmp                 byte ptr [esp + 4], 0
            //   7428                 | je                  0x2a
            //   837e1808             | cmp                 dword ptr [esi + 0x18], 8

        $sequence_3 = { e8???????? 8b4658 85c0 755f 83ff14 720e 3945f8 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b4658               | mov                 eax, dword ptr [esi + 0x58]
            //   85c0                 | test                eax, eax
            //   755f                 | jne                 0x61
            //   83ff14               | cmp                 edi, 0x14
            //   720e                 | jb                  0x10
            //   3945f8               | cmp                 dword ptr [ebp - 8], eax

        $sequence_4 = { 2aca d3e8 8bca d3e7 8d8ba00e0300 51 03c7 }
            // n = 7, score = 200
            //   2aca                 | sub                 cl, dl
            //   d3e8                 | shr                 eax, cl
            //   8bca                 | mov                 ecx, edx
            //   d3e7                 | shl                 edi, cl
            //   8d8ba00e0300         | lea                 ecx, [ebx + 0x30ea0]
            //   51                   | push                ecx
            //   03c7                 | add                 eax, edi

        $sequence_5 = { c605????????01 e8???????? 837df808 8b45e4 7303 8d45e4 68???????? }
            // n = 7, score = 200
            //   c605????????01       |                     
            //   e8????????           |                     
            //   837df808             | cmp                 dword ptr [ebp - 8], 8
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   7303                 | jae                 5
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   68????????           |                     

        $sequence_6 = { 7406 ff15???????? 68d0070000 ff15???????? 6a02 ff15???????? 81fe01000b80 }
            // n = 7, score = 200
            //   7406                 | je                  8
            //   ff15????????         |                     
            //   68d0070000           | push                0x7d0
            //   ff15????????         |                     
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   81fe01000b80         | cmp                 esi, 0x800b0001

        $sequence_7 = { 83c004 2bfa 4f 8938 83c004 5f 5e }
            // n = 7, score = 200
            //   83c004               | add                 eax, 4
            //   2bfa                 | sub                 edi, edx
            //   4f                   | dec                 edi
            //   8938                 | mov                 dword ptr [eax], edi
            //   83c004               | add                 eax, 4
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_8 = { 68???????? eb05 68???????? e8???????? 50 8d4594 50 }
            // n = 7, score = 200
            //   68????????           |                     
            //   eb05                 | jmp                 7
            //   68????????           |                     
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d4594               | lea                 eax, [ebp - 0x6c]
            //   50                   | push                eax

        $sequence_9 = { 0345f8 8b4d14 8904b1 46 3b7510 72e4 5e }
            // n = 7, score = 200
            //   0345f8               | add                 eax, dword ptr [ebp - 8]
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   8904b1               | mov                 dword ptr [ecx + esi*4], eax
            //   46                   | inc                 esi
            //   3b7510               | cmp                 esi, dword ptr [ebp + 0x10]
            //   72e4                 | jb                  0xffffffe6
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 761856
}
