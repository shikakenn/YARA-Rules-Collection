rule win_unidentified_087_auto {

    meta:
        id = "7YDdHD9qE6UbpT7V0m9kN0"
        fingerprint = "v1_sha256_10f141206749e7e53bb829c93df64c19732ef1dad0c95b847ac5042b772c3c95"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_087."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_087"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 488bc3 4a8d1429 488d0c38 4d8bc4 4903d4 4c2bc5 4803cd }
            // n = 7, score = 200
            //   488bc3               | mov                 ecx, 0x8000
            //   4a8d1429             | dec                 eax
            //   488d0c38             | mov                 ecx, esi
            //   4d8bc4               | nop                 
            //   4903d4               | inc                 sp
            //   4c2bc5               | mov                 dword ptr [eax], ebp
            //   4803cd               | inc                 esp

        $sequence_1 = { 488bce ff15???????? 90 e9???????? 66448928 44896c2460 ff15???????? }
            // n = 7, score = 200
            //   488bce               | inc                 ebp
            //   ff15????????         |                     
            //   90                   | xor                 eax, eax
            //   e9????????           |                     
            //   66448928             | dec                 eax
            //   44896c2460           | mov                 edx, esi
            //   ff15????????         |                     

        $sequence_2 = { 7415 41b900800000 4533c0 488bd6 488bcf ff15???????? }
            // n = 6, score = 200
            //   7415                 | movzx               esi, word ptr [ebp + 0x26]
            //   41b900800000         | inc                 esp
            //   4533c0               | movzx               ecx, word ptr [ebp + 0x24]
            //   488bd6               | mov                 dword ptr [esp + 0x60], eax
            //   488bcf               | mov                 dword ptr [esp + 0x58], ecx
            //   ff15????????         |                     

        $sequence_3 = { bb01000000 4885f6 7415 41b900800000 }
            // n = 4, score = 200
            //   bb01000000           | mov                 dword ptr [esp + 0x50], edx
            //   4885f6               | je                  0x17
            //   7415                 | inc                 ecx
            //   41b900800000         | mov                 ecx, 0x8000

        $sequence_4 = { 488bc8 4c8d442460 418d542428 ff15???????? }
            // n = 4, score = 200
            //   488bc8               | dec                 eax
            //   4c8d442460           | mov                 ecx, edi
            //   418d542428           | mov                 ebx, 1
            //   ff15????????         |                     

        $sequence_5 = { 0fb77526 440fb74d24 89442460 894c2458 89542450 }
            // n = 5, score = 200
            //   0fb77526             | dec                 eax
            //   440fb74d24           | add                 edx, esi
            //   89442460             | dec                 eax
            //   894c2458             | cmp                 dword ptr [ebx + 0x18], 0x10
            //   89542450             | jb                  7

        $sequence_6 = { 4d8bc4 ba08030000 ff15???????? e9???????? 4c8d4c2430 4533c0 }
            // n = 6, score = 200
            //   4d8bc4               | dec                 eax
            //   ba08030000           | test                esi, esi
            //   ff15????????         |                     
            //   e9????????           |                     
            //   4c8d4c2430           | je                  0x17
            //   4533c0               | inc                 ecx

        $sequence_7 = { 4a8d0c28 4d8bc6 4803cd 4803d6 e8???????? 48837b1810 7205 }
            // n = 7, score = 200
            //   4a8d0c28             | dec                 edx
            //   4d8bc6               | lea                 ecx, [eax + ebp]
            //   4803cd               | dec                 ebp
            //   4803d6               | mov                 eax, esi
            //   e8????????           |                     
            //   48837b1810           | dec                 eax
            //   7205                 | add                 ecx, ebp

        $sequence_8 = { a1???????? 83f803 7409 83f801 0f8535fcffff 8b0d???????? }
            // n = 6, score = 100
            //   a1????????           |                     
            //   83f803               | inc                 ebp
            //   7409                 | xor                 eax, eax
            //   83f801               | dec                 eax
            //   0f8535fcffff         | mov                 eax, ebx
            //   8b0d????????         |                     

        $sequence_9 = { eb54 83460801 83560c00 8807 8b0e 8b5104 8b443238 }
            // n = 7, score = 100
            //   eb54                 | inc                 ecx
            //   83460801             | lea                 edx, [esp + 0x28]
            //   83560c00             | dec                 ebp
            //   8807                 | mov                 eax, esp
            //   8b0e                 | mov                 edx, 0x308
            //   8b5104               | dec                 esp
            //   8b443238             | lea                 ecx, [esp + 0x30]

        $sequence_10 = { 7435 83e805 0f8510010000 a1???????? 8b4d10 }
            // n = 5, score = 100
            //   7435                 | dec                 eax
            //   83e805               | mov                 edx, edi
            //   0f8510010000         | jmp                 0x56
            //   a1????????           |                     
            //   8b4d10               | add                 dword ptr [esi + 8], 1

        $sequence_11 = { 83f804 0f8542010000 83ec1c 8bcc }
            // n = 4, score = 100
            //   83f804               | add                 ecx, ebp
            //   0f8542010000         | dec                 eax
            //   83ec1c               | cmp                 dword ptr [edi + 0x18], 0x10
            //   8bcc                 | jae                 0x16

        $sequence_12 = { 8d4db4 e8???????? 32c0 e9???????? 8b8d54ffffff 6aff }
            // n = 6, score = 100
            //   8d4db4               | adc                 dword ptr [esi + 0xc], 0
            //   e8????????           |                     
            //   32c0                 | mov                 byte ptr [edi], al
            //   e9????????           |                     
            //   8b8d54ffffff         | mov                 ecx, dword ptr [esi]
            //   6aff                 | mov                 edx, dword ptr [ecx + 4]

        $sequence_13 = { 50 c685fcfbffff00 e8???????? 8b5508 83c40c }
            // n = 5, score = 100
            //   50                   | dec                 esp
            //   c685fcfbffff00       | mov                 eax, dword ptr [edi + 0x10]
            //   e8????????           |                     
            //   8b5508               | dec                 ecx
            //   83c40c               | inc                 eax

        $sequence_14 = { 56 ff15???????? 85c0 75e7 eb0e 8d4c242c 51 }
            // n = 7, score = 100
            //   56                   | dec                 edx
            //   ff15????????         |                     
            //   85c0                 | lea                 edx, [ecx + ebp]
            //   75e7                 | dec                 eax
            //   eb0e                 | lea                 ecx, [eax + edi]
            //   8d4c242c             | dec                 ebp
            //   51                   | mov                 eax, esp

        $sequence_15 = { 0fb685e6feffff 0fb68de5feffff 52 0fb695e4feffff 50 }
            // n = 5, score = 100
            //   0fb685e6feffff       | dec                 ecx
            //   0fb68de5feffff       | add                 edx, esp
            //   52                   | dec                 esp
            //   0fb695e4feffff       | sub                 eax, ebp
            //   50                   | dec                 eax

    condition:
        7 of them and filesize < 462848
}
