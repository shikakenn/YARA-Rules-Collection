rule win_roopy_auto {

    meta:
        id = "5PY6zm1Zh1nZnAgzlNDLo7"
        fingerprint = "v1_sha256_635b23691aea648c5b01623163933331eba5c241a10085695aa02ee95522aae1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.roopy."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.roopy"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c7404800000000 c7404c00000000 eb15 8b55f8 8b8590fdffff 894248 8b8594fdffff }
            // n = 7, score = 300
            //   c7404800000000       | mov                 dword ptr [eax + 0x48], 0
            //   c7404c00000000       | mov                 dword ptr [eax + 0x4c], 0
            //   eb15                 | jmp                 0x17
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b8590fdffff         | mov                 eax, dword ptr [ebp - 0x270]
            //   894248               | mov                 dword ptr [edx + 0x48], eax
            //   8b8594fdffff         | mov                 eax, dword ptr [ebp - 0x26c]

        $sequence_1 = { f3a4 0fb7859cfcffff 68ff000000 8d8d70fbffff baffffffff }
            // n = 5, score = 300
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   0fb7859cfcffff       | movzx               eax, word ptr [ebp - 0x364]
            //   68ff000000           | push                0xff
            //   8d8d70fbffff         | lea                 ecx, [ebp - 0x490]
            //   baffffffff           | mov                 edx, 0xffffffff

        $sequence_2 = { 7fbe 8d85ccefffff 50 6801100000 8d85d0efffff 50 ff75e4 }
            // n = 7, score = 300
            //   7fbe                 | jg                  0xffffffc0
            //   8d85ccefffff         | lea                 eax, [ebp - 0x1034]
            //   50                   | push                eax
            //   6801100000           | push                0x1001
            //   8d85d0efffff         | lea                 eax, [ebp - 0x1030]
            //   50                   | push                eax
            //   ff75e4               | push                dword ptr [ebp - 0x1c]

        $sequence_3 = { 8d55f8 8b45f0 ff15???????? 8d55fc 89d8 }
            // n = 5, score = 300
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   ff15????????         |                     
            //   8d55fc               | lea                 edx, [ebp - 4]
            //   89d8                 | mov                 eax, ebx

        $sequence_4 = { e8???????? 39d6 7c06 7f0a 39c3 7706 c6042401 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   39d6                 | cmp                 esi, edx
            //   7c06                 | jl                  8
            //   7f0a                 | jg                  0xc
            //   39c3                 | cmp                 ebx, eax
            //   7706                 | ja                  8
            //   c6042401             | mov                 byte ptr [esp], 1

        $sequence_5 = { 89c2 83ea01 8b45f8 8b4004 e8???????? }
            // n = 5, score = 300
            //   89c2                 | mov                 edx, eax
            //   83ea01               | sub                 edx, 1
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   e8????????           |                     

        $sequence_6 = { 89c7 89fa b8???????? e8???????? 8b5654 895024 89f8 }
            // n = 7, score = 300
            //   89c7                 | mov                 edi, eax
            //   89fa                 | mov                 edx, edi
            //   b8????????           |                     
            //   e8????????           |                     
            //   8b5654               | mov                 edx, dword ptr [esi + 0x54]
            //   895024               | mov                 dword ptr [eax + 0x24], edx
            //   89f8                 | mov                 eax, edi

        $sequence_7 = { 89de 89f0 e8???????? 89c7 89d3 8b45fc }
            // n = 6, score = 300
            //   89de                 | mov                 esi, ebx
            //   89f0                 | mov                 eax, esi
            //   e8????????           |                     
            //   89c7                 | mov                 edi, eax
            //   89d3                 | mov                 ebx, edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_8 = { 8b45a4 8d5058 8b4da4 8b412c b91c000000 e8???????? 83459001 }
            // n = 7, score = 300
            //   8b45a4               | mov                 eax, dword ptr [ebp - 0x5c]
            //   8d5058               | lea                 edx, [eax + 0x58]
            //   8b4da4               | mov                 ecx, dword ptr [ebp - 0x5c]
            //   8b412c               | mov                 eax, dword ptr [ecx + 0x2c]
            //   b91c000000           | mov                 ecx, 0x1c
            //   e8????????           |                     
            //   83459001             | add                 dword ptr [ebp - 0x70], 1

        $sequence_9 = { 8d858cfcffff 30c9 6631d2 e8???????? 0fb785a4fcffff 68ff000000 8d8d70fbffff }
            // n = 7, score = 300
            //   8d858cfcffff         | lea                 eax, [ebp - 0x374]
            //   30c9                 | xor                 cl, cl
            //   6631d2               | xor                 dx, dx
            //   e8????????           |                     
            //   0fb785a4fcffff       | movzx               eax, word ptr [ebp - 0x35c]
            //   68ff000000           | push                0xff
            //   8d8d70fbffff         | lea                 ecx, [ebp - 0x490]

    condition:
        7 of them and filesize < 739328
}
