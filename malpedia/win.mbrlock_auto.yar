rule win_mbrlock_auto {

    meta:
        id = "5saOLAEDLYNxD2CsTiKcck"
        fingerprint = "v1_sha256_491b9f4fb168bceb19b5cf7b6c98ee71ee5564cadbcb31d189925e8a478d4bf3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mbrlock."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mbrlock"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7e26 8b4510 57 83c004 53 50 ff15???????? }
            // n = 7, score = 100
            //   7e26                 | jle                 0x28
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   57                   | push                edi
            //   83c004               | add                 eax, 4
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_1 = { 50 ff15???????? 8b0d???????? 8945fc eb25 81ff34080000 7c39 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b0d????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   eb25                 | jmp                 0x27
            //   81ff34080000         | cmp                 edi, 0x834
            //   7c39                 | jl                  0x3b

        $sequence_2 = { 84c3 7521 8ad0 b980850110 0ad3 8815???????? }
            // n = 6, score = 100
            //   84c3                 | test                bl, al
            //   7521                 | jne                 0x23
            //   8ad0                 | mov                 dl, al
            //   b980850110           | mov                 ecx, 0x10018580
            //   0ad3                 | or                  dl, bl
            //   8815????????         |                     

        $sequence_3 = { 0bc1 894de8 7519 68fc5a0110 6a02 684b030000 68d4580110 }
            // n = 7, score = 100
            //   0bc1                 | or                  eax, ecx
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   7519                 | jne                 0x1b
            //   68fc5a0110           | push                0x10015afc
            //   6a02                 | push                2
            //   684b030000           | push                0x34b
            //   68d4580110           | push                0x100158d4

        $sequence_4 = { 8965f0 8975ec 893e ff15???????? 50 8945e4 68a0620110 }
            // n = 7, score = 100
            //   8965f0               | mov                 dword ptr [ebp - 0x10], esp
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   893e                 | mov                 dword ptr [esi], edi
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   68a0620110           | push                0x100162a0

        $sequence_5 = { e8???????? 8b442434 c744242000000000 83f803 0f87cb000000 ff248540504000 56 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   c744242000000000     | mov                 dword ptr [esp + 0x20], 0
            //   83f803               | cmp                 eax, 3
            //   0f87cb000000         | ja                  0xd1
            //   ff248540504000       | jmp                 dword ptr [eax*4 + 0x405040]
            //   56                   | push                esi

        $sequence_6 = { 68d4580110 e8???????? 83c410 8b55c8 6a00 6a00 52 }
            // n = 7, score = 100
            //   68d4580110           | push                0x100158d4
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8b55c8               | mov                 edx, dword ptr [ebp - 0x38]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   52                   | push                edx

        $sequence_7 = { 8b4508 c1f805 8d1c8500f74e00 8b4508 83e01f 8d34c0 }
            // n = 6, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   c1f805               | sar                 eax, 5
            //   8d1c8500f74e00       | lea                 ebx, [eax*4 + 0x4ef700]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83e01f               | and                 eax, 0x1f
            //   8d34c0               | lea                 esi, [eax + eax*8]

        $sequence_8 = { 68af010000 6898610110 e8???????? 83c410 8b45ec 85c0 7416 }
            // n = 7, score = 100
            //   68af010000           | push                0x1af
            //   6898610110           | push                0x10016198
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   85c0                 | test                eax, eax
            //   7416                 | je                  0x18

        $sequence_9 = { c1e602 8932 5e b801000000 5b c21800 33c9 }
            // n = 7, score = 100
            //   c1e602               | shl                 esi, 2
            //   8932                 | mov                 dword ptr [edx], esi
            //   5e                   | pop                 esi
            //   b801000000           | mov                 eax, 1
            //   5b                   | pop                 ebx
            //   c21800               | ret                 0x18
            //   33c9                 | xor                 ecx, ecx

    condition:
        7 of them and filesize < 2031616
}
