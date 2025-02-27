rule win_mount_locker_auto {

    meta:
        id = "72b8jRY7c9H5AdCtob36iC"
        fingerprint = "v1_sha256_7b77b6c0c433631050c62ceb54745fc365be8fc933570e0c4c919105bbc01b03"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mount_locker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mount_locker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 498be8 4d8bc8 4c8bc2 4c8bf2 }
            // n = 4, score = 500
            //   498be8               | dec                 esp
            //   4d8bc8               | lea                 eax, [esp + 0x30]
            //   4c8bc2               | dec                 eax
            //   4c8bf2               | and                 dword ptr [esp + 0x20], 0

        $sequence_1 = { f30f5905???????? 0f5ad0 66490f7ed0 e8???????? }
            // n = 4, score = 500
            //   f30f5905????????     |                     
            //   0f5ad0               | inc                 ebp
            //   66490f7ed0           | xor                 ecx, ecx
            //   e8????????           |                     

        $sequence_2 = { 488b0b 41b902000000 4533c0 33d2 }
            // n = 4, score = 500
            //   488b0b               | dec                 eax
            //   41b902000000         | mov                 ecx, dword ptr [esp + 0x58]
            //   4533c0               | xor                 edx, edx
            //   33d2                 | mov                 dword ptr [esp + 0x30], 1

        $sequence_3 = { 4533c9 488b4c2458 33d2 c744243001000000 }
            // n = 4, score = 500
            //   4533c9               | mov                 esi, edx
            //   488b4c2458           | mov                 esi, ecx
            //   33d2                 | xor                 edx, edx
            //   c744243001000000     | xor                 ecx, ecx

        $sequence_4 = { 4c8bc2 4c8bf2 8bf1 33d2 }
            // n = 4, score = 500
            //   4c8bc2               | dec                 esp
            //   4c8bf2               | mov                 eax, edx
            //   8bf1                 | dec                 esp
            //   33d2                 | mov                 esi, edx

        $sequence_5 = { 488d4df0 4889442428 4533c9 4533c0 }
            // n = 4, score = 500
            //   488d4df0             | mov                 ecx, eax
            //   4889442428           | dec                 esp
            //   4533c9               | mov                 eax, edx
            //   4533c0               | dec                 esp

        $sequence_6 = { 8bc8 81e10000ffff 81f900000780 7503 0fb7c0 }
            // n = 5, score = 500
            //   8bc8                 | mov                 ebp, eax
            //   81e10000ffff         | dec                 ebp
            //   81f900000780         | mov                 ecx, eax
            //   7503                 | dec                 esp
            //   0fb7c0               | mov                 eax, edx

        $sequence_7 = { 4c8b05???????? 488bcb 488b15???????? e8???????? 85c0 }
            // n = 5, score = 500
            //   4c8b05????????       |                     
            //   488bcb               | mov                 esi, ecx
            //   488b15????????       |                     
            //   e8????????           |                     
            //   85c0                 | xor                 edx, edx

        $sequence_8 = { 7505 e8???????? 833d????????00 7409 833d????????00 7505 e8???????? }
            // n = 7, score = 300
            //   7505                 | mov                 ecx, dword ptr [esp + 0x58]
            //   e8????????           |                     
            //   833d????????00       |                     
            //   7409                 | xor                 edx, edx
            //   833d????????00       |                     
            //   7505                 | mov                 dword ptr [esp + 0x30], 1
            //   e8????????           |                     

        $sequence_9 = { ff15???????? 85c0 7509 f0ff05???????? }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   85c0                 | mov                 eax, edx
            //   7509                 | dec                 esp
            //   f0ff05????????       |                     

        $sequence_10 = { 415e 5f 5e c3 488bc4 48895010 4c894018 }
            // n = 7, score = 300
            //   415e                 | xor                 ecx, ecx
            //   5f                   | dec                 eax
            //   5e                   | mov                 ecx, dword ptr [esp + 0x58]
            //   c3                   | xor                 edx, edx
            //   488bc4               | mov                 dword ptr [esp + 0x30], 1
            //   48895010             | dec                 ecx
            //   4c894018             | mov                 ebp, eax

        $sequence_11 = { 6a01 ff15???????? 8d4538 50 68???????? }
            // n = 5, score = 100
            //   6a01                 | mov                 dword ptr [esp + 0x3c], 2
            //   ff15????????         |                     
            //   8d4538               | dec                 ebp
            //   50                   | mov                 ecx, eax
            //   68????????           |                     

        $sequence_12 = { 83ef01 75ec 6a20 59 8a06 884620 46 }
            // n = 7, score = 100
            //   83ef01               | mov                 esi, ecx
            //   75ec                 | xor                 edx, edx
            //   6a20                 | dec                 esp
            //   59                   | lea                 eax, [esp + 0x30]
            //   8a06                 | dec                 eax
            //   884620               | and                 dword ptr [esp + 0x20], 0
            //   46                   | inc                 ebp

        $sequence_13 = { 68???????? e8???????? 8d45c0 50 ff750c }
            // n = 5, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   8d45c0               | mov                 dword ptr [esp + 0x3c], 2
            //   50                   | dec                 eax
            //   ff750c               | lea                 ecx, [ebp - 0x10]

        $sequence_14 = { 6815020100 6a08 83ceff ff15???????? 50 }
            // n = 5, score = 100
            //   6815020100           | dec                 esp
            //   6a08                 | mov                 eax, edx
            //   83ceff               | dec                 esp
            //   ff15????????         |                     
            //   50                   | mov                 esi, edx

        $sequence_15 = { 68???????? 6a01 e8???????? 83c40c 5e c3 56 }
            // n = 7, score = 100
            //   68????????           |                     
            //   6a01                 | xor                 ecx, ecx
            //   e8????????           |                     
            //   83c40c               | dec                 eax
            //   5e                   | mov                 ecx, dword ptr [esp + 0x58]
            //   c3                   | xor                 edx, edx
            //   56                   | mov                 dword ptr [esp + 0x30], 1

    condition:
        7 of them and filesize < 368640
}
