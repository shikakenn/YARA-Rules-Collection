rule win_odinaff_auto {

    meta:
        id = "456wd6pYE3CmyoyuGArJlX"
        fingerprint = "v1_sha256_30f018bdaf01e341e417353febba3580b7f1e98a76ca0b650eefbf84ad5901ef"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.odinaff."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.odinaff"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 56 ff15???????? 837dfc00 b801000000 7503 8b45e4 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   ff15????????         |                     
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   b801000000           | mov                 eax, 1
            //   7503                 | jne                 5
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_1 = { 8b45f8 83c410 85c0 7408 50 6a00 }
            // n = 6, score = 200
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_2 = { 8d55f0 52 ff15???????? 85c0 0f84ea000000 8b45ec }
            // n = 6, score = 200
            //   8d55f0               | lea                 edx, [ebp - 0x10]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84ea000000         | je                  0xf0
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

        $sequence_3 = { c7458044000000 ff15???????? 8b4dfc 53 68???????? 51 ff15???????? }
            // n = 7, score = 200
            //   c7458044000000       | mov                 dword ptr [ebp - 0x80], 0x44
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   53                   | push                ebx
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_4 = { 50 c745e400000000 ff15???????? 8b35???????? 8d7808 57 6a08 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   8d7808               | lea                 edi, [eax + 8]
            //   57                   | push                edi
            //   6a08                 | push                8

        $sequence_5 = { 668910 8b55f4 8d4df0 51 52 6a02 c745f000080000 }
            // n = 7, score = 200
            //   668910               | mov                 word ptr [eax], dx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   6a02                 | push                2
            //   c745f000080000       | mov                 dword ptr [ebp - 0x10], 0x800

        $sequence_6 = { 51 52 52 6a20 6a01 52 }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   52                   | push                edx
            //   52                   | push                edx
            //   6a20                 | push                0x20
            //   6a01                 | push                1
            //   52                   | push                edx

        $sequence_7 = { 6808020000 56 6a00 8bf8 }
            // n = 4, score = 200
            //   6808020000           | push                0x208
            //   56                   | push                esi
            //   6a00                 | push                0
            //   8bf8                 | mov                 edi, eax

        $sequence_8 = { 53 52 8945fc 895de0 }
            // n = 4, score = 200
            //   53                   | push                ebx
            //   52                   | push                edx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx

        $sequence_9 = { 8b1d???????? 50 ffd3 8b4d10 }
            // n = 4, score = 200
            //   8b1d????????         |                     
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]

    condition:
        7 of them and filesize < 73728
}
