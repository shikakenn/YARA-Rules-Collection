rule win_unidentified_070_auto {

    meta:
        id = "7SYLPbyP3I0WRDA0cjRa93"
        fingerprint = "v1_sha256_45a52b7bdbd7641f0d504c35a74291eb016539e938091cf460316e51b8b9d79b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_070."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_070"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a00 6a00 6a04 50 ff15???????? 8945fc }
            // n = 6, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_1 = { 6a00 6a00 6a00 6a04 50 ff15???????? 8945fc }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_2 = { 6a00 6a00 6a04 50 ff15???????? 8945fc 85c0 }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   85c0                 | test                eax, eax

        $sequence_3 = { 6a04 50 ff15???????? 8945fc 85c0 }
            // n = 5, score = 300
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   85c0                 | test                eax, eax

        $sequence_4 = { 6a00 6a04 50 ff15???????? 8945fc 85c0 }
            // n = 6, score = 300
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   85c0                 | test                eax, eax

        $sequence_5 = { 6a00 6a04 50 ff15???????? 8945fc }
            // n = 5, score = 300
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_6 = { 33c0 c20400 3b0d???????? 7502 }
            // n = 4, score = 300
            //   33c0                 | xor                 eax, eax
            //   c20400               | ret                 4
            //   3b0d????????         |                     
            //   7502                 | jne                 4

        $sequence_7 = { 85db 0f84af000000 6a00 6a00 }
            // n = 4, score = 200
            //   85db                 | test                ebx, ebx
            //   0f84af000000         | je                  0xb5
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_8 = { 742d 68???????? 57 ffd6 a3???????? 85c0 741c }
            // n = 7, score = 200
            //   742d                 | je                  0x2f
            //   68????????           |                     
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   85c0                 | test                eax, eax
            //   741c                 | je                  0x1e

        $sequence_9 = { 6808020000 8d8424d4020000 6a00 50 e8???????? }
            // n = 5, score = 200
            //   6808020000           | push                0x208
            //   8d8424d4020000       | lea                 eax, [esp + 0x2d4]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 90112
}
