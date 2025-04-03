rule win_nimbo_c2_auto {

    meta:
        id = "5DB3ex1tee82hAqPQMZPN4"
        fingerprint = "v1_sha256_8589aa9b6f63efad7fde0dd033ffc7aedc0446802bcc3cc8f7fcdbf116768199"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.nimbo_c2."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nimbo_c2"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7f16 31d2 4889d9 e8???????? ba01000000 4885c0 480f4fc2 }
            // n = 7, score = 500
            //   7f16                 | add                 esp, 0x48
            //   31d2                 | pop                 ebx
            //   4889d9               | pop                 esi
            //   e8????????           |                     
            //   ba01000000           | dec                 esp
            //   4885c0               | mov                 ecx, ebp
            //   480f4fc2             | dec                 esp

        $sequence_1 = { c744245801000000 e8???????? b90f000000 4989c5 4885c0 7407 488b00 }
            // n = 7, score = 500
            //   c744245801000000     | dec                 eax
            //   e8????????           |                     
            //   b90f000000           | lea                 ecx, [0x65447]
            //   4989c5               | inc                 ecx
            //   4885c0               | push                esp
            //   7407                 | push                esi
            //   488b00               | push                ebx

        $sequence_2 = { 83e03f 41886c1c13 83c880 4188441c12 eb9d 85c0 789c }
            // n = 7, score = 500
            //   83e03f               | lea                 ebx, [0x44053]
            //   41886c1c13           | dec                 esp
            //   83c880               | lea                 edx, [0x2d1c7]
            //   4188441c12           | dec                 esp
            //   eb9d                 | lea                 ebx, [0x43ea3]
            //   85c0                 | dec                 eax
            //   789c                 | lea                 eax, [0x5162e]

        $sequence_3 = { e8???????? ebe3 e8???????? 4889c1 e8???????? 4883bdd8fcffff00 7414 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   ebe3                 | cmp                 dword ptr [eax], 0
            //   e8????????           |                     
            //   4889c1               | jne                 0x536
            //   e8????????           |                     
            //   4883bdd8fcffff00     | mov                 ecx, 0x34
            //   7414                 | dec                 eax

        $sequence_4 = { 4889c1 e8???????? ba20000000 4889c1 e8???????? 4989c4 4885ff }
            // n = 7, score = 500
            //   4889c1               | dec                 ebp
            //   e8????????           |                     
            //   ba20000000           | add                 ebp, esp
            //   4889c1               | dec                 esp
            //   e8????????           |                     
            //   4989c4               | add                 ebx, esi
            //   4885ff               | dec                 esp

        $sequence_5 = { 741a 49837d0000 7e13 4c89e1 e8???????? 4c89ea }
            // n = 6, score = 500
            //   741a                 | dec                 eax
            //   49837d0000           | mov                 edx, dword ptr [esp + 0xa8]
            //   7e13                 | inc                 ebp
            //   4c89e1               | xor                 ebp, ebp
            //   e8????????           |                     
            //   4c89ea               | dec                 eax

        $sequence_6 = { c7859cfcffff00000000 ff5018 8905???????? 85c0 0f85f6020000 488d8dc8fcffff e8???????? }
            // n = 7, score = 500
            //   c7859cfcffff00000000     | sub    esp, 0x28
            //   ff5018               | dec                 eax
            //   8905????????         |                     
            //   85c0                 | mov                 eax, dword ptr [ecx]
            //   0f85f6020000         | dec                 esi
            //   488d8dc8fcffff       | mov                 esp, dword ptr [eax + eax*8 + 0x10]
            //   e8????????           |                     

        $sequence_7 = { 56 53 4883ec20 31f6 4889cb 0fb6fa 4885db }
            // n = 7, score = 500
            //   56                   | je                  0x1762
            //   53                   | dec                 eax
            //   4883ec20             | mov                 dword ptr [ebp - 0x670], eax
            //   31f6                 | dec                 eax
            //   4889cb               | test                eax, eax
            //   0fb6fa               | jne                 0x17de
            //   4885db               | dec                 esp

        $sequence_8 = { c605????????01 48c705????????02000000 c605????????01 48c705????????03000000 48c705????????04000000 c605????????02 }
            // n = 6, score = 500
            //   c605????????01       |                     
            //   48c705????????02000000     |     
            //   c605????????01       |                     
            //   48c705????????03000000     |     
            //   48c705????????04000000     |     
            //   c605????????02       |                     

        $sequence_9 = { b907000000 4c8b8424c0000000 ba03000000 4d89ce e8???????? ba03000000 b906000000 }
            // n = 7, score = 500
            //   b907000000           | mov                 esi, dword ptr [ebp - 0x668]
            //   4c8b8424c0000000     | dec                 eax
            //   ba03000000           | lea                 edx, [ebp - 0x634]
            //   4d89ce               | inc                 ecx
            //   e8????????           |                     
            //   ba03000000           | mov                 ecx, 1
            //   b906000000           | dec                 esp

    condition:
        7 of them and filesize < 1141760
}
