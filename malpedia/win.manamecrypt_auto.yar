rule win_manamecrypt_auto {

    meta:
        id = "4TtdM5YW6sI6BokkaNoVwm"
        fingerprint = "v1_sha256_11c020fd87769a4886140b70b89c3d00f7ecc070fcd9b6483f651ed35ad73205"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.manamecrypt"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6aff 68???????? 64a100000000 50 b8241c0000 e8???????? }
            // n = 6, score = 100
            //   6aff                 | push                -1
            //   68????????           |                     
            //   64a100000000         | mov                 eax, dword ptr fs:[0]
            //   50                   | push                eax
            //   b8241c0000           | mov                 eax, 0x1c24
            //   e8????????           |                     

        $sequence_1 = { 6a30 50 e8???????? 8d4c2428 51 68???????? 8d942464040000 }
            // n = 7, score = 100
            //   6a30                 | push                0x30
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d4c2428             | lea                 ecx, [esp + 0x28]
            //   51                   | push                ecx
            //   68????????           |                     
            //   8d942464040000       | lea                 edx, [esp + 0x464]

        $sequence_2 = { 7423 807c241500 0f85c5ebffff 80bdd16d000000 0f84b1ebffff 807c241600 }
            // n = 6, score = 100
            //   7423                 | je                  0x25
            //   807c241500           | cmp                 byte ptr [esp + 0x15], 0
            //   0f85c5ebffff         | jne                 0xffffebcb
            //   80bdd16d000000       | cmp                 byte ptr [ebp + 0x6dd1], 0
            //   0f84b1ebffff         | je                  0xffffebb7
            //   807c241600           | cmp                 byte ptr [esp + 0x16], 0

        $sequence_3 = { b9???????? e8???????? 6a00 e8???????? 8d4c2410 }
            // n = 5, score = 100
            //   b9????????           |                     
            //   e8????????           |                     
            //   6a00                 | push                0
            //   e8????????           |                     
            //   8d4c2410             | lea                 ecx, [esp + 0x10]

        $sequence_4 = { 803f7a 8d77fe 0f85db000000 b908000000 b8???????? }
            // n = 5, score = 100
            //   803f7a               | cmp                 byte ptr [edi], 0x7a
            //   8d77fe               | lea                 esi, [edi - 2]
            //   0f85db000000         | jne                 0xe1
            //   b908000000           | mov                 ecx, 8
            //   b8????????           |                     

        $sequence_5 = { 81fb00010000 0f8f2a020000 bd???????? 33f6 }
            // n = 4, score = 100
            //   81fb00010000         | cmp                 ebx, 0x100
            //   0f8f2a020000         | jg                  0x230
            //   bd????????           |                     
            //   33f6                 | xor                 esi, esi

        $sequence_6 = { 83fe07 7515 8bcb e8???????? 83f8ff 0f84ba000000 }
            // n = 6, score = 100
            //   83fe07               | cmp                 esi, 7
            //   7515                 | jne                 0x17
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   0f84ba000000         | je                  0xc0

        $sequence_7 = { 8906 85c0 750a b9???????? e8???????? 897e08 8b4e10 }
            // n = 7, score = 100
            //   8906                 | mov                 dword ptr [esi], eax
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   b9????????           |                     
            //   e8????????           |                     
            //   897e08               | mov                 dword ptr [esi + 8], edi
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]

    condition:
        7 of them and filesize < 1475584
}
