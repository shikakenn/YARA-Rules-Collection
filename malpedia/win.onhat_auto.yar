rule win_onhat_auto {

    meta:
        id = "DWuxPXGx7ODxtcqO64RAX"
        fingerprint = "v1_sha256_3d8264647f2b4bfebfbb64b6330e4d7098e25f3b002acba0b19c8992974ae5d6"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.onhat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.onhat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 85c0 0f842b010000 6888130000 8d8c2424010000 6a10 51 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f842b010000         | je                  0x131
            //   6888130000           | push                0x1388
            //   8d8c2424010000       | lea                 ecx, [esp + 0x124]
            //   6a10                 | push                0x10
            //   51                   | push                ecx

        $sequence_1 = { 50 c68424d90000004e c68424da00000054 c68424db00000041 c68424dc00000048 889c24dd000000 c68424de00000045 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   c68424d90000004e     | mov                 byte ptr [esp + 0xd9], 0x4e
            //   c68424da00000054     | mov                 byte ptr [esp + 0xda], 0x54
            //   c68424db00000041     | mov                 byte ptr [esp + 0xdb], 0x41
            //   c68424dc00000048     | mov                 byte ptr [esp + 0xdc], 0x48
            //   889c24dd000000       | mov                 byte ptr [esp + 0xdd], bl
            //   c68424de00000045     | mov                 byte ptr [esp + 0xde], 0x45

        $sequence_2 = { 66894c2412 e8???????? 83f8ff 0f85a7000000 b04e b243 }
            // n = 6, score = 200
            //   66894c2412           | mov                 word ptr [esp + 0x12], cx
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   0f85a7000000         | jne                 0xad
            //   b04e                 | mov                 al, 0x4e
            //   b243                 | mov                 dl, 0x43

        $sequence_3 = { 33c9 8a4c2426 52 c1e818 }
            // n = 4, score = 200
            //   33c9                 | xor                 ecx, ecx
            //   8a4c2426             | mov                 cl, byte ptr [esp + 0x26]
            //   52                   | push                edx
            //   c1e818               | shr                 eax, 0x18

        $sequence_4 = { c68424ca0000004f c68424cc00000070 c68424ce00000050 c68424d000000073 c68424d200000074 c68424d400000000 }
            // n = 6, score = 200
            //   c68424ca0000004f     | mov                 byte ptr [esp + 0xca], 0x4f
            //   c68424cc00000070     | mov                 byte ptr [esp + 0xcc], 0x70
            //   c68424ce00000050     | mov                 byte ptr [esp + 0xce], 0x50
            //   c68424d000000073     | mov                 byte ptr [esp + 0xd0], 0x73
            //   c68424d200000074     | mov                 byte ptr [esp + 0xd2], 0x74
            //   c68424d400000000     | mov                 byte ptr [esp + 0xd4], 0

        $sequence_5 = { 51 8b4c2458 50 52 51 }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   8b4c2458             | mov                 ecx, dword ptr [esp + 0x58]
            //   50                   | push                eax
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_6 = { ffd6 8b2d???????? 8d842494000000 50 }
            // n = 4, score = 200
            //   ffd6                 | call                esi
            //   8b2d????????         |                     
            //   8d842494000000       | lea                 eax, [esp + 0x94]
            //   50                   | push                eax

        $sequence_7 = { 890d???????? 5b c3 8b048e 8a10 }
            // n = 5, score = 200
            //   890d????????         |                     
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8b048e               | mov                 eax, dword ptr [esi + ecx*4]
            //   8a10                 | mov                 dl, byte ptr [eax]

        $sequence_8 = { 6a00 57 c744241c01000000 e8???????? 85c0 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   57                   | push                edi
            //   c744241c01000000     | mov                 dword ptr [esp + 0x1c], 1
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8b542440 52 8b542428 50 8b442464 50 }
            // n = 6, score = 200
            //   8b542440             | mov                 edx, dword ptr [esp + 0x40]
            //   52                   | push                edx
            //   8b542428             | mov                 edx, dword ptr [esp + 0x28]
            //   50                   | push                eax
            //   8b442464             | mov                 eax, dword ptr [esp + 0x64]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 57344
}
