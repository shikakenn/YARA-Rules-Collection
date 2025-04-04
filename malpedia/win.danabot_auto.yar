rule win_danabot_auto {

    meta:
        id = "3vftujvuYMZMChE75QkIeL"
        fingerprint = "v1_sha256_0aacaade997adfab10265dc65b353035ffe85eb407c689ce61c2eca9a9f37b60"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.danabot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.danabot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b0f 8b16 e8???????? 8b07 50 8b442424 }
            // n = 6, score = 400
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   e8????????           |                     
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   50                   | push                eax
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]

        $sequence_1 = { 0305???????? 8b15???????? 0315???????? 3bc2 7e0a }
            // n = 5, score = 400
            //   0305????????         |                     
            //   8b15????????         |                     
            //   0315????????         |                     
            //   3bc2                 | cmp                 eax, edx
            //   7e0a                 | jle                 0xc

        $sequence_2 = { e8???????? c645f690 c645f790 648f0500000000 }
            // n = 4, score = 400
            //   e8????????           |                     
            //   c645f690             | mov                 byte ptr [ebp - 0xa], 0x90
            //   c645f790             | mov                 byte ptr [ebp - 9], 0x90
            //   648f0500000000       | pop                 dword ptr fs:[0]

        $sequence_3 = { c1e020 03c3 8906 8b06 e8???????? 8b55f8 }
            // n = 6, score = 400
            //   c1e020               | shl                 eax, 0x20
            //   03c3                 | add                 eax, ebx
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   e8????????           |                     
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]

        $sequence_4 = { 8b16 e8???????? 8b07 50 8b442428 50 6a0a }
            // n = 7, score = 400
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   e8????????           |                     
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   50                   | push                eax
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   50                   | push                eax
            //   6a0a                 | push                0xa

        $sequence_5 = { 55 68???????? 64ff30 648920 6a02 6800040000 8b75f8 }
            // n = 7, score = 400
            //   55                   | push                ebp
            //   68????????           |                     
            //   64ff30               | push                dword ptr fs:[eax]
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   6a02                 | push                2
            //   6800040000           | push                0x400
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]

        $sequence_6 = { 50 8b44241c 50 6a0b }
            // n = 4, score = 400
            //   50                   | push                eax
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   50                   | push                eax
            //   6a0b                 | push                0xb

        $sequence_7 = { e8???????? 8d45f8 e8???????? bb???????? 33c0 55 }
            // n = 6, score = 400
            //   e8????????           |                     
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   e8????????           |                     
            //   bb????????           |                     
            //   33c0                 | xor                 eax, eax
            //   55                   | push                ebp

        $sequence_8 = { 68???????? 64ff30 648920 a1???????? a3???????? a1???????? 0305???????? }
            // n = 7, score = 400
            //   68????????           |                     
            //   64ff30               | push                dword ptr fs:[eax]
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   a1????????           |                     
            //   a3????????           |                     
            //   a1????????           |                     
            //   0305????????         |                     

        $sequence_9 = { 8b0424 8b00 8903 8b0424 8b4004 }
            // n = 5, score = 400
            //   8b0424               | mov                 eax, dword ptr [esp]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8903                 | mov                 dword ptr [ebx], eax
            //   8b0424               | mov                 eax, dword ptr [esp]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]

    condition:
        7 of them and filesize < 237568
}
