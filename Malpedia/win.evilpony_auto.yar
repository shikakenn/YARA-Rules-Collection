rule win_evilpony_auto {

    meta:
        id = "1KTuUfiYACXKN6n4UPGfEL"
        fingerprint = "v1_sha256_ffd9f8ba97fbd907290551898893cb44ef48c12bf2cd21edd5aa01ba36ae5a3e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.evilpony."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.evilpony"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a04 8d9ddcf7ffff c785dcf7ffff1000efbe e8???????? ffb5f0f7ffff 8bc7 }
            // n = 6, score = 200
            //   6a04                 | push                4
            //   8d9ddcf7ffff         | lea                 ebx, [ebp - 0x824]
            //   c785dcf7ffff1000efbe     | mov    dword ptr [ebp - 0x824], 0xbeef0010
            //   e8????????           |                     
            //   ffb5f0f7ffff         | push                dword ptr [ebp - 0x810]
            //   8bc7                 | mov                 eax, edi

        $sequence_1 = { 85ff 7423 8bc6 e8???????? 56 }
            // n = 5, score = 200
            //   85ff                 | test                edi, edi
            //   7423                 | je                  0x25
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   56                   | push                esi

        $sequence_2 = { 8d8c019979825a c14db002 8bc2 3345e4 894da8 3345cc 3345c4 }
            // n = 7, score = 200
            //   8d8c019979825a       | lea                 ecx, [ecx + eax + 0x5a827999]
            //   c14db002             | ror                 dword ptr [ebp - 0x50], 2
            //   8bc2                 | mov                 eax, edx
            //   3345e4               | xor                 eax, dword ptr [ebp - 0x1c]
            //   894da8               | mov                 dword ptr [ebp - 0x58], ecx
            //   3345cc               | xor                 eax, dword ptr [ebp - 0x34]
            //   3345c4               | xor                 eax, dword ptr [ebp - 0x3c]

        $sequence_3 = { 55 8bec 56 6885010000 6a40 ff15???????? 8bf0 }
            // n = 7, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   6885010000           | push                0x185
            //   6a40                 | push                0x40
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_4 = { e8???????? 83c414 6a00 6a00 57 56 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_5 = { ff15???????? 85c0 0f85b0000000 56 57 8b3d???????? 33f6 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f85b0000000         | jne                 0xb6
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b3d????????         |                     
            //   33f6                 | xor                 esi, esi

        $sequence_6 = { 83c410 85ff 7420 688c000000 6a40 ff15???????? }
            // n = 6, score = 200
            //   83c410               | add                 esp, 0x10
            //   85ff                 | test                edi, edi
            //   7420                 | je                  0x22
            //   688c000000           | push                0x8c
            //   6a40                 | push                0x40
            //   ff15????????         |                     

        $sequence_7 = { 53 89442438 ff5114 3bf7 7510 }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   89442438             | mov                 dword ptr [esp + 0x38], eax
            //   ff5114               | call                dword ptr [ecx + 0x14]
            //   3bf7                 | cmp                 esi, edi
            //   7510                 | jne                 0x12

        $sequence_8 = { e8???????? 83c40c ff750c 6a1c ff7508 e8???????? 83c40c }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   6a1c                 | push                0x1c
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_9 = { 8b55b0 3345d8 2355ac 3345c4 894da8 d1c0 8945e4 }
            // n = 7, score = 200
            //   8b55b0               | mov                 edx, dword ptr [ebp - 0x50]
            //   3345d8               | xor                 eax, dword ptr [ebp - 0x28]
            //   2355ac               | and                 edx, dword ptr [ebp - 0x54]
            //   3345c4               | xor                 eax, dword ptr [ebp - 0x3c]
            //   894da8               | mov                 dword ptr [ebp - 0x58], ecx
            //   d1c0                 | rol                 eax, 1
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

    condition:
        7 of them and filesize < 147456
}
