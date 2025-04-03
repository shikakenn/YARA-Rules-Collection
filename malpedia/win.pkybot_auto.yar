rule win_pkybot_auto {

    meta:
        id = "795llz0Tr9S1idMCkenqxh"
        fingerprint = "v1_sha256_a42386b2108c9d1af3a399f3ab6d599f676b5aeb865fae8577e3f6311e115c33"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.pkybot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pkybot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83c40c 8d45fc 50 56 ff7510 ff750c }
            // n = 6, score = 1400
            //   83c40c               | add                 esp, 0xc
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_1 = { 85c0 7510 8b4e04 21413c c741300c000000 897938 5f }
            // n = 7, score = 1400
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   21413c               | and                 dword ptr [ecx + 0x3c], eax
            //   c741300c000000       | mov                 dword ptr [ecx + 0x30], 0xc
            //   897938               | mov                 dword ptr [ecx + 0x38], edi
            //   5f                   | pop                 edi

        $sequence_2 = { 894604 e8???????? 6a04 50 }
            // n = 4, score = 1400
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   e8????????           |                     
            //   6a04                 | push                4
            //   50                   | push                eax

        $sequence_3 = { 56 ff7518 57 ff15???????? 56 ff7514 ff7510 }
            // n = 7, score = 1400
            //   56                   | push                esi
            //   ff7518               | push                dword ptr [ebp + 0x18]
            //   57                   | push                edi
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   ff7510               | push                dword ptr [ebp + 0x10]

        $sequence_4 = { 84c0 750e 8b7624 85f6 }
            // n = 4, score = 1400
            //   84c0                 | test                al, al
            //   750e                 | jne                 0x10
            //   8b7624               | mov                 esi, dword ptr [esi + 0x24]
            //   85f6                 | test                esi, esi

        $sequence_5 = { ff15???????? 8bf0 ff15???????? 85c0 7509 85f6 }
            // n = 6, score = 1400
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7509                 | jne                 0xb
            //   85f6                 | test                esi, esi

        $sequence_6 = { e8???????? 8d8e90000000 e8???????? 8d4e44 e8???????? 8bce }
            // n = 6, score = 1400
            //   e8????????           |                     
            //   8d8e90000000         | lea                 ecx, [esi + 0x90]
            //   e8????????           |                     
            //   8d4e44               | lea                 ecx, [esi + 0x44]
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi

        $sequence_7 = { ff15???????? 8b45f0 0b45f4 741b 8b45f8 0b45fc }
            // n = 6, score = 1400
            //   ff15????????         |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   0b45f4               | or                  eax, dword ptr [ebp - 0xc]
            //   741b                 | je                  0x1d
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   0b45fc               | or                  eax, dword ptr [ebp - 4]

        $sequence_8 = { 7512 ff15???????? a3???????? 03c0 }
            // n = 4, score = 1400
            //   7512                 | jne                 0x14
            //   ff15????????         |                     
            //   a3????????           |                     
            //   03c0                 | add                 eax, eax

        $sequence_9 = { ff7510 ff750c 57 ff7508 e8???????? 57 8bd8 }
            // n = 7, score = 1400
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   57                   | push                edi
            //   8bd8                 | mov                 ebx, eax

    condition:
        7 of them and filesize < 204800
}
