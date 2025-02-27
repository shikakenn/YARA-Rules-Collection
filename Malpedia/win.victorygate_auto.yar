rule win_victorygate_auto {

    meta:
        id = "4IFi1C7cFUsryJs27kzkKG"
        fingerprint = "v1_sha256_427b2d98b9c3c2aa99b815ff597c75e43d477300e8035fd3554b7df3486b4eb0"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.victorygate."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.victorygate"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 009bb3410050 ba410050ba 41 0050ba 41 0050ba 41 }
            // n = 7, score = 100
            //   009bb3410050         | add                 byte ptr [ebx + 0x500041b3], bl
            //   ba410050ba           | mov                 edx, 0xba500041
            //   41                   | inc                 ecx
            //   0050ba               | add                 byte ptr [eax - 0x46], dl
            //   41                   | inc                 ecx
            //   0050ba               | add                 byte ptr [eax - 0x46], dl
            //   41                   | inc                 ecx

        $sequence_1 = { c745e800000000 c745ec0f000000 c645d800 e8???????? 57 51 8d45d8 }
            // n = 7, score = 100
            //   c745e800000000       | mov                 dword ptr [ebp - 0x18], 0
            //   c745ec0f000000       | mov                 dword ptr [ebp - 0x14], 0xf
            //   c645d800             | mov                 byte ptr [ebp - 0x28], 0
            //   e8????????           |                     
            //   57                   | push                edi
            //   51                   | push                ecx
            //   8d45d8               | lea                 eax, [ebp - 0x28]

        $sequence_2 = { 745c 5f 5b c60000 33c0 5e }
            // n = 6, score = 100
            //   745c                 | je                  0x5e
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   c60000               | mov                 byte ptr [eax], 0
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi

        $sequence_3 = { 85c0 740d 50 e8???????? 83c404 8bf8 eb21 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bf8                 | mov                 edi, eax
            //   eb21                 | jmp                 0x23

        $sequence_4 = { c1fa04 8bf2 c1ee1f 03f2 f7e9 c1fa04 8bc2 }
            // n = 7, score = 100
            //   c1fa04               | sar                 edx, 4
            //   8bf2                 | mov                 esi, edx
            //   c1ee1f               | shr                 esi, 0x1f
            //   03f2                 | add                 esi, edx
            //   f7e9                 | imul                ecx
            //   c1fa04               | sar                 edx, 4
            //   8bc2                 | mov                 eax, edx

        $sequence_5 = { 8b460c 8d7e0c 85c0 7556 8bce e8???????? 85c0 }
            // n = 7, score = 100
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   8d7e0c               | lea                 edi, [esi + 0xc]
            //   85c0                 | test                eax, eax
            //   7556                 | jne                 0x58
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_6 = { 680c2b0000 68???????? 68???????? ff15???????? 8b0d???????? 6a00 6a02 }
            // n = 7, score = 100
            //   680c2b0000           | push                0x2b0c
            //   68????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b0d????????         |                     
            //   6a00                 | push                0
            //   6a02                 | push                2

        $sequence_7 = { e8???????? 8d55f0 8bc8 e8???????? 8b45f0 c645fc01 8b55e8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d55f0               | lea                 edx, [ebp - 0x10]
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]

        $sequence_8 = { 8d86e0010000 6a36 50 ff15???????? 85c0 0f850b070000 ff75f8 }
            // n = 7, score = 100
            //   8d86e0010000         | lea                 eax, [esi + 0x1e0]
            //   6a36                 | push                0x36
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f850b070000         | jne                 0x711
            //   ff75f8               | push                dword ptr [ebp - 8]

        $sequence_9 = { ff15???????? 85c0 0f852b010000 ff75f8 8d8688020000 6a5b 50 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f852b010000         | jne                 0x131
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   8d8688020000         | lea                 eax, [esi + 0x288]
            //   6a5b                 | push                0x5b
            //   50                   | push                eax

    condition:
        7 of them and filesize < 1209344
}
