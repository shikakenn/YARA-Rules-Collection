rule win_murofet_auto {

    meta:
        id = "6yZE58CohOrFb7a0Uhyj4U"
        fingerprint = "v1_sha256_9298e47cf759c52371e794c7e892c3c0542296ba15da499ce2f22bd9f2d8e48e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.murofet."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.murofet"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? a2???????? 84c0 7510 e8???????? 3c04 }
            // n = 6, score = 300
            //   e8????????           |                     
            //   a2????????           |                     
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4

        $sequence_1 = { e8???????? a2???????? 84c0 7510 e8???????? 3c04 73ce }
            // n = 7, score = 300
            //   e8????????           |                     
            //   a2????????           |                     
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0

        $sequence_2 = { 7510 e8???????? 3c04 73ce b002 }
            // n = 5, score = 300
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0
            //   b002                 | mov                 al, 2

        $sequence_3 = { 56 ff15???????? c6443eff00 83f8ff 7509 56 ff15???????? }
            // n = 7, score = 300
            //   56                   | push                esi
            //   ff15????????         |                     
            //   c6443eff00           | mov                 byte ptr [esi + edi - 1], 0
            //   83f8ff               | cmp                 eax, -1
            //   7509                 | jne                 0xb
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_4 = { 72e5 e8???????? a2???????? 84c0 }
            // n = 4, score = 300
            //   72e5                 | jb                  0xffffffe7
            //   e8????????           |                     
            //   a2????????           |                     
            //   84c0                 | test                al, al

        $sequence_5 = { 8816 e8???????? 0fb6c0 99 }
            // n = 4, score = 300
            //   8816                 | mov                 byte ptr [esi], dl
            //   e8????????           |                     
            //   0fb6c0               | movzx               eax, al
            //   99                   | cdq                 

        $sequence_6 = { 6a10 8d4624 55 50 ff15???????? }
            // n = 5, score = 300
            //   6a10                 | push                0x10
            //   8d4624               | lea                 eax, [esi + 0x24]
            //   55                   | push                ebp
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_7 = { a2???????? 84c0 7510 e8???????? 3c04 73ce b002 }
            // n = 7, score = 300
            //   a2????????           |                     
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0
            //   b002                 | mov                 al, 2

        $sequence_8 = { a2???????? 84c0 7510 e8???????? 3c04 73ce }
            // n = 6, score = 300
            //   a2????????           |                     
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0

        $sequence_9 = { 8d4624 55 50 ff15???????? }
            // n = 4, score = 300
            //   8d4624               | lea                 eax, [esi + 0x24]
            //   55                   | push                ebp
            //   50                   | push                eax
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 622592
}
