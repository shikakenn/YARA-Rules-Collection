rule win_mebromi_auto {

    meta:
        id = "1cFlck57Y1xM2VofFMBzl"
        fingerprint = "v1_sha256_051f5b8119e90ef14be758def00ef62b697ce727969ed9523ac57414d0773faf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mebromi."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mebromi"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 5f eb26 8d4508 8db694702900 6a00 }
            // n = 5, score = 100
            //   5f                   | pop                 edi
            //   eb26                 | jmp                 0x28
            //   8d4508               | lea                 eax, [ebp + 8]
            //   8db694702900         | lea                 esi, [esi + 0x297094]
            //   6a00                 | push                0

        $sequence_1 = { b82c2900d8 2c29 0000 2d29008a46 0323 }
            // n = 5, score = 100
            //   b82c2900d8           | mov                 eax, 0xd800292c
            //   2c29                 | sub                 al, 0x29
            //   0000                 | add                 byte ptr [eax], al
            //   2d29008a46           | sub                 eax, 0x468a0029
            //   0323                 | add                 esp, dword ptr [ebx]

        $sequence_2 = { 8bec 8b4508 ff348520712900 ff15???????? }
            // n = 4, score = 100
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff348520712900       | push                dword ptr [eax*4 + 0x297120]
            //   ff15????????         |                     

        $sequence_3 = { eb0f 0fb6d2 f68201a0290004 7403 }
            // n = 4, score = 100
            //   eb0f                 | jmp                 0x11
            //   0fb6d2               | movzx               edx, dl
            //   f68201a0290004       | test                byte ptr [edx + 0x29a001], 4
            //   7403                 | je                  5

        $sequence_4 = { 56 ffd7 3bdd 5b }
            // n = 4, score = 100
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   3bdd                 | cmp                 ebx, ebp
            //   5b                   | pop                 ebx

        $sequence_5 = { 68000000c0 68???????? ff15???????? 8b3d???????? 83f8ff a3???????? 7544 }
            // n = 7, score = 100
            //   68000000c0           | push                0xc0000000
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b3d????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   a3????????           |                     
            //   7544                 | jne                 0x46

        $sequence_6 = { 58 c20c00 ff05???????? 833d????????01 55 56 57 }
            // n = 7, score = 100
            //   58                   | pop                 eax
            //   c20c00               | ret                 0xc
            //   ff05????????         |                     
            //   833d????????01       |                     
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_7 = { 68???????? ff742410 ff15???????? 8bf0 85f6 7416 57 }
            // n = 7, score = 100
            //   68????????           |                     
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7416                 | je                  0x18
            //   57                   | push                edi

        $sequence_8 = { 8888009f2900 eb1f 83f861 7213 83f87a }
            // n = 5, score = 100
            //   8888009f2900         | mov                 byte ptr [eax + 0x299f00], cl
            //   eb1f                 | jmp                 0x21
            //   83f861               | cmp                 eax, 0x61
            //   7213                 | jb                  0x15
            //   83f87a               | cmp                 eax, 0x7a

        $sequence_9 = { ff742410 ff15???????? 8bf0 85f6 7416 57 56 }
            // n = 7, score = 100
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7416                 | je                  0x18
            //   57                   | push                edi
            //   56                   | push                esi

    condition:
        7 of them and filesize < 106496
}
