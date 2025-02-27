rule win_shatteredglass_auto {

    meta:
        id = "6GDrlYJoCD3j2tFQs4fzF0"
        fingerprint = "v1_sha256_01b6c47460c5c08264d9ff26f8c68c9d17064a107dafa21abd25815194e46710"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.shatteredglass."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shatteredglass"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 59 eb3c 8b9530e5ffff 8b8528e5ffff 8b8d24e5ffff 8b0485d0d14100 f644010440 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   eb3c                 | jmp                 0x3e
            //   8b9530e5ffff         | mov                 edx, dword ptr [ebp - 0x1ad0]
            //   8b8528e5ffff         | mov                 eax, dword ptr [ebp - 0x1ad8]
            //   8b8d24e5ffff         | mov                 ecx, dword ptr [ebp - 0x1adc]
            //   8b0485d0d14100       | mov                 eax, dword ptr [eax*4 + 0x41d1d0]
            //   f644010440           | test                byte ptr [ecx + eax + 4], 0x40

        $sequence_1 = { ff15???????? 57 ff15???????? 8b4dfc 8a45e7 33cd 5f }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8a45e7               | mov                 al, byte ptr [ebp - 0x19]
            //   33cd                 | xor                 ecx, ebp
            //   5f                   | pop                 edi

        $sequence_2 = { 75f5 2bce d1f9 83f918 }
            // n = 4, score = 100
            //   75f5                 | jne                 0xfffffff7
            //   2bce                 | sub                 ecx, esi
            //   d1f9                 | sar                 ecx, 1
            //   83f918               | cmp                 ecx, 0x18

        $sequence_3 = { 68???????? 56 ffd7 68???????? 68???????? 8d85f8feffff }
            // n = 6, score = 100
            //   68????????           |                     
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   68????????           |                     
            //   68????????           |                     
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]

        $sequence_4 = { 7c88 33f6 8d9b00000000 0fb70c73 }
            // n = 4, score = 100
            //   7c88                 | jl                  0xffffff8a
            //   33f6                 | xor                 esi, esi
            //   8d9b00000000         | lea                 ebx, [ebx]
            //   0fb70c73             | movzx               ecx, word ptr [ebx + esi*2]

        $sequence_5 = { 8d4900 0fb70c77 8d41d0 6683f809 7705 }
            // n = 5, score = 100
            //   8d4900               | lea                 ecx, [ecx]
            //   0fb70c77             | movzx               ecx, word ptr [edi + esi*2]
            //   8d41d0               | lea                 eax, [ecx - 0x30]
            //   6683f809             | cmp                 ax, 9
            //   7705                 | ja                  7

        $sequence_6 = { 68???????? 68???????? e8???????? 8b3d???????? 83c408 837c241001 7576 }
            // n = 7, score = 100
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   8b3d????????         |                     
            //   83c408               | add                 esp, 8
            //   837c241001           | cmp                 dword ptr [esp + 0x10], 1
            //   7576                 | jne                 0x78

        $sequence_7 = { b810000000 2bc6 50 8d8640d74100 50 57 ffd3 }
            // n = 7, score = 100
            //   b810000000           | mov                 eax, 0x10
            //   2bc6                 | sub                 eax, esi
            //   50                   | push                eax
            //   8d8640d74100         | lea                 eax, [esi + 0x41d740]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ffd3                 | call                ebx

        $sequence_8 = { 888840d74100 83fe20 7c88 8b3d???????? }
            // n = 4, score = 100
            //   888840d74100         | mov                 byte ptr [eax + 0x41d740], cl
            //   83fe20               | cmp                 esi, 0x20
            //   7c88                 | jl                  0xffffff8a
            //   8b3d????????         |                     

        $sequence_9 = { 8d410d 8d642400 8a08 8a5001 8a6802 8a70ff }
            // n = 6, score = 100
            //   8d410d               | lea                 eax, [ecx + 0xd]
            //   8d642400             | lea                 esp, [esp]
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   8a5001               | mov                 dl, byte ptr [eax + 1]
            //   8a6802               | mov                 ch, byte ptr [eax + 2]
            //   8a70ff               | mov                 dh, byte ptr [eax - 1]

    condition:
        7 of them and filesize < 273408
}
