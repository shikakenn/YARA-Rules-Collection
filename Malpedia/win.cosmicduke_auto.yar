rule win_cosmicduke_auto {

    meta:
        id = "AMre1nv1gKHz52JZe1t4y"
        fingerprint = "v1_sha256_7c78d88a6294fbefeccb9e02496af3e7aa8e7c4fd27d39a3747c54e6c53a3f19"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.cosmicduke."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cosmicduke"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e9???????? 8db514ffffff e9???????? 8db504ffffff e9???????? b8???????? e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8db514ffffff         | lea                 esi, [ebp - 0xec]
            //   e9????????           |                     
            //   8db504ffffff         | lea                 esi, [ebp - 0xfc]
            //   e9????????           |                     
            //   b8????????           |                     
            //   e9????????           |                     

        $sequence_1 = { ff15???????? 6a02 6a02 6800000040 ff7510 53 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   6a02                 | push                2
            //   6a02                 | push                2
            //   6800000040           | push                0x40000000
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_2 = { c644240f01 85f6 0f8594000000 ff742418 8d842414010000 ff742428 }
            // n = 6, score = 100
            //   c644240f01           | mov                 byte ptr [esp + 0xf], 1
            //   85f6                 | test                esi, esi
            //   0f8594000000         | jne                 0x9a
            //   ff742418             | push                dword ptr [esp + 0x18]
            //   8d842414010000       | lea                 eax, [esp + 0x114]
            //   ff742428             | push                dword ptr [esp + 0x28]

        $sequence_3 = { 668985ecfeffff 0fb645fb 50 0fb645fa 50 0fb645f9 }
            // n = 6, score = 100
            //   668985ecfeffff       | mov                 word ptr [ebp - 0x114], ax
            //   0fb645fb             | movzx               eax, byte ptr [ebp - 5]
            //   50                   | push                eax
            //   0fb645fa             | movzx               eax, byte ptr [ebp - 6]
            //   50                   | push                eax
            //   0fb645f9             | movzx               eax, byte ptr [ebp - 7]

        $sequence_4 = { 56 ff15???????? 885c2417 ebdd 33c9 394c2408 7e0f }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   885c2417             | mov                 byte ptr [esp + 0x17], bl
            //   ebdd                 | jmp                 0xffffffdf
            //   33c9                 | xor                 ecx, ecx
            //   394c2408             | cmp                 dword ptr [esp + 8], ecx
            //   7e0f                 | jle                 0x11

        $sequence_5 = { 5f 85c0 7444 8b442454 8944240c 53 8d442414 }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   85c0                 | test                eax, eax
            //   7444                 | je                  0x46
            //   8b442454             | mov                 eax, dword ptr [esp + 0x54]
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   53                   | push                ebx
            //   8d442414             | lea                 eax, [esp + 0x14]

        $sequence_6 = { 83ffff 7416 8d45e4 50 57 ff15???????? 85c0 }
            // n = 7, score = 100
            //   83ffff               | cmp                 edi, -1
            //   7416                 | je                  0x18
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_7 = { 8bf8 8a8358020000 8bf3 8845ff e8???????? 84c0 0f84ae000000 }
            // n = 7, score = 100
            //   8bf8                 | mov                 edi, eax
            //   8a8358020000         | mov                 al, byte ptr [ebx + 0x258]
            //   8bf3                 | mov                 esi, ebx
            //   8845ff               | mov                 byte ptr [ebp - 1], al
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   0f84ae000000         | je                  0xb4

        $sequence_8 = { 53 53 8d44242c 50 ff15???????? 85c0 740d }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   8d44242c             | lea                 eax, [esp + 0x2c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf

        $sequence_9 = { 8b1d???????? 83c40c 8d842490000000 50 8d842414010000 50 ffd3 }
            // n = 7, score = 100
            //   8b1d????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   8d842490000000       | lea                 eax, [esp + 0x90]
            //   50                   | push                eax
            //   8d842414010000       | lea                 eax, [esp + 0x114]
            //   50                   | push                eax
            //   ffd3                 | call                ebx

    condition:
        7 of them and filesize < 456704
}
