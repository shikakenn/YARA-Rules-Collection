rule win_ehdevel_auto {

    meta:
        id = "LBadmTnoMhDvlPsBJeeYi"
        fingerprint = "v1_sha256_9b05c9bc40d7442213206fba6f4d684a37ffe66d5cd633b4545ba4a54fb64f27"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.ehdevel."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ehdevel"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c744240c00040000 89742418 ff15???????? 68???????? e8???????? 83c404 5e }
            // n = 7, score = 100
            //   c744240c00040000     | mov                 dword ptr [esp + 0xc], 0x400
            //   89742418             | mov                 dword ptr [esp + 0x18], esi
            //   ff15????????         |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   5e                   | pop                 esi

        $sequence_1 = { 52 8b95ece7ffff 50 51 52 c685f3e7ffff00 e8???????? }
            // n = 7, score = 100
            //   52                   | push                edx
            //   8b95ece7ffff         | mov                 edx, dword ptr [ebp - 0x1814]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   52                   | push                edx
            //   c685f3e7ffff00       | mov                 byte ptr [ebp - 0x180d], 0
            //   e8????????           |                     

        $sequence_2 = { 6a00 6800000040 8d85f4efffff 50 ff15???????? 8bf0 }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   6800000040           | push                0x40000000
            //   8d85f4efffff         | lea                 eax, [ebp - 0x100c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_3 = { 33cc e8???????? 8be5 5d c3 8d442410 68???????? }
            // n = 7, score = 100
            //   33cc                 | xor                 ecx, esp
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   68????????           |                     

        $sequence_4 = { 898dc48bffff e8???????? 83c408 8985e88bffff }
            // n = 4, score = 100
            //   898dc48bffff         | mov                 dword ptr [ebp - 0x743c], ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8985e88bffff         | mov                 dword ptr [ebp - 0x7418], eax

        $sequence_5 = { 668955d4 e8???????? 8bce c745fc0a000000 e8???????? c745fcffffffff }
            // n = 6, score = 100
            //   668955d4             | mov                 word ptr [ebp - 0x2c], dx
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   c745fc0a000000       | mov                 dword ptr [ebp - 4], 0xa
            //   e8????????           |                     
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff

        $sequence_6 = { 8b95ece7ffff 83c404 52 e8???????? 8b85ece7ffff 83c404 }
            // n = 6, score = 100
            //   8b95ece7ffff         | mov                 edx, dword ptr [ebp - 0x1814]
            //   83c404               | add                 esp, 4
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b85ece7ffff         | mov                 eax, dword ptr [ebp - 0x1814]
            //   83c404               | add                 esp, 4

        $sequence_7 = { 6800008000 6a00 6a00 6a00 8d8df88bffff 51 }
            // n = 6, score = 100
            //   6800008000           | push                0x800000
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d8df88bffff         | lea                 ecx, [ebp - 0x7408]
            //   51                   | push                ecx

        $sequence_8 = { 8b4df8 83c404 5f 33cd b001 }
            // n = 5, score = 100
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   83c404               | add                 esp, 4
            //   5f                   | pop                 edi
            //   33cd                 | xor                 ecx, ebp
            //   b001                 | mov                 al, 1

        $sequence_9 = { 7514 68???????? 6800040000 8d842408080000 50 eb28 68???????? }
            // n = 7, score = 100
            //   7514                 | jne                 0x16
            //   68????????           |                     
            //   6800040000           | push                0x400
            //   8d842408080000       | lea                 eax, [esp + 0x808]
            //   50                   | push                eax
            //   eb28                 | jmp                 0x2a
            //   68????????           |                     

    condition:
        7 of them and filesize < 524288
}
