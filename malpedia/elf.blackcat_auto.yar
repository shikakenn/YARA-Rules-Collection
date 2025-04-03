rule elf_blackcat_auto {

    meta:
        id = "3igifgfKs71mfgT94cEepS"
        fingerprint = "v1_sha256_630d3dc7c9122b8f92125090dcb7617ef29586df7b1f7e85bb11a06ca666eb4d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects elf.blackcat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.blackcat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 81fa???????? 720d b805000000 81faffffff0f }
            // n = 4, score = 200
            //   81fa????????         |                     
            //   720d                 | mov                 dword ptr [esp + 0x24], ebx
            //   b805000000           | pshufd              xmm1, xmm0, 0x44
            //   81faffffff0f         | pshufd              xmm2, xmm0, 0xee

        $sequence_1 = { 7227 b903000000 81fa???????? 721a }
            // n = 4, score = 200
            //   7227                 | mov                 dword ptr [eax], esi
            //   b903000000           | mov                 word ptr [eax + 0x5c], 2
            //   81fa????????         |                     
            //   721a                 | mov                 word ptr [eax + 0x5c], 2

        $sequence_2 = { 81f9???????? 0f823fffffff b802000000 81f9???????? 0f822effffff }
            // n = 5, score = 200
            //   81f9????????         |                     
            //   0f823fffffff         | jne                 0xfffffffd
            //   b802000000           | cmp                 dword ptr [edi + 8], 3
            //   81f9????????         |                     
            //   0f822effffff         | mov                 dword ptr [esp + 0x18], ecx

        $sequence_3 = { 0f823fffffff b802000000 81f9???????? 0f822effffff }
            // n = 4, score = 200
            //   0f823fffffff         | mov                 dword ptr [esp + 0xa0], edx
            //   b802000000           | mov                 edx, dword ptr [ebx + 0x24]
            //   81f9????????         |                     
            //   0f822effffff         | mov                 esi, dword ptr [eax]

        $sequence_4 = { 721a b804000000 81fa???????? 720d b805000000 81faffffff0f }
            // n = 6, score = 200
            //   721a                 | dec                 eax
            //   b804000000           | mov                 edi, dword ptr [ebp + 0x10]
            //   81fa????????         |                     
            //   720d                 | dec                 eax
            //   b805000000           | mov                 eax, dword ptr [ebp + 0x38]
            //   81faffffff0f         | jb                  0x486

        $sequence_5 = { b802000000 81f9???????? 7227 b803000000 81f9???????? 721a }
            // n = 6, score = 200
            //   b802000000           | mov                 dword ptr [esp + 0x34c], edx
            //   81f9????????         |                     
            //   7227                 | lea                 esi, [esp + 0x340]
            //   b803000000           | mov                 eax, dword ptr [esp + 0x2c]
            //   81f9????????         |                     
            //   721a                 | mov                 eax, 1

        $sequence_6 = { 6685db 7404 660fbccb 0fb7c9 }
            // n = 4, score = 200
            //   6685db               | nop                 word ptr cs:[eax + eax]
            //   7404                 | nop                 
            //   660fbccb             | dec                 eax
            //   0fb7c9               | cmp                 edi, ebx

        $sequence_7 = { 81fa???????? 721a b904000000 81fa???????? }
            // n = 4, score = 200
            //   81fa????????         |                     
            //   721a                 | mov                 dword ptr [esp + 0x18], esi
            //   b904000000           | mov                 eax, ecx
            //   81fa????????         |                     

        $sequence_8 = { 81f9???????? 0f823fffffff b802000000 81f9???????? }
            // n = 4, score = 200
            //   81f9????????         |                     
            //   0f823fffffff         | jne                 0x2b6
            //   b802000000           | mov                 eax, dword ptr [ebx + eax*4 - 0x4ee4c]
            //   81f9????????         |                     

        $sequence_9 = { 0fb6c8 8d1489 8d0cd1 c1e90c 6bd164 28d0 }
            // n = 6, score = 200
            //   0fb6c8               | mov                 eax, dword ptr [esp + 0x160]
            //   8d1489               | inc                 ecx
            //   8d0cd1               | mov                 dword ptr [esp + 0x24], eax
            //   c1e90c               | mov                 byte ptr [esp + 0x71], 1
            //   6bd164               | movzx               eax, word ptr [esp + 0x17c]
            //   28d0                 | movzx               eax, byte ptr [esp + 0x165]

    condition:
        7 of them and filesize < 8011776
}
