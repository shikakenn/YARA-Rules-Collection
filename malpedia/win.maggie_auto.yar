rule win_maggie_auto {

    meta:
        id = "1mLUnVJiEFCyBZq6zdJzHl"
        fingerprint = "v1_sha256_f79cbc6ae2d70c9e6484e5066353afb6506cea51f8ea75e10ee4458493abfd34"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.maggie."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maggie"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7511 ff15???????? 85c0 7407 33c0 e9???????? }
            // n = 6, score = 300
            //   7511                 | inc                 esp
            //   ff15????????         |                     
            //   85c0                 | mov                 dword ptr [esp + 0x30], ebp
            //   7407                 | dec                 eax
            //   33c0                 | lea                 edx, [esp + 0x5a0]
            //   e9????????           |                     

        $sequence_1 = { 663b05???????? 7505 e8???????? e8???????? }
            // n = 4, score = 300
            //   663b05????????       |                     
            //   7505                 | dec                 eax
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_2 = { 663b05???????? 7505 e8???????? e8???????? 84c0 }
            // n = 5, score = 300
            //   663b05????????       |                     
            //   7505                 | jne                 0x1fc2
            //   e8????????           |                     
            //   e8????????           |                     
            //   84c0                 | dec                 eax

        $sequence_3 = { 83f8ff 750f ff15???????? 2d33270000 f7d8 }
            // n = 5, score = 300
            //   83f8ff               | dec                 esp
            //   750f                 | lea                 eax, [0x25d85]
            //   ff15????????         |                     
            //   2d33270000           | jmp                 0x194e
            //   f7d8                 | dec                 eax

        $sequence_4 = { 750f ff15???????? 2d33270000 f7d8 }
            // n = 4, score = 300
            //   750f                 | dec                 esp
            //   ff15????????         |                     
            //   2d33270000           | mov                 dword ptr [esp + 0x910], ebp
            //   f7d8                 | dec                 eax

        $sequence_5 = { ff15???????? 83f8ff 750f ff15???????? 2d33270000 f7d8 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   83f8ff               | dec                 eax
            //   750f                 | mov                 edx, ebx
            //   ff15????????         |                     
            //   2d33270000           | dec                 eax
            //   f7d8                 | mov                 dword ptr [esp + 0x20], 0x100

        $sequence_6 = { 83f8ff 750f ff15???????? 2d33270000 f7d8 1bc0 }
            // n = 6, score = 300
            //   83f8ff               | mov                 dword ptr [esp + 0x20], edi
            //   750f                 | jmp                 0x1c8
            //   ff15????????         |                     
            //   2d33270000           | dec                 eax
            //   f7d8                 | arpl                ax, dx
            //   1bc0                 | dec                 eax

        $sequence_7 = { ff15???????? 83f8ff 750f ff15???????? 2d33270000 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   83f8ff               | mov                 eax, dword ptr [ebp + 8]
            //   750f                 | pop                 ecx
            //   ff15????????         |                     
            //   2d33270000           | mov                 dword ptr [ebp - 8], eax

        $sequence_8 = { 750f ff15???????? 2d33270000 f7d8 1bc0 }
            // n = 5, score = 300
            //   750f                 | dec                 eax
            //   ff15????????         |                     
            //   2d33270000           | mov                 ecx, dword ptr [eax + 0x18]
            //   f7d8                 | dec                 eax
            //   1bc0                 | mov                 eax, dword ptr [ecx]

        $sequence_9 = { b8ff000000 663b05???????? 7505 e8???????? e8???????? }
            // n = 5, score = 300
            //   b8ff000000           | je                  0x13d2
            //   663b05????????       |                     
            //   7505                 | dec                 ecx
            //   e8????????           |                     
            //   e8????????           |                     

    condition:
        7 of them and filesize < 611328
}
