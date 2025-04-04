rule win_pubload_auto {

    meta:
        id = "VPm5AmKmdBv2wpAfGIE5B"
        fingerprint = "v1_sha256_5f25f978a9edba85952ac66b5108bbd65875055e22860f7df1e90762255be210"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.pubload."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pubload"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a5c 68???????? e8???????? 83c408 33c9 }
            // n = 5, score = 1500
            //   6a5c                 | push                0x5c
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c9                 | xor                 ecx, ecx

        $sequence_1 = { 6a00 ff15???????? 6a5c 68???????? e8???????? 83c408 33c9 }
            // n = 7, score = 1500
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a5c                 | push                0x5c
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c9                 | xor                 ecx, ecx

        $sequence_2 = { 6804010000 68???????? 6a00 ff15???????? 6a5c 68???????? }
            // n = 6, score = 1500
            //   6804010000           | push                0x104
            //   68????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a5c                 | push                0x5c
            //   68????????           |                     

        $sequence_3 = { ff15???????? 6a5c 68???????? e8???????? 83c408 33c9 }
            // n = 6, score = 1500
            //   ff15????????         |                     
            //   6a5c                 | push                0x5c
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c9                 | xor                 ecx, ecx

        $sequence_4 = { 68???????? e8???????? 83c408 33c9 68???????? }
            // n = 5, score = 1500
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c9                 | xor                 ecx, ecx
            //   68????????           |                     

        $sequence_5 = { 6804010000 68???????? 6a00 ff15???????? 6a5c 68???????? e8???????? }
            // n = 7, score = 1500
            //   6804010000           | push                0x104
            //   68????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a5c                 | push                0x5c
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_6 = { e8???????? 83c408 33c9 68???????? }
            // n = 4, score = 1500
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c9                 | xor                 ecx, ecx
            //   68????????           |                     

        $sequence_7 = { 68???????? e8???????? 83c408 33c9 68???????? 66894802 ff15???????? }
            // n = 7, score = 1500
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c9                 | xor                 ecx, ecx
            //   68????????           |                     
            //   66894802             | mov                 word ptr [eax + 2], cx
            //   ff15????????         |                     

        $sequence_8 = { 83c408 33c9 68???????? 66894802 ff15???????? }
            // n = 5, score = 1500
            //   83c408               | add                 esp, 8
            //   33c9                 | xor                 ecx, ecx
            //   68????????           |                     
            //   66894802             | mov                 word ptr [eax + 2], cx
            //   ff15????????         |                     

        $sequence_9 = { 6a00 6a00 6a00 ff15???????? c3 }
            // n = 5, score = 1500
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 524288
}
