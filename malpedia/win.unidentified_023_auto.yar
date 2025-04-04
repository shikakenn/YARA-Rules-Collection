rule win_unidentified_023_auto {

    meta:
        id = "3qu4Ha0bdH3IbAj58AdWub"
        fingerprint = "v1_sha256_1eec10f2afa6bd7e6a1d69558f2f25a771bedb385bd839fc0b4d5b578eec4086"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_023."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_023"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 68???????? ff15???????? 3bf4 e8???????? b801000000 52 }
            // n = 6, score = 200
            //   68????????           |                     
            //   ff15????????         |                     
            //   3bf4                 | cmp                 esi, esp
            //   e8????????           |                     
            //   b801000000           | mov                 eax, 1
            //   52                   | push                edx

        $sequence_1 = { 894df4 8a15???????? 8855f8 837d0c01 7514 8bf4 68???????? }
            // n = 7, score = 200
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8a15????????         |                     
            //   8855f8               | mov                 byte ptr [ebp - 8], dl
            //   837d0c01             | cmp                 dword ptr [ebp + 0xc], 1
            //   7514                 | jne                 0x16
            //   8bf4                 | mov                 esi, esp
            //   68????????           |                     

        $sequence_2 = { 8855f8 837d0c01 7514 8bf4 }
            // n = 4, score = 200
            //   8855f8               | mov                 byte ptr [ebp - 8], dl
            //   837d0c01             | cmp                 dword ptr [ebp + 0xc], 1
            //   7514                 | jne                 0x16
            //   8bf4                 | mov                 esi, esp

        $sequence_3 = { 8945f0 8b0d???????? 894df4 8a15???????? 8855f8 837d0c01 }
            // n = 6, score = 200
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b0d????????         |                     
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8a15????????         |                     
            //   8855f8               | mov                 byte ptr [ebp - 8], dl
            //   837d0c01             | cmp                 dword ptr [ebp + 0xc], 1

        $sequence_4 = { 8855f8 837d0c01 7514 8bf4 68???????? }
            // n = 5, score = 200
            //   8855f8               | mov                 byte ptr [ebp - 8], dl
            //   837d0c01             | cmp                 dword ptr [ebp + 0xc], 1
            //   7514                 | jne                 0x16
            //   8bf4                 | mov                 esi, esp
            //   68????????           |                     

        $sequence_5 = { 68???????? ff15???????? 3bf4 e8???????? b801000000 52 8bcd }
            // n = 7, score = 200
            //   68????????           |                     
            //   ff15????????         |                     
            //   3bf4                 | cmp                 esi, esp
            //   e8????????           |                     
            //   b801000000           | mov                 eax, 1
            //   52                   | push                edx
            //   8bcd                 | mov                 ecx, ebp

        $sequence_6 = { 0909 0909 0407 0807 8d4900 4f }
            // n = 6, score = 200
            //   0909                 | or                  dword ptr [ecx], ecx
            //   0909                 | or                  dword ptr [ecx], ecx
            //   0407                 | add                 al, 7
            //   0807                 | or                  byte ptr [edi], al
            //   8d4900               | lea                 ecx, [ecx]
            //   4f                   | dec                 edi

        $sequence_7 = { 8a15???????? 8855f8 837d0c01 7514 8bf4 }
            // n = 5, score = 200
            //   8a15????????         |                     
            //   8855f8               | mov                 byte ptr [ebp - 8], dl
            //   837d0c01             | cmp                 dword ptr [ebp + 0xc], 1
            //   7514                 | jne                 0x16
            //   8bf4                 | mov                 esi, esp

        $sequence_8 = { 8945f0 8b0d???????? 894df4 8a15???????? 8855f8 837d0c01 7514 }
            // n = 7, score = 200
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b0d????????         |                     
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8a15????????         |                     
            //   8855f8               | mov                 byte ptr [ebp - 8], dl
            //   837d0c01             | cmp                 dword ptr [ebp + 0xc], 1
            //   7514                 | jne                 0x16

        $sequence_9 = { 7514 8bf4 68???????? ff15???????? 3bf4 e8???????? b801000000 }
            // n = 7, score = 200
            //   7514                 | jne                 0x16
            //   8bf4                 | mov                 esi, esp
            //   68????????           |                     
            //   ff15????????         |                     
            //   3bf4                 | cmp                 esi, esp
            //   e8????????           |                     
            //   b801000000           | mov                 eax, 1

    condition:
        7 of them and filesize < 1433600
}
