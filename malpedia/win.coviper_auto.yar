rule win_coviper_auto {

    meta:
        id = "109b3MLaVp4lLfMq4J2TCy"
        fingerprint = "v1_sha256_f82f8deb00c9f0f056bc7b669c4b9eff14fa7266b104d66c4ba07e8ad6d42f85"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.coviper"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b55e4 58 e8???????? 0f8465010000 53 e8???????? }
            // n = 6, score = 100
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   58                   | pop                 eax
            //   e8????????           |                     
            //   0f8465010000         | je                  0x16b
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_1 = { 5f 40 003a 60 40 00494e }
            // n = 6, score = 100
            //   5f                   | pop                 edi
            //   40                   | inc                 eax
            //   003a                 | add                 byte ptr [edx], bh
            //   60                   | pushal              
            //   40                   | inc                 eax
            //   00494e               | add                 byte ptr [ecx + 0x4e], cl

        $sequence_2 = { 6a02 68???????? e8???????? 83f801 1bc0 40 880424 }
            // n = 7, score = 100
            //   6a02                 | push                2
            //   68????????           |                     
            //   e8????????           |                     
            //   83f801               | cmp                 eax, 1
            //   1bc0                 | sbb                 eax, eax
            //   40                   | inc                 eax
            //   880424               | mov                 byte ptr [esp], al

        $sequence_3 = { 240f 25ff000000 40 ba???????? 8a4402ff 5a }
            // n = 6, score = 100
            //   240f                 | and                 al, 0xf
            //   25ff000000           | and                 eax, 0xff
            //   40                   | inc                 eax
            //   ba????????           |                     
            //   8a4402ff             | mov                 al, byte ptr [edx + eax - 1]
            //   5a                   | pop                 edx

        $sequence_4 = { 003a 60 40 00494e 46 4e 41 }
            // n = 7, score = 100
            //   003a                 | add                 byte ptr [edx], bh
            //   60                   | pushal              
            //   40                   | inc                 eax
            //   00494e               | add                 byte ptr [ecx + 0x4e], cl
            //   46                   | inc                 esi
            //   4e                   | dec                 esi
            //   41                   | inc                 ecx

        $sequence_5 = { 83e21f 8d1492 dbac53372a4000 def9 c1e805 7434 }
            // n = 6, score = 100
            //   83e21f               | and                 edx, 0x1f
            //   8d1492               | lea                 edx, [edx + edx*4]
            //   dbac53372a4000       | fld                 xword ptr [ebx + edx*2 + 0x402a37]
            //   def9                 | fdivp               st(1)
            //   c1e805               | shr                 eax, 5
            //   7434                 | je                  0x36

        $sequence_6 = { 731a 89c1 e8???????? 8db449245f4000 0375ec b903000000 f3a4 }
            // n = 7, score = 100
            //   731a                 | jae                 0x1c
            //   89c1                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8db449245f4000       | lea                 esi, [ecx + ecx*2 + 0x405f24]
            //   0375ec               | add                 esi, dword ptr [ebp - 0x14]
            //   b903000000           | mov                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]

        $sequence_7 = { 80fb58 0f843cfaffff b90a000000 80fb55 0f842efaffff e9???????? }
            // n = 6, score = 100
            //   80fb58               | cmp                 bl, 0x58
            //   0f843cfaffff         | je                  0xfffffa42
            //   b90a000000           | mov                 ecx, 0xa
            //   80fb55               | cmp                 bl, 0x55
            //   0f842efaffff         | je                  0xfffffa34
            //   e9????????           |                     

        $sequence_8 = { 84c0 7504 c6042400 8b442404 50 }
            // n = 5, score = 100
            //   84c0                 | test                al, al
            //   7504                 | jne                 6
            //   c6042400             | mov                 byte ptr [esp], 0
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   50                   | push                eax

        $sequence_9 = { 6800040000 53 e8???????? 6a00 68???????? 68000c0000 }
            // n = 6, score = 100
            //   6800040000           | push                0x400
            //   53                   | push                ebx
            //   e8????????           |                     
            //   6a00                 | push                0
            //   68????????           |                     
            //   68000c0000           | push                0xc00

    condition:
        7 of them and filesize < 146432
}
