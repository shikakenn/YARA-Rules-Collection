rule win_fancyfilter_auto {

    meta:
        id = "77VpoNXmSvBdMc8rhPrN3c"
        fingerprint = "v1_sha256_476e24d851dbd343335f49ac83fe24b993db2eb5e282eab0e77caa734f27e50a"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.fancyfilter."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fancyfilter"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 85c0 740a 66833800 7404 b001 eb02 }
            // n = 6, score = 400
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   66833800             | cmp                 word ptr [eax], 0
            //   7404                 | je                  6
            //   b001                 | mov                 al, 1
            //   eb02                 | jmp                 4

        $sequence_1 = { 891d???????? 891d???????? b001 5b }
            // n = 4, score = 400
            //   891d????????         |                     
            //   891d????????         |                     
            //   b001                 | mov                 al, 1
            //   5b                   | pop                 ebx

        $sequence_2 = { 740a 66833800 7404 b001 eb02 }
            // n = 5, score = 400
            //   740a                 | je                  0xc
            //   66833800             | cmp                 word ptr [eax], 0
            //   7404                 | je                  6
            //   b001                 | mov                 al, 1
            //   eb02                 | jmp                 4

        $sequence_3 = { 750d 8b472c a801 7406 }
            // n = 4, score = 400
            //   750d                 | jne                 0xf
            //   8b472c               | mov                 eax, dword ptr [edi + 0x2c]
            //   a801                 | test                al, 1
            //   7406                 | je                  8

        $sequence_4 = { a1???????? 83c012 50 ff15???????? a1???????? }
            // n = 5, score = 400
            //   a1????????           |                     
            //   83c012               | add                 eax, 0x12
            //   50                   | push                eax
            //   ff15????????         |                     
            //   a1????????           |                     

        $sequence_5 = { 8d4f20 51 50 ff15???????? }
            // n = 4, score = 400
            //   8d4f20               | lea                 ecx, [edi + 0x20]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_6 = { 85c0 740a 66833800 7404 b001 eb02 32c0 }
            // n = 7, score = 400
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   66833800             | cmp                 word ptr [eax], 0
            //   7404                 | je                  6
            //   b001                 | mov                 al, 1
            //   eb02                 | jmp                 4
            //   32c0                 | xor                 al, al

        $sequence_7 = { 8b07 83e810 50 83c610 }
            // n = 4, score = 400
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   83e810               | sub                 eax, 0x10
            //   50                   | push                eax
            //   83c610               | add                 esi, 0x10

        $sequence_8 = { 85c0 750d 8b472c a801 }
            // n = 4, score = 400
            //   85c0                 | test                eax, eax
            //   750d                 | jne                 0xf
            //   8b472c               | mov                 eax, dword ptr [edi + 0x2c]
            //   a801                 | test                al, 1

        $sequence_9 = { 85c0 750d 8b472c a801 7406 }
            // n = 5, score = 400
            //   85c0                 | test                eax, eax
            //   750d                 | jne                 0xf
            //   8b472c               | mov                 eax, dword ptr [edi + 0x2c]
            //   a801                 | test                al, 1
            //   7406                 | je                  8

    condition:
        7 of them and filesize < 169984
}
