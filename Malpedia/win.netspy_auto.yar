rule win_netspy_auto {

    meta:
        id = "6vPpNSpAtknPfUq6Ons9qJ"
        fingerprint = "v1_sha256_66a516dd000926156bcdfd45ff83678e3971de0f2826970552469344651d0e0a"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.netspy."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netspy"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e9???????? 488b8540010000 488b8db8190000 4889c4 488b8558180000 488985d0000000 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   488b8540010000       | mov                 dword ptr [ebp + 0x4d90], ecx
            //   488b8db8190000       | dec                 eax
            //   4889c4               | sub                 esp, eax
            //   488b8558180000       | dec                 eax
            //   488985d0000000       | mov                 eax, dword ptr [ebp + 0xa50]

        $sequence_1 = { e9???????? 488b8548340000 8b8d944d0000 4889c4 488b85484d0000 }
            // n = 5, score = 100
            //   e9????????           |                     
            //   488b8548340000       | mov                 eax, dword ptr [ebp + 0x3454]
            //   8b8d944d0000         | cmp                 eax, 0xfad629df
            //   4889c4               | je                  0x1e1
            //   488b85484d0000       | dec                 eax

        $sequence_2 = { 488b09 4863493c 4801c8 48898528340000 8b15???????? }
            // n = 5, score = 100
            //   488b09               | dec                 eax
            //   4863493c             | mov                 dword ptr [ebp + 0x1050], eax
            //   4801c8               | dec                 eax
            //   48898528340000       | mov                 eax, esp
            //   8b15????????         |                     

        $sequence_3 = { 3d3f08c577 0f84d6280000 e9???????? 8b8584130000 }
            // n = 4, score = 100
            //   3d3f08c577           | dec                 eax
            //   0f84d6280000         | mov                 ecx, esp
            //   e9????????           |                     
            //   8b8584130000         | dec                 eax

        $sequence_4 = { 48898d904d0000 e8???????? 4829c4 488b85500a0000 4889e1 48898d984d0000 }
            // n = 6, score = 100
            //   48898d904d0000       | dec                 eax
            //   e8????????           |                     
            //   4829c4               | add                 eax, ecx
            //   488b85500a0000       | dec                 eax
            //   4889e1               | mov                 dword ptr [ebp + 0x3428], eax
            //   48898d984d0000       | je                  0x8e

        $sequence_5 = { 0f8488000000 e9???????? 8b8554340000 3ddf29d6fa 0f84d0010000 }
            // n = 5, score = 100
            //   0f8488000000         | dec                 eax
            //   e9????????           |                     
            //   8b8554340000         | mov                 ecx, dword ptr [ecx]
            //   3ddf29d6fa           | dec                 eax
            //   0f84d0010000         | arpl                word ptr [ecx + 0x3c], cx

        $sequence_6 = { e8???????? 4829c4 488b8540180000 4889e2 48899550180000 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   4829c4               | dec                 eax
            //   488b8540180000       | mov                 esp, eax
            //   4889e2               | dec                 eax
            //   48899550180000       | mov                 eax, dword ptr [ebp + 0x4d48]

        $sequence_7 = { c70163382994 e8???????? 4829c4 4889e0 488985e05e0000 e9???????? }
            // n = 6, score = 100
            //   c70163382994         | mov                 dword ptr [ebp + 0x4d98], ecx
            //   e8????????           |                     
            //   4829c4               | dec                 eax
            //   4889e0               | mov                 eax, dword ptr [ebp + 0x3448]
            //   488985e05e0000       | mov                 ecx, dword ptr [ebp + 0x4d94]
            //   e9????????           |                     

    condition:
        7 of them and filesize < 12033024
}
