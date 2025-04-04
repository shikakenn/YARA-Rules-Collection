rule win_komprogo_auto {

    meta:
        id = "5G2xzuCDwEBKeuKPNrGxN9"
        fingerprint = "v1_sha256_a0932a9f38d23a8c7cc40d2bb7fb17066e556ed1703c6642f0b68427cdf44c0d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.komprogo."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.komprogo"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 899638930300 8d96488e0300 899680940300 8986a1910200 8986aa910200 8d86ac700300 }
            // n = 6, score = 100
            //   899638930300         | mov                 dword ptr [esi + 0x39338], edx
            //   8d96488e0300         | lea                 edx, [esi + 0x38e48]
            //   899680940300         | mov                 dword ptr [esi + 0x39480], edx
            //   8986a1910200         | mov                 dword ptr [esi + 0x291a1], eax
            //   8986aa910200         | mov                 dword ptr [esi + 0x291aa], eax
            //   8d86ac700300         | lea                 eax, [esi + 0x370ac]

        $sequence_1 = { 899674be0300 899ed7720000 8d86052a0000 89869cbe0300 8d9690be0300 8996b0be0300 8d863b6e0300 }
            // n = 7, score = 100
            //   899674be0300         | mov                 dword ptr [esi + 0x3be74], edx
            //   899ed7720000         | mov                 dword ptr [esi + 0x72d7], ebx
            //   8d86052a0000         | lea                 eax, [esi + 0x2a05]
            //   89869cbe0300         | mov                 dword ptr [esi + 0x3be9c], eax
            //   8d9690be0300         | lea                 edx, [esi + 0x3be90]
            //   8996b0be0300         | mov                 dword ptr [esi + 0x3beb0], edx
            //   8d863b6e0300         | lea                 eax, [esi + 0x36e3b]

        $sequence_2 = { 8d8618720300 898613b40000 8d8676490000 8986bcb90300 8d8e80920200 898e4c920200 89bed5b40000 }
            // n = 7, score = 100
            //   8d8618720300         | lea                 eax, [esi + 0x37218]
            //   898613b40000         | mov                 dword ptr [esi + 0xb413], eax
            //   8d8676490000         | lea                 eax, [esi + 0x4976]
            //   8986bcb90300         | mov                 dword ptr [esi + 0x3b9bc], eax
            //   8d8e80920200         | lea                 ecx, [esi + 0x29280]
            //   898e4c920200         | mov                 dword ptr [esi + 0x2924c], ecx
            //   89bed5b40000         | mov                 dword ptr [esi + 0xb4d5], edi

        $sequence_3 = { 8986cd530200 8d8674700300 8986e1530200 8d8614930200 8986c8920200 8d86f0380400 }
            // n = 6, score = 100
            //   8986cd530200         | mov                 dword ptr [esi + 0x253cd], eax
            //   8d8674700300         | lea                 eax, [esi + 0x37074]
            //   8986e1530200         | mov                 dword ptr [esi + 0x253e1], eax
            //   8d8614930200         | lea                 eax, [esi + 0x29314]
            //   8986c8920200         | mov                 dword ptr [esi + 0x292c8], eax
            //   8d86f0380400         | lea                 eax, [esi + 0x438f0]

        $sequence_4 = { 8d96f8380400 899699d00000 8d9688bf0300 8996acbf0300 898ecdca0000 }
            // n = 5, score = 100
            //   8d96f8380400         | lea                 edx, [esi + 0x438f8]
            //   899699d00000         | mov                 dword ptr [esi + 0xd099], edx
            //   8d9688bf0300         | lea                 edx, [esi + 0x3bf88]
            //   8996acbf0300         | mov                 dword ptr [esi + 0x3bfac], edx
            //   898ecdca0000         | mov                 dword ptr [esi + 0xcacd], ecx

        $sequence_5 = { 898ea20d0100 8d8ec8780300 898ecce70300 8d9638a10300 8996d70d0100 8d8e44700300 898ebf3f0000 }
            // n = 7, score = 100
            //   898ea20d0100         | mov                 dword ptr [esi + 0x10da2], ecx
            //   8d8ec8780300         | lea                 ecx, [esi + 0x378c8]
            //   898ecce70300         | mov                 dword ptr [esi + 0x3e7cc], ecx
            //   8d9638a10300         | lea                 edx, [esi + 0x3a138]
            //   8996d70d0100         | mov                 dword ptr [esi + 0x10dd7], edx
            //   8d8e44700300         | lea                 ecx, [esi + 0x37044]
            //   898ebf3f0000         | mov                 dword ptr [esi + 0x3fbf], ecx

        $sequence_6 = { 8d9698680300 89969cbc0300 8d8624e20300 8986f8b00200 8d8ee5310000 898ee0310000 8d96b0680300 }
            // n = 7, score = 100
            //   8d9698680300         | lea                 edx, [esi + 0x36898]
            //   89969cbc0300         | mov                 dword ptr [esi + 0x3bc9c], edx
            //   8d8624e20300         | lea                 eax, [esi + 0x3e224]
            //   8986f8b00200         | mov                 dword ptr [esi + 0x2b0f8], eax
            //   8d8ee5310000         | lea                 ecx, [esi + 0x31e5]
            //   898ee0310000         | mov                 dword ptr [esi + 0x31e0], ecx
            //   8d96b0680300         | lea                 edx, [esi + 0x368b0]

        $sequence_7 = { 55 8bec 50 51 ff15???????? 85c0 7504 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7504                 | jne                 6

        $sequence_8 = { 32db 56 e8???????? 83c404 5f 5e 8ac3 }
            // n = 7, score = 100
            //   32db                 | xor                 bl, bl
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8ac3                 | mov                 al, bl

        $sequence_9 = { 898e9c160100 89bec8c20000 8d8e02960300 898ee2c20000 898659c30000 8d8ee15c0300 898e86c30000 }
            // n = 7, score = 100
            //   898e9c160100         | mov                 dword ptr [esi + 0x1169c], ecx
            //   89bec8c20000         | mov                 dword ptr [esi + 0xc2c8], edi
            //   8d8e02960300         | lea                 ecx, [esi + 0x39602]
            //   898ee2c20000         | mov                 dword ptr [esi + 0xc2e2], ecx
            //   898659c30000         | mov                 dword ptr [esi + 0xc359], eax
            //   8d8ee15c0300         | lea                 ecx, [esi + 0x35ce1]
            //   898e86c30000         | mov                 dword ptr [esi + 0xc386], ecx

    condition:
        7 of them and filesize < 1045504
}
