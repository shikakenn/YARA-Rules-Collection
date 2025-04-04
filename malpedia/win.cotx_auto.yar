rule win_cotx_auto {

    meta:
        id = "6TAu4Z4EUJ4KJ4U1ypHtjD"
        fingerprint = "v1_sha256_3b8fe5510fd419b8c1ff3124a08904512765ac561abd89e88faa984449f17fc2"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.cotx."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cotx"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c705????????5411e14c c705????????2b3d0396 c705????????e54dcca2 c705????????92d61819 c705????????0c56aef3 c705????????c8a4ea05 }
            // n = 6, score = 500
            //   c705????????5411e14c     |     
            //   c705????????2b3d0396     |     
            //   c705????????e54dcca2     |     
            //   c705????????92d61819     |     
            //   c705????????0c56aef3     |     
            //   c705????????c8a4ea05     |     

        $sequence_1 = { 50 0f2805???????? 8d85bcfbffff 0f1145d0 }
            // n = 4, score = 500
            //   50                   | push                eax
            //   0f2805????????       |                     
            //   8d85bcfbffff         | lea                 eax, [ebp - 0x444]
            //   0f1145d0             | movups              xmmword ptr [ebp - 0x30], xmm0

        $sequence_2 = { c705????????2b342411 c705????????4a06d5fe c705????????5411e14c c705????????2b3d0396 c705????????e54dcca2 c705????????92d61819 c705????????0c56aef3 }
            // n = 7, score = 500
            //   c705????????2b342411     |     
            //   c705????????4a06d5fe     |     
            //   c705????????5411e14c     |     
            //   c705????????2b3d0396     |     
            //   c705????????e54dcca2     |     
            //   c705????????92d61819     |     
            //   c705????????0c56aef3     |     

        $sequence_3 = { 84c0 75f8 0f2805???????? 8d85bdfaffff 8bca c785b8faffff39313044 }
            // n = 6, score = 500
            //   84c0                 | test                al, al
            //   75f8                 | jne                 0xfffffffa
            //   0f2805????????       |                     
            //   8d85bdfaffff         | lea                 eax, [ebp - 0x543]
            //   8bca                 | mov                 ecx, edx
            //   c785b8faffff39313044     | mov    dword ptr [ebp - 0x548], 0x44303139

        $sequence_4 = { e8???????? 83c438 8d8500f8ffff 6a00 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   83c438               | add                 esp, 0x38
            //   8d8500f8ffff         | lea                 eax, [ebp - 0x800]
            //   6a00                 | push                0

        $sequence_5 = { 84c0 75f9 8dbd98faffff 2bd6 }
            // n = 4, score = 500
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   8dbd98faffff         | lea                 edi, [ebp - 0x568]
            //   2bd6                 | sub                 edx, esi

        $sequence_6 = { 8d45fc 50 8b8574fdffff 83c008 50 ff75ec ff15???????? }
            // n = 7, score = 500
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   8b8574fdffff         | mov                 eax, dword ptr [ebp - 0x28c]
            //   83c008               | add                 eax, 8
            //   50                   | push                eax
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff15????????         |                     

        $sequence_7 = { c785b8faffff39313044 c1e902 f3a5 8bca }
            // n = 4, score = 500
            //   c785b8faffff39313044     | mov    dword ptr [ebp - 0x548], 0x44303139
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bca                 | mov                 ecx, edx

        $sequence_8 = { c705????????8e220b1d c705????????6825794d c705????????4506ce62 c705????????b60451f0 c705????????3f3f5288 }
            // n = 5, score = 500
            //   c705????????8e220b1d     |     
            //   c705????????6825794d     |     
            //   c705????????4506ce62     |     
            //   c705????????b60451f0     |     
            //   c705????????3f3f5288     |     

        $sequence_9 = { 6800040000 8d8598f6ffff 6a00 50 e8???????? 83c40c 8d8598feffff }
            // n = 7, score = 500
            //   6800040000           | push                0x400
            //   8d8598f6ffff         | lea                 eax, [ebp - 0x968]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d8598feffff         | lea                 eax, [ebp - 0x168]

    condition:
        7 of them and filesize < 1171456
}
