rule win_scarab_ransom_auto {

    meta:
        id = "d4L0WG4JPaOJaoO3Rr8A3"
        fingerprint = "v1_sha256_15e87675f50a7310d8d114c24b29e5eb374762ccaea386112ed3eb7ae5474e50"
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
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scarab_ransom"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b0424 335034 8954241c 0fb6442410 8b1485ac084300 8b442414 }
            // n = 6, score = 100
            //   8b0424               | mov                 eax, dword ptr [esp]
            //   335034               | xor                 edx, dword ptr [eax + 0x34]
            //   8954241c             | mov                 dword ptr [esp + 0x1c], edx
            //   0fb6442410           | movzx               eax, byte ptr [esp + 0x10]
            //   8b1485ac084300       | mov                 edx, dword ptr [eax*4 + 0x4308ac]
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]

        $sequence_1 = { 8955e4 8b45fc 8b0485ec054300 8945e0 8b45f8 }
            // n = 5, score = 100
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b0485ec054300       | mov                 eax, dword ptr [eax*4 + 0x4305ec]
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_2 = { 4c fb 42 0020 1b4300 44 }
            // n = 6, score = 100
            //   4c                   | dec                 esp
            //   fb                   | sti                 
            //   42                   | inc                 edx
            //   0020                 | add                 byte ptr [eax], ah
            //   1b4300               | sbb                 eax, dword ptr [ebx]
            //   44                   | inc                 esp

        $sequence_3 = { 25f0000000 c1e804 8b0485c0fb4200 50 8b04b5b4fb4200 }
            // n = 5, score = 100
            //   25f0000000           | and                 eax, 0xf0
            //   c1e804               | shr                 eax, 4
            //   8b0485c0fb4200       | mov                 eax, dword ptr [eax*4 + 0x42fbc0]
            //   50                   | push                eax
            //   8b04b5b4fb4200       | mov                 eax, dword ptr [esi*4 + 0x42fbb4]

        $sequence_4 = { 00ec fa 42 00741c43 00e4 fa 42 }
            // n = 7, score = 100
            //   00ec                 | add                 ah, ch
            //   fa                   | cli                 
            //   42                   | inc                 edx
            //   00741c43             | add                 byte ptr [esp + ebx + 0x43], dh
            //   00e4                 | add                 ah, ah
            //   fa                   | cli                 
            //   42                   | inc                 edx

        $sequence_5 = { 8b44240c c1e808 0fb6c0 8b0485ac104300 8b4c2408 }
            // n = 5, score = 100
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   c1e808               | shr                 eax, 8
            //   0fb6c0               | movzx               eax, al
            //   8b0485ac104300       | mov                 eax, dword ptr [eax*4 + 0x4310ac]
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]

        $sequence_6 = { c744240409000000 8b1c24 83c310 8b13 8bca 81e180808080 }
            // n = 6, score = 100
            //   c744240409000000     | mov                 dword ptr [esp + 4], 9
            //   8b1c24               | mov                 ebx, dword ptr [esp]
            //   83c310               | add                 ebx, 0x10
            //   8b13                 | mov                 edx, dword ptr [ebx]
            //   8bca                 | mov                 ecx, edx
            //   81e180808080         | and                 ecx, 0x80808080

        $sequence_7 = { c1ea0d c1e908 b8ffffffff d3e0 23049520274300 740c 83e1e0 }
            // n = 7, score = 100
            //   c1ea0d               | shr                 edx, 0xd
            //   c1e908               | shr                 ecx, 8
            //   b8ffffffff           | mov                 eax, 0xffffffff
            //   d3e0                 | shl                 eax, cl
            //   23049520274300       | and                 eax, dword ptr [edx*4 + 0x432720]
            //   740c                 | je                  0xe
            //   83e1e0               | and                 ecx, 0xffffffe0

        $sequence_8 = { 0bc1 33d0 8b0424 3390c0000000 89542408 0fb644241c 8b1485ac084300 }
            // n = 7, score = 100
            //   0bc1                 | or                  eax, ecx
            //   33d0                 | xor                 edx, eax
            //   8b0424               | mov                 eax, dword ptr [esp]
            //   3390c0000000         | xor                 edx, dword ptr [eax + 0xc0]
            //   89542408             | mov                 dword ptr [esp + 8], edx
            //   0fb644241c           | movzx               eax, byte ptr [esp + 0x1c]
            //   8b1485ac084300       | mov                 edx, dword ptr [eax*4 + 0x4308ac]

        $sequence_9 = { 895704 893a 39d7 7517 bafeffffff d3c2 21148520274300 }
            // n = 7, score = 100
            //   895704               | mov                 dword ptr [edi + 4], edx
            //   893a                 | mov                 dword ptr [edx], edi
            //   39d7                 | cmp                 edi, edx
            //   7517                 | jne                 0x19
            //   bafeffffff           | mov                 edx, 0xfffffffe
            //   d3c2                 | rol                 edx, cl
            //   21148520274300       | and                 dword ptr [eax*4 + 0x432720], edx

    condition:
        7 of them and filesize < 507904
}
