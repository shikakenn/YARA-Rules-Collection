rule win_webc2_cson_auto {

    meta:
        id = "3MSCR1bZRQkImelIXIHOVY"
        fingerprint = "v1_sha256_9a18d875b3b14f91d30d03a0640ea0a5b789b8ad5cdc4c9d1d8ddab08372dfdc"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.webc2_cson."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_cson"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83c414 85c0 0f8473ffffff 6a06 }
            // n = 4, score = 100
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   0f8473ffffff         | je                  0xffffff79
            //   6a06                 | push                6

        $sequence_1 = { 740a 68???????? e9???????? 8d45c0 }
            // n = 4, score = 100
            //   740a                 | je                  0xc
            //   68????????           |                     
            //   e9????????           |                     
            //   8d45c0               | lea                 eax, [ebp - 0x40]

        $sequence_2 = { 744d 8d85d8feffff 50 56 e8???????? 85c0 }
            // n = 6, score = 100
            //   744d                 | je                  0x4f
            //   8d85d8feffff         | lea                 eax, [ebp - 0x128]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_3 = { 6a0f f3ab 66ab aa 59 33c0 8d7d81 }
            // n = 7, score = 100
            //   6a0f                 | push                0xf
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   8d7d81               | lea                 edi, [ebp - 0x7f]

        $sequence_4 = { 57 33db b9ff630000 33c0 }
            // n = 4, score = 100
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx
            //   b9ff630000           | mov                 ecx, 0x63ff
            //   33c0                 | xor                 eax, eax

        $sequence_5 = { e9???????? 8d45c0 68???????? 50 ff15???????? }
            // n = 5, score = 100
            //   e9????????           |                     
            //   8d45c0               | lea                 eax, [ebp - 0x40]
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_6 = { 8a4c0588 884c05c0 40 83f840 72ec }
            // n = 5, score = 100
            //   8a4c0588             | mov                 cl, byte ptr [ebp + eax - 0x78]
            //   884c05c0             | mov                 byte ptr [ebp + eax - 0x40], cl
            //   40                   | inc                 eax
            //   83f840               | cmp                 eax, 0x40
            //   72ec                 | jb                  0xffffffee

        $sequence_7 = { 50 ff15???????? 8d85acfeffff 50 e8???????? 80bc05abfeffff5c 59 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d85acfeffff         | lea                 eax, [ebp - 0x154]
            //   50                   | push                eax
            //   e8????????           |                     
            //   80bc05abfeffff5c     | cmp                 byte ptr [ebp + eax - 0x155], 0x5c
            //   59                   | pop                 ecx

        $sequence_8 = { 0fbec1 83e81d c3 80f961 7c0c 80f97a }
            // n = 6, score = 100
            //   0fbec1               | movsx               eax, cl
            //   83e81d               | sub                 eax, 0x1d
            //   c3                   | ret                 
            //   80f961               | cmp                 cl, 0x61
            //   7c0c                 | jl                  0xe
            //   80f97a               | cmp                 cl, 0x7a

        $sequence_9 = { 8bc7 5f 5e c3 ff15???????? 6a09 }
            // n = 6, score = 100
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   ff15????????         |                     
            //   6a09                 | push                9

    condition:
        7 of them and filesize < 98304
}
