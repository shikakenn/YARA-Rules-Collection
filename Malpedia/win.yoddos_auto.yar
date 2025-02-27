rule win_yoddos_auto {

    meta:
        id = "6GuayJlcsahOjrWec8EvBq"
        fingerprint = "v1_sha256_8286010b7da9f1df882192411526cd0a211d255dea4daeff1ec9797cedceaf98"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.yoddos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yoddos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 90 b89dffffff 90 c685d0fdffff4b }
            // n = 4, score = 100
            //   90                   | nop                 
            //   b89dffffff           | mov                 eax, 0xffffff9d
            //   90                   | nop                 
            //   c685d0fdffff4b       | mov                 byte ptr [ebp - 0x230], 0x4b

        $sequence_1 = { ff15???????? ff35???????? ff15???????? 6880000000 53 68???????? c705????????01000000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   6880000000           | push                0x80
            //   53                   | push                ebx
            //   68????????           |                     
            //   c705????????01000000     |     

        $sequence_2 = { 90 b89dffffff 90 be04010000 8d858cfeffff 33db 56 }
            // n = 7, score = 100
            //   90                   | nop                 
            //   b89dffffff           | mov                 eax, 0xffffff9d
            //   90                   | nop                 
            //   be04010000           | mov                 esi, 0x104
            //   8d858cfeffff         | lea                 eax, [ebp - 0x174]
            //   33db                 | xor                 ebx, ebx
            //   56                   | push                esi

        $sequence_3 = { 33db 56 50 53 c645f043 c645f14f c645f24d }
            // n = 7, score = 100
            //   33db                 | xor                 ebx, ebx
            //   56                   | push                esi
            //   50                   | push                eax
            //   53                   | push                ebx
            //   c645f043             | mov                 byte ptr [ebp - 0x10], 0x43
            //   c645f14f             | mov                 byte ptr [ebp - 0xf], 0x4f
            //   c645f24d             | mov                 byte ptr [ebp - 0xe], 0x4d

        $sequence_4 = { c6459863 c645996b c6459a2e c6459b63 }
            // n = 4, score = 100
            //   c6459863             | mov                 byte ptr [ebp - 0x68], 0x63
            //   c645996b             | mov                 byte ptr [ebp - 0x67], 0x6b
            //   c6459a2e             | mov                 byte ptr [ebp - 0x66], 0x2e
            //   c6459b63             | mov                 byte ptr [ebp - 0x65], 0x63

        $sequence_5 = { c9 c20400 55 8bec 81ec480d0000 53 56 }
            // n = 7, score = 100
            //   c9                   | leave               
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec480d0000         | sub                 esp, 0xd48
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_6 = { 889d27feffff c6853cfeffff77 c6853dfeffff77 c6853efeffff77 c6853ffeffff2e c68540feffff68 c68541feffff61 }
            // n = 7, score = 100
            //   889d27feffff         | mov                 byte ptr [ebp - 0x1d9], bl
            //   c6853cfeffff77       | mov                 byte ptr [ebp - 0x1c4], 0x77
            //   c6853dfeffff77       | mov                 byte ptr [ebp - 0x1c3], 0x77
            //   c6853efeffff77       | mov                 byte ptr [ebp - 0x1c2], 0x77
            //   c6853ffeffff2e       | mov                 byte ptr [ebp - 0x1c1], 0x2e
            //   c68540feffff68       | mov                 byte ptr [ebp - 0x1c0], 0x68
            //   c68541feffff61       | mov                 byte ptr [ebp - 0x1bf], 0x61

        $sequence_7 = { 8d85e0fdffff 50 e8???????? 50 8d85c8fcffff 50 }
            // n = 6, score = 100
            //   8d85e0fdffff         | lea                 eax, [ebp - 0x220]
            //   50                   | push                eax
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d85c8fcffff         | lea                 eax, [ebp - 0x338]
            //   50                   | push                eax

        $sequence_8 = { c645d34c c645d46f c645d563 c645d661 c645d76c }
            // n = 5, score = 100
            //   c645d34c             | mov                 byte ptr [ebp - 0x2d], 0x4c
            //   c645d46f             | mov                 byte ptr [ebp - 0x2c], 0x6f
            //   c645d563             | mov                 byte ptr [ebp - 0x2b], 0x63
            //   c645d661             | mov                 byte ptr [ebp - 0x2a], 0x61
            //   c645d76c             | mov                 byte ptr [ebp - 0x29], 0x6c

        $sequence_9 = { e8???????? 83c410 8d85d4fbffff 53 50 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8d85d4fbffff         | lea                 eax, [ebp - 0x42c]
            //   53                   | push                ebx
            //   50                   | push                eax

    condition:
        7 of them and filesize < 557056
}
