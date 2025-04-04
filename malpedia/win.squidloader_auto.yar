rule win_squidloader_auto {

    meta:
        id = "7ZuwafV2YF9gn9bUDxIW1H"
        fingerprint = "v1_sha256_457a1f3d7d17509f684b88b8b92c880d3534d76469a8f93e7dd90a9494a02ca3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.squidloader."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.squidloader"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 4c8d0ddcfdffff 448d4008 e8???????? 488bcb ff15???????? 4533e4 4983c708 }
            // n = 7, score = 200
            //   4c8d0ddcfdffff       | dec                 esp
            //   448d4008             | lea                 ecx, [0xfffffddc]
            //   e8????????           |                     
            //   488bcb               | inc                 esp
            //   ff15????????         |                     
            //   4533e4               | lea                 eax, [eax + 8]
            //   4983c708             | dec                 eax

        $sequence_1 = { 4889742420 57 4881ec90000000 488b05???????? 4833c4 4889842480000000 488bda }
            // n = 7, score = 200
            //   4889742420           | inc                 esp
            //   57                   | lea                 eax, [eax + 8]
            //   4881ec90000000       | dec                 eax
            //   488b05????????       |                     
            //   4833c4               | mov                 ecx, ebx
            //   4889842480000000     | inc                 ebp
            //   488bda               | xor                 esp, esp

        $sequence_2 = { 5f 5e c3 4053 4883ec30 488bd9 8b4934 }
            // n = 7, score = 200
            //   5f                   | dec                 ecx
            //   5e                   | sub                 edx, esp
            //   c3                   | dec                 edx
            //   4053                 | lea                 ecx, [edi]
            //   4883ec30             | dec                 esp
            //   488bd9               | lea                 ecx, [0xfffffddc]
            //   8b4934               | inc                 esp

        $sequence_3 = { 48c1fa03 4c3be2 7417 492bd4 4a8d0ce7 4c8d0ddcfdffff 448d4008 }
            // n = 7, score = 200
            //   48c1fa03             | mov                 ecx, ebx
            //   4c3be2               | inc                 ebp
            //   7417                 | xor                 esp, esp
            //   492bd4               | dec                 ecx
            //   4a8d0ce7             | add                 edi, 8
            //   4c8d0ddcfdffff       | dec                 eax
            //   448d4008             | sar                 edx, 3

        $sequence_4 = { 4a8d04a500000000 4c8d0480 8b5e08 4585ff }
            // n = 4, score = 100
            //   4a8d04a500000000     | inc                 eax
            //   4c8d0480             | push                ebx
            //   8b5e08               | dec                 eax
            //   4585ff               | sub                 esp, 0x30

        $sequence_5 = { 7402 8902 33db 48c7411807000000 488d156bd80200 }
            // n = 5, score = 100
            //   7402                 | mov                 edi, ecx
            //   8902                 | pop                 esi
            //   33db                 | ret                 
            //   48c7411807000000     | inc                 eax
            //   488d156bd80200       | push                ebx

        $sequence_6 = { 7403 49ffcb 400fb6d6 488d1d2ce70000 }
            // n = 4, score = 100
            //   7403                 | dec                 ecx
            //   49ffcb               | sub                 edx, esp
            //   400fb6d6             | dec                 edx
            //   488d1d2ce70000       | lea                 ecx, [edi]

        $sequence_7 = { 4a8d04a500000000 4585e4 48c7c1ffffffff 480f49c8 e8???????? 4989c7 }
            // n = 6, score = 100
            //   4a8d04a500000000     | inc                 eax
            //   4585e4               | movzx               edx, dh
            //   48c7c1ffffffff       | dec                 eax
            //   480f49c8             | lea                 ebx, [0xe72c]
            //   e8????????           |                     
            //   4989c7               | xor                 edx, 1

        $sequence_8 = { 4a8d04a500000000 4c8d0440 4c8bbc24e8020000 488b8424f0020000 }
            // n = 4, score = 100
            //   4a8d04a500000000     | dec                 eax
            //   4c8d0440             | lea                 ebx, [0xe72c]
            //   4c8bbc24e8020000     | xor                 edx, 1
            //   488b8424f0020000     | add                 edx, edx

        $sequence_9 = { 4a8d04a6 4883c008 f3420f7e4c8608 f3420f7e44a608 }
            // n = 4, score = 100
            //   4a8d04a6             | dec                 eax
            //   4883c008             | mov                 ecx, ebx
            //   f3420f7e4c8608       | dec                 esp
            //   f3420f7e44a608       | lea                 ecx, [0xfffffddc]

        $sequence_10 = { 7402 890e 4863c1 488d15c8d50200 }
            // n = 4, score = 100
            //   7402                 | mov                 ecx, dword ptr [ecx + 0x34]
            //   890e                 | sub                 ecx, 2
            //   4863c1               | dec                 ecx
            //   488d15c8d50200       | sub                 edx, esp

        $sequence_11 = { 7403 48ffcd 488bfd 48c1e705 }
            // n = 4, score = 100
            //   7403                 | lea                 ecx, [0xfffffddc]
            //   48ffcd               | dec                 esp
            //   488bfd               | lea                 ecx, [0xfffffddc]
            //   48c1e705             | inc                 esp

    condition:
        7 of them and filesize < 18701312
}
