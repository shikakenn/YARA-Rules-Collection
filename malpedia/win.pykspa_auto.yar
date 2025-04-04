rule win_pykspa_auto {

    meta:
        id = "54hWRzb2voJfL7Hd9BqZ5m"
        fingerprint = "v1_sha256_debf44a0a6bbb12f51a3423f6d02332e02447168503a68de6d1e19702f8f8b56"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.pykspa."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pykspa"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 59 8bc3 e9???????? e8???????? e9???????? 8d85acfeffff }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   8bc3                 | mov                 eax, ebx
            //   e9????????           |                     
            //   e8????????           |                     
            //   e9????????           |                     
            //   8d85acfeffff         | lea                 eax, [ebp - 0x154]

        $sequence_1 = { 8945fc 75df 5b c9 c3 56 8b742408 }
            // n = 7, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   75df                 | jne                 0xffffffe1
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]

        $sequence_2 = { 57 8935???????? e8???????? 56 ff35???????? a3???????? 50 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8935????????         |                     
            //   e8????????           |                     
            //   56                   | push                esi
            //   ff35????????         |                     
            //   a3????????           |                     
            //   50                   | push                eax

        $sequence_3 = { 6a00 56 53 e8???????? 83c410 8d4558 50 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   56                   | push                esi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8d4558               | lea                 eax, [ebp + 0x58]
            //   50                   | push                eax

        $sequence_4 = { 59 8bf8 59 8d45fc 50 57 ff15???????? }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   8bf8                 | mov                 edi, eax
            //   59                   | pop                 ecx
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_5 = { 80385c 7410 48 49 83f901 7ff4 80385c }
            // n = 7, score = 100
            //   80385c               | cmp                 byte ptr [eax], 0x5c
            //   7410                 | je                  0x12
            //   48                   | dec                 eax
            //   49                   | dec                 ecx
            //   83f901               | cmp                 ecx, 1
            //   7ff4                 | jg                  0xfffffff6
            //   80385c               | cmp                 byte ptr [eax], 0x5c

        $sequence_6 = { e8???????? 59 ff75fc ff15???????? 32c0 5e }
            // n = 6, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   32c0                 | xor                 al, al
            //   5e                   | pop                 esi

        $sequence_7 = { 56 57 ff15???????? 53 6a6f }
            // n = 5, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   6a6f                 | push                0x6f

        $sequence_8 = { e8???????? 59 5e 5b c3 8b4a04 8b520c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8b4a04               | mov                 ecx, dword ptr [edx + 4]
            //   8b520c               | mov                 edx, dword ptr [edx + 0xc]

        $sequence_9 = { 59 8d7dbd 8845bc f3ab 7777 83fe05 7272 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   8d7dbd               | lea                 edi, [ebp - 0x43]
            //   8845bc               | mov                 byte ptr [ebp - 0x44], al
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   7777                 | ja                  0x79
            //   83fe05               | cmp                 esi, 5
            //   7272                 | jb                  0x74

    condition:
        7 of them and filesize < 835584
}
