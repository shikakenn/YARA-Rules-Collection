rule win_cherry_picker_auto {

    meta:
        id = "1KefyrHsIkQMmMkazdTTBb"
        fingerprint = "v1_sha256_d063fae0bccc43dbf0d60b6c18c60c6de12439bcf31003957c363036cbe5a98f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.cherry_picker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cherry_picker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83c8ff 56 90 8bf0 0fbec9 81e6ff000000 }
            // n = 6, score = 300
            //   83c8ff               | or                  eax, 0xffffffff
            //   56                   | push                esi
            //   90                   | nop                 
            //   8bf0                 | mov                 esi, eax
            //   0fbec9               | movsx               ecx, cl
            //   81e6ff000000         | and                 esi, 0xff

        $sequence_1 = { 68???????? 68???????? a3???????? ffd6 68???????? 6a3c }
            // n = 6, score = 300
            //   68????????           |                     
            //   68????????           |                     
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   6a3c                 | push                0x3c

        $sequence_2 = { 69c0e8030000 68???????? 6a01 68???????? 68???????? a3???????? }
            // n = 6, score = 300
            //   69c0e8030000         | imul                eax, eax, 0x3e8
            //   68????????           |                     
            //   6a01                 | push                1
            //   68????????           |                     
            //   68????????           |                     
            //   a3????????           |                     

        $sequence_3 = { 52 8d442428 50 ff542420 }
            // n = 4, score = 300
            //   52                   | push                edx
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   50                   | push                eax
            //   ff542420             | call                dword ptr [esp + 0x20]

        $sequence_4 = { 41 84d2 75f6 8b3d???????? }
            // n = 4, score = 300
            //   41                   | inc                 ecx
            //   84d2                 | test                dl, dl
            //   75f6                 | jne                 0xfffffff8
            //   8b3d????????         |                     

        $sequence_5 = { 7512 68???????? 50 50 ff15???????? a3???????? }
            // n = 6, score = 300
            //   7512                 | jne                 0x14
            //   68????????           |                     
            //   50                   | push                eax
            //   50                   | push                eax
            //   ff15????????         |                     
            //   a3????????           |                     

        $sequence_6 = { a1???????? 56 6aff 50 8bf1 }
            // n = 5, score = 300
            //   a1????????           |                     
            //   56                   | push                esi
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   8bf1                 | mov                 esi, ecx

        $sequence_7 = { 83c408 2bf2 8a11 88140e 41 84d2 }
            // n = 6, score = 300
            //   83c408               | add                 esp, 8
            //   2bf2                 | sub                 esi, edx
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   88140e               | mov                 byte ptr [esi + ecx], dl
            //   41                   | inc                 ecx
            //   84d2                 | test                dl, dl

        $sequence_8 = { 8a0d???????? ba???????? 83c8ff 56 }
            // n = 4, score = 300
            //   8a0d????????         |                     
            //   ba????????           |                     
            //   83c8ff               | or                  eax, 0xffffffff
            //   56                   | push                esi

        $sequence_9 = { 6aff 50 ffd3 6a00 6a00 }
            // n = 5, score = 300
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   6a00                 | push                0
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 712704
}
