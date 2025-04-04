rule win_necurs_auto {

    meta:
        id = "7Jem4XgzaAah9gUtdJRAgn"
        fingerprint = "v1_sha256_1a877e35a35cc5b42dec49f688cab91a0513382e31843c1efea0701ab2d894e0"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.necurs."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.necurs"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 56 8bf2 ba06e0a636 f7e2 }
            // n = 4, score = 1300
            //   56                   | push                esi
            //   8bf2                 | mov                 esi, edx
            //   ba06e0a636           | mov                 edx, 0x36a6e006
            //   f7e2                 | mul                 edx

        $sequence_1 = { f7f6 8bc2 034508 5e 5d c3 }
            // n = 6, score = 1300
            //   f7f6                 | div                 esi
            //   8bc2                 | mov                 eax, edx
            //   034508               | add                 eax, dword ptr [ebp + 8]
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_2 = { ba06e0a636 f7e2 03c8 a1???????? 13f2 33d2 }
            // n = 6, score = 1300
            //   ba06e0a636           | mov                 edx, 0x36a6e006
            //   f7e2                 | mul                 edx
            //   03c8                 | add                 ecx, eax
            //   a1????????           |                     
            //   13f2                 | adc                 esi, edx
            //   33d2                 | xor                 edx, edx

        $sequence_3 = { 13f2 33d2 030d???????? a3???????? }
            // n = 4, score = 1300
            //   13f2                 | adc                 esi, edx
            //   33d2                 | xor                 edx, edx
            //   030d????????         |                     
            //   a3????????           |                     

        $sequence_4 = { 8bc8 a1???????? 56 8bf2 }
            // n = 4, score = 1300
            //   8bc8                 | mov                 ecx, eax
            //   a1????????           |                     
            //   56                   | push                esi
            //   8bf2                 | mov                 esi, edx

        $sequence_5 = { 8935???????? 890d???????? 8bc1 5e c3 55 8bec }
            // n = 7, score = 1300
            //   8935????????         |                     
            //   890d????????         |                     
            //   8bc1                 | mov                 eax, ecx
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_6 = { a1???????? 13f2 a3???????? 8935???????? }
            // n = 4, score = 1300
            //   a1????????           |                     
            //   13f2                 | adc                 esi, edx
            //   a3????????           |                     
            //   8935????????         |                     

        $sequence_7 = { 8d85ecfbffff 57 50 e8???????? 83c410 }
            // n = 5, score = 1100
            //   8d85ecfbffff         | lea                 eax, [ebp - 0x414]
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_8 = { 33d7 33c1 52 50 e8???????? }
            // n = 5, score = 900
            //   33d7                 | xor                 edx, edi
            //   33c1                 | xor                 eax, ecx
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_9 = { 6a7b 50 ffd6 8bf8 59 59 }
            // n = 6, score = 800
            //   6a7b                 | push                0x7b
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8bf8                 | mov                 edi, eax
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_10 = { 7409 8bc1 8bd7 e9???????? }
            // n = 4, score = 800
            //   7409                 | je                  0xb
            //   8bc1                 | mov                 eax, ecx
            //   8bd7                 | mov                 edx, edi
            //   e9????????           |                     

        $sequence_11 = { 53 ff15???????? 59 33c0 5e 5b }
            // n = 6, score = 800
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_12 = { 6a7d 50 ffd6 59 59 85c0 }
            // n = 6, score = 800
            //   6a7d                 | push                0x7d
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_13 = { 33d2 5e 5f c9 }
            // n = 4, score = 800
            //   33d2                 | xor                 edx, edx
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   c9                   | leave               

        $sequence_14 = { e9???????? 83caff 8bc2 e9???????? }
            // n = 4, score = 800
            //   e9????????           |                     
            //   83caff               | or                  edx, 0xffffffff
            //   8bc2                 | mov                 eax, edx
            //   e9????????           |                     

    condition:
        7 of them and filesize < 475136
}
