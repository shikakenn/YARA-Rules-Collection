rule win_phobos_auto {

    meta:
        id = "3tEwGnNX52CrqsFY4JV2jK"
        fingerprint = "v1_sha256_c0587de91f9b07bd28460653ab9d55aeeffabbc31465d7d7ac9b9413a4a57c0d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.phobos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 ff36 ff15???????? 8bd8 83fbff 7509 ff15???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff36                 | push                dword ptr [esi]
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   83fbff               | cmp                 ebx, -1
            //   7509                 | jne                 0xb
            //   ff15????????         |                     

        $sequence_1 = { 5b c9 c3 8b4620 85c0 7407 50 }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c3                   | ret                 
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   50                   | push                eax

        $sequence_2 = { 33ff 5b c6043080 3bc3 40 730e 3bc3 }
            // n = 7, score = 100
            //   33ff                 | xor                 edi, edi
            //   5b                   | pop                 ebx
            //   c6043080             | mov                 byte ptr [eax + esi], 0x80
            //   3bc3                 | cmp                 eax, ebx
            //   40                   | inc                 eax
            //   730e                 | jae                 0x10
            //   3bc3                 | cmp                 eax, ebx

        $sequence_3 = { ff15???????? 89442414 e8???????? 6a00 6a14 89442420 e8???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a14                 | push                0x14
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   e8????????           |                     

        $sequence_4 = { 68a00f0000 8d4610 50 ff15???????? }
            // n = 4, score = 100
            //   68a00f0000           | push                0xfa0
            //   8d4610               | lea                 eax, [esi + 0x10]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_5 = { 8b450c 83c414 85c0 7408 8b0e 8b4c3908 }
            // n = 6, score = 100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   8b4c3908             | mov                 ecx, dword ptr [ecx + edi + 8]

        $sequence_6 = { 59 50 8945fc e8???????? 8bf8 59 85ff }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   59                   | pop                 ecx
            //   85ff                 | test                edi, edi

        $sequence_7 = { 333c9dd0b54000 8bda 23d8 333c9dd0c14000 8b5df0 337910 }
            // n = 6, score = 100
            //   333c9dd0b54000       | xor                 edi, dword ptr [ebx*4 + 0x40b5d0]
            //   8bda                 | mov                 ebx, edx
            //   23d8                 | and                 ebx, eax
            //   333c9dd0c14000       | xor                 edi, dword ptr [ebx*4 + 0x40c1d0]
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]
            //   337910               | xor                 edi, dword ptr [ecx + 0x10]

        $sequence_8 = { 83c104 83fe08 72d6 8b0a 83e90a 0f8466010000 49 }
            // n = 7, score = 100
            //   83c104               | add                 ecx, 4
            //   83fe08               | cmp                 esi, 8
            //   72d6                 | jb                  0xffffffd8
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   83e90a               | sub                 ecx, 0xa
            //   0f8466010000         | je                  0x16c
            //   49                   | dec                 ecx

        $sequence_9 = { 2bfa 53 0fb716 0fb71c37 663bd3 770a 720d }
            // n = 7, score = 100
            //   2bfa                 | sub                 edi, edx
            //   53                   | push                ebx
            //   0fb716               | movzx               edx, word ptr [esi]
            //   0fb71c37             | movzx               ebx, word ptr [edi + esi]
            //   663bd3               | cmp                 dx, bx
            //   770a                 | ja                  0xc
            //   720d                 | jb                  0xf

    condition:
        7 of them and filesize < 139264
}
