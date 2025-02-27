rule win_classfon_auto {

    meta:
        id = "1tV6S3A8FYYGe4p1cXg7AE"
        fingerprint = "v1_sha256_66ac3b2c234be6c5adfcd77cebd772d5254febc41066bba0a145357a351f1537"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.classfon."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.classfon"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a01 56 ffd0 85c0 7511 55 e8???????? }
            // n = 7, score = 200
            //   6a01                 | push                1
            //   56                   | push                esi
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   7511                 | jne                 0x13
            //   55                   | push                ebp
            //   e8????????           |                     

        $sequence_1 = { 8d4c2400 c744240000000000 51 68???????? 52 c744241001000000 }
            // n = 6, score = 200
            //   8d4c2400             | lea                 ecx, [esp]
            //   c744240000000000     | mov                 dword ptr [esp], 0
            //   51                   | push                ecx
            //   68????????           |                     
            //   52                   | push                edx
            //   c744241001000000     | mov                 dword ptr [esp + 0x10], 1

        $sequence_2 = { e8???????? 8b8c2420020000 8bb42418020000 8bd8 8bd1 8bfb }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8b8c2420020000       | mov                 ecx, dword ptr [esp + 0x220]
            //   8bb42418020000       | mov                 esi, dword ptr [esp + 0x218]
            //   8bd8                 | mov                 ebx, eax
            //   8bd1                 | mov                 edx, ecx
            //   8bfb                 | mov                 edi, ebx

        $sequence_3 = { 0f859d010000 8d4c241c 8d542424 51 8b4c2414 8d442424 52 }
            // n = 7, score = 200
            //   0f859d010000         | jne                 0x1a3
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   8d542424             | lea                 edx, [esp + 0x24]
            //   51                   | push                ecx
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   52                   | push                edx

        $sequence_4 = { 897d04 89450c 894508 894510 8b4b50 }
            // n = 5, score = 200
            //   897d04               | mov                 dword ptr [ebp + 4], edi
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   894510               | mov                 dword ptr [ebp + 0x10], eax
            //   8b4b50               | mov                 ecx, dword ptr [ebx + 0x50]

        $sequence_5 = { 83c408 40 8bf8 803f00 }
            // n = 4, score = 200
            //   83c408               | add                 esp, 8
            //   40                   | inc                 eax
            //   8bf8                 | mov                 edi, eax
            //   803f00               | cmp                 byte ptr [edi], 0

        $sequence_6 = { ffd3 89be00020000 89be10020000 89be14020000 5f 5e }
            // n = 6, score = 200
            //   ffd3                 | call                ebx
            //   89be00020000         | mov                 dword ptr [esi + 0x200], edi
            //   89be10020000         | mov                 dword ptr [esi + 0x210], edi
            //   89be14020000         | mov                 dword ptr [esi + 0x214], edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_7 = { 03f5 56 89742418 ff15???????? 85c0 0f85c3000000 }
            // n = 6, score = 200
            //   03f5                 | add                 esi, ebp
            //   56                   | push                esi
            //   89742418             | mov                 dword ptr [esp + 0x18], esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f85c3000000         | jne                 0xc9

        $sequence_8 = { e8???????? 83c40c 85c0 7437 8b8c2428020000 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   7437                 | je                  0x39
            //   8b8c2428020000       | mov                 ecx, dword ptr [esp + 0x228]

        $sequence_9 = { 5f 5e 5b 81c418020000 c3 5f }
            // n = 6, score = 200
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   81c418020000         | add                 esp, 0x218
            //   c3                   | ret                 
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 73728
}
