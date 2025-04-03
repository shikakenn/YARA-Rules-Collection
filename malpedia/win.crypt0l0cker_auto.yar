rule win_crypt0l0cker_auto {

    meta:
        id = "4ggK6t0sM5K7r607280JCF"
        fingerprint = "v1_sha256_11804f6d364478c710393f9e456002818242d521693fa2a4f73173b108217067"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.crypt0l0cker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypt0l0cker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 744f 83ff73 7516 83fb09 7209 83fb0d 0f865d040000 }
            // n = 7, score = 100
            //   744f                 | je                  0x51
            //   83ff73               | cmp                 edi, 0x73
            //   7516                 | jne                 0x18
            //   83fb09               | cmp                 ebx, 9
            //   7209                 | jb                  0xb
            //   83fb0d               | cmp                 ebx, 0xd
            //   0f865d040000         | jbe                 0x463

        $sequence_1 = { 8bcb e8???????? 8b7dfc 59 8d7708 56 ff15???????? }
            // n = 7, score = 100
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   59                   | pop                 ecx
            //   8d7708               | lea                 esi, [edi + 8]
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_2 = { b801000000 5b 81c484000000 c3 5f 8bc6 5e }
            // n = 7, score = 100
            //   b801000000           | mov                 eax, 1
            //   5b                   | pop                 ebx
            //   81c484000000         | add                 esp, 0x84
            //   c3                   | ret                 
            //   5f                   | pop                 edi
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi

        $sequence_3 = { 8bbd20fdffff 59 59 83bdf8fcffff00 7417 8b8d2cfdffff 8bc1 }
            // n = 7, score = 100
            //   8bbd20fdffff         | mov                 edi, dword ptr [ebp - 0x2e0]
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   83bdf8fcffff00       | cmp                 dword ptr [ebp - 0x308], 0
            //   7417                 | je                  0x19
            //   8b8d2cfdffff         | mov                 ecx, dword ptr [ebp - 0x2d4]
            //   8bc1                 | mov                 eax, ecx

        $sequence_4 = { 33d2 898524fdffff 899d34fdffff 898d10fdffff c785e0fcffff5e010000 8995e4fcffff 8995dcfcffff }
            // n = 7, score = 100
            //   33d2                 | xor                 edx, edx
            //   898524fdffff         | mov                 dword ptr [ebp - 0x2dc], eax
            //   899d34fdffff         | mov                 dword ptr [ebp - 0x2cc], ebx
            //   898d10fdffff         | mov                 dword ptr [ebp - 0x2f0], ecx
            //   c785e0fcffff5e010000     | mov    dword ptr [ebp - 0x320], 0x15e
            //   8995e4fcffff         | mov                 dword ptr [ebp - 0x31c], edx
            //   8995dcfcffff         | mov                 dword ptr [ebp - 0x324], edx

        $sequence_5 = { 42 33db 03fa 3bfa 6a01 58 0f42d8 }
            // n = 7, score = 100
            //   42                   | inc                 edx
            //   33db                 | xor                 ebx, ebx
            //   03fa                 | add                 edi, edx
            //   3bfa                 | cmp                 edi, edx
            //   6a01                 | push                1
            //   58                   | pop                 eax
            //   0f42d8               | cmovb               ebx, eax

        $sequence_6 = { 8b04950028a900 f644180448 7452 6a0a 58 6a0d 663945f8 }
            // n = 7, score = 100
            //   8b04950028a900       | mov                 eax, dword ptr [edx*4 + 0xa92800]
            //   f644180448           | test                byte ptr [eax + ebx + 4], 0x48
            //   7452                 | je                  0x54
            //   6a0a                 | push                0xa
            //   58                   | pop                 eax
            //   6a0d                 | push                0xd
            //   663945f8             | cmp                 word ptr [ebp - 8], ax

        $sequence_7 = { 85c0 770a 7204 3bd3 7304 8bd9 2bdf }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   770a                 | ja                  0xc
            //   7204                 | jb                  6
            //   3bd3                 | cmp                 edx, ebx
            //   7304                 | jae                 6
            //   8bd9                 | mov                 ebx, ecx
            //   2bdf                 | sub                 ebx, edi

        $sequence_8 = { 0f85ea000000 68???????? ba48162d71 8bce e8???????? 83c404 85c0 }
            // n = 7, score = 100
            //   0f85ea000000         | jne                 0xf0
            //   68????????           |                     
            //   ba48162d71           | mov                 edx, 0x712d1648
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8b7c2418 85c0 0f84a0000000 8d4c2420 51 50 6a00 }
            // n = 7, score = 100
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]
            //   85c0                 | test                eax, eax
            //   0f84a0000000         | je                  0xa6
            //   8d4c2420             | lea                 ecx, [esp + 0x20]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 917504
}
