rule win_wpbrutebot_auto {

    meta:
        id = "aY55gzqBwZBOGmK97U5gb"
        fingerprint = "v1_sha256_4440d9063c782ae6ab73b1ab2283579374719f22f3d62d05493ede3029f224d5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.wpbrutebot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wpbrutebot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b542438 83f90f 7433 83f90e 7425 8b07 3b5004 }
            // n = 7, score = 100
            //   8b542438             | mov                 edx, dword ptr [esp + 0x38]
            //   83f90f               | cmp                 ecx, 0xf
            //   7433                 | je                  0x35
            //   83f90e               | cmp                 ecx, 0xe
            //   7425                 | je                  0x27
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   3b5004               | cmp                 edx, dword ptr [eax + 4]

        $sequence_1 = { e8???????? 8d8d7ceaffff e8???????? 8d8d64eaffff e8???????? 8d8d4ceaffff e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d8d7ceaffff         | lea                 ecx, [ebp - 0x1584]
            //   e8????????           |                     
            //   8d8d64eaffff         | lea                 ecx, [ebp - 0x159c]
            //   e8????????           |                     
            //   8d8d4ceaffff         | lea                 ecx, [ebp - 0x15b4]
            //   e8????????           |                     

        $sequence_2 = { e9???????? 83ef05 8364241404 741c 85ff 7e17 55 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   83ef05               | sub                 edi, 5
            //   8364241404           | and                 dword ptr [esp + 0x14], 4
            //   741c                 | je                  0x1e
            //   85ff                 | test                edi, edi
            //   7e17                 | jle                 0x19
            //   55                   | push                ebp

        $sequence_3 = { c3 c785b001000002000000 8b7c2410 ff37 ff15???????? 57 ff15???????? }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   c785b001000002000000     | mov    dword ptr [ebp + 0x1b0], 2
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   ff37                 | push                dword ptr [edi]
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_4 = { c645fc0e e8???????? c645fc0b 8b8560feffff 83f810 7213 40 }
            // n = 7, score = 100
            //   c645fc0e             | mov                 byte ptr [ebp - 4], 0xe
            //   e8????????           |                     
            //   c645fc0b             | mov                 byte ptr [ebp - 4], 0xb
            //   8b8560feffff         | mov                 eax, dword ptr [ebp - 0x1a0]
            //   83f810               | cmp                 eax, 0x10
            //   7213                 | jb                  0x15
            //   40                   | inc                 eax

        $sequence_5 = { c3 803e00 0f8508feffff 5f 5e 5d 33c0 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   803e00               | cmp                 byte ptr [esi], 0
            //   0f8508feffff         | jne                 0xfffffe0e
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { c3 83be0c06000000 744d 6a01 56 e8???????? ffb63c060000 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   83be0c06000000       | cmp                 dword ptr [esi + 0x60c], 0
            //   744d                 | je                  0x4f
            //   6a01                 | push                1
            //   56                   | push                esi
            //   e8????????           |                     
            //   ffb63c060000         | push                dword ptr [esi + 0x63c]

        $sequence_7 = { c7864c01000000000000 ff15???????? 8d8654010000 c7864001000000000000 50 e8???????? 8d8668030000 }
            // n = 7, score = 100
            //   c7864c01000000000000     | mov    dword ptr [esi + 0x14c], 0
            //   ff15????????         |                     
            //   8d8654010000         | lea                 eax, [esi + 0x154]
            //   c7864001000000000000     | mov    dword ptr [esi + 0x140], 0
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8668030000         | lea                 eax, [esi + 0x368]

        $sequence_8 = { ff15???????? 8b442428 83c404 898380000000 8bc6 c7879007000000000000 5e }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   83c404               | add                 esp, 4
            //   898380000000         | mov                 dword ptr [ebx + 0x80], eax
            //   8bc6                 | mov                 eax, esi
            //   c7879007000000000000     | mov    dword ptr [edi + 0x790], 0
            //   5e                   | pop                 esi

        $sequence_9 = { e8???????? 83c404 85c0 0f85c3020000 80fb2e 0f8572f9ffff e9???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   0f85c3020000         | jne                 0x2c9
            //   80fb2e               | cmp                 bl, 0x2e
            //   0f8572f9ffff         | jne                 0xfffff978
            //   e9????????           |                     

    condition:
        7 of them and filesize < 5134336
}
