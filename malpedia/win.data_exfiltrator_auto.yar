rule win_data_exfiltrator_auto {

    meta:
        id = "3KaIvgGmOVNi3hYDDXT4WX"
        fingerprint = "v1_sha256_6297c1d8a56d8255bac738410a860d5a8da8f6a36d36d069cc390dc91a10d95e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.data_exfiltrator."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.data_exfiltrator"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 488b442408 c60000 488b442408 48c7404000000000 488b442408 }
            // n = 5, score = 100
            //   488b442408           | dec                 eax
            //   c60000               | lea                 ecx, [0x3740]
            //   488b442408           | dec                 eax
            //   48c7404000000000     | lea                 ecx, [0x3740]
            //   488b442408           | dec                 eax

        $sequence_1 = { c684248a0000008a c684248b0000007b c684248c00000084 c684248d00000085 }
            // n = 4, score = 100
            //   c684248a0000008a     | mov                 eax, dword ptr [esp + 0x28]
            //   c684248b0000007b     | dec                 eax
            //   c684248c00000084     | mov                 ecx, dword ptr [esp + 0x78]
            //   c684248d00000085     | dec                 eax

        $sequence_2 = { 4889842490000000 488d842410010000 488d8c2490000000 488bf8 488bf1 }
            // n = 5, score = 100
            //   4889842490000000     | dec                 esp
            //   488d842410010000     | mov                 eax, dword ptr [esp + 0x20]
            //   488d8c2490000000     | inc                 ebp
            //   488bf8               | xor                 eax, eax
            //   488bf1               | dec                 eax

        $sequence_3 = { 33c0 e9???????? 488b442420 488b4018 488b4020 4889442430 }
            // n = 6, score = 100
            //   33c0                 | mov                 dword ptr [esp + 0x28], eax
            //   e9????????           |                     
            //   488b442420           | dec                 eax
            //   488b4018             | mov                 dword ptr [esp + 0x38], 0
            //   488b4020             | dec                 eax
            //   4889442430           | mov                 dword ptr [esp + 0x58], 0

        $sequence_4 = { c68424a50000004a c68424a600000070 c68424a700000077 c68424a800000069 c68424a900000077 c68424aa00000074 c68424ab0000006c }
            // n = 7, score = 100
            //   c68424a50000004a     | dec                 eax
            //   c68424a600000070     | mov                 edx, dword ptr [esp + 0x50]
            //   c68424a700000077     | xor                 edx, edx
            //   c68424a800000069     | dec                 eax
            //   c68424a900000077     | mov                 ecx, dword ptr [esp + 0x28]
            //   c68424aa00000074     | dec                 esp
            //   c68424ab0000006c     | mov                 eax, dword ptr [esp + 0x28]

        $sequence_5 = { 56 57 4881ecb8000000 c744242000000000 33d2 488b8424d0000000 488b4040 }
            // n = 7, score = 100
            //   56                   | mov                 byte ptr [esp + 0x38], 0x78
            //   57                   | mov                 byte ptr [esp + 0x39], 0x78
            //   4881ecb8000000       | mov                 byte ptr [esp + 0x34], 0x6d
            //   c744242000000000     | mov                 byte ptr [esp + 0x35], 0x4f
            //   33d2                 | mov                 byte ptr [esp + 0x36], 0x72
            //   488b8424d0000000     | mov                 byte ptr [esp + 0x37], 0x78
            //   488b4040             | mov                 byte ptr [esp + 0x38], 0x78

        $sequence_6 = { 48837c24300a 7d10 488b442430 4883c030 4889442438 eb1a 488b442430 }
            // n = 7, score = 100
            //   48837c24300a         | mov                 edx, 0x3000
            //   7d10                 | mov                 ecx, 8
            //   488b442430           | dec                 eax
            //   4883c030             | lea                 ecx, [0x3ab5]
            //   4889442438           | dec                 eax
            //   eb1a                 | mov                 dword ptr [esp + 0x38], 1
            //   488b442430           | mov                 dword ptr [esp + 0x30], 0

        $sequence_7 = { ff15???????? 4889842480000000 eb13 488b4c2478 ff15???????? 4889842480000000 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   4889842480000000     | mov                 dword ptr [esp + 0x64], 1
            //   eb13                 | movzx               eax, byte ptr [esp + 0x140]
            //   488b4c2478           | dec                 eax
            //   ff15????????         |                     
            //   4889842480000000     | mov                 ecx, dword ptr [esp + 0x38]

        $sequence_8 = { e8???????? 8bc0 41b840000000 ba00300000 8bc8 e8???????? 4889442468 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bc0                 | cmp                 dword ptr [esp + 0x28], eax
            //   41b840000000         | jae                 0xfa6
            //   ba00300000           | dec                 eax
            //   8bc8                 | mov                 eax, dword ptr [esp + 0x28]
            //   e8????????           |                     
            //   4889442468           | dec                 eax

        $sequence_9 = { 4889542410 48894c2408 4883ec48 ff15???????? 41b8ffff0000 ba08000000 488bc8 }
            // n = 7, score = 100
            //   4889542410           | dec                 esp
            //   48894c2408           | lea                 eax, [esp + 0x20]
            //   4883ec48             | dec                 eax
            //   ff15????????         |                     
            //   41b8ffff0000         | mov                 edx, dword ptr [esp + 0x40]
            //   ba08000000           | dec                 eax
            //   488bc8               | mov                 ecx, 0xffffffff

    condition:
        7 of them and filesize < 107520
}
