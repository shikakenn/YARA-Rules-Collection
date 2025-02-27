rule win_doublefinger_auto {

    meta:
        id = "7bNZhnNs9SsngE4tlCCoN1"
        fingerprint = "v1_sha256_3eae491d263429c9200953e488faaa30692919588c48a865c32492ea2fca792f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.doublefinger."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doublefinger"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0fb70401 83f82f 750e 488b442430 4883c002 4889442430 }
            // n = 6, score = 100
            //   0fb70401             | dec                 eax
            //   83f82f               | mov                 ecx, dword ptr [esp + 0x68]
            //   750e                 | dec                 eax
            //   488b442430           | mov                 dword ptr [esp + 0x20], 0
            //   4883c002             | dec                 esp
            //   4889442430           | lea                 ecx, [esp + 0x40]

        $sequence_1 = { 33c0 488705???????? 48833d????????00 742a 488d0d9f540000 e8???????? 85c0 }
            // n = 7, score = 100
            //   33c0                 | dec                 eax
            //   488705????????       |                     
            //   48833d????????00     |                     
            //   742a                 | mov                 ecx, eax
            //   488d0d9f540000       | mov                 edx, 1
            //   e8????????           |                     
            //   85c0                 | mov                 edx, 0x3ee

        $sequence_2 = { 486bc005 c64404588c b801000000 486bc006 c6440458ee }
            // n = 5, score = 100
            //   486bc005             | dec                 eax
            //   c64404588c           | mov                 dword ptr [esp + 0x2e0], eax
            //   b801000000           | mov                 dword ptr [esp + 0x130], 0xcb1508dc
            //   486bc006             | mov                 dword ptr [esp + 0x134], 0xc97c1fff
            //   c6440458ee           | mov                 dword ptr [esp + 0x138], 0x9febe16c

        $sequence_3 = { 90 ff15???????? 8bc8 4c8d4c2460 4c8d442458 488d542450 e8???????? }
            // n = 7, score = 100
            //   90                   | dec                 eax
            //   ff15????????         |                     
            //   8bc8                 | shl                 eax, 1
            //   4c8d4c2460           | inc                 esp
            //   4c8d442458           | mov                 eax, eax
            //   488d542450           | dec                 eax
            //   e8????????           |                     

        $sequence_4 = { 4863442404 8b4c2404 8b1424 03d1 8bca 034c2408 8bc9 }
            // n = 7, score = 100
            //   4863442404           | cmp                 dword ptr [esp + 0x2c], 0
            //   8b4c2404             | jne                 0x1adf
            //   8b1424               | dec                 eax
            //   03d1                 | mov                 ecx, dword ptr [esp + 0x60]
            //   8bca                 | dec                 eax
            //   034c2408             | mov                 ecx, ebx
            //   8bc9                 | inc                 ebp

        $sequence_5 = { 488b442428 4889442430 83bc24f000000000 7512 837c242000 750b 488b442430 }
            // n = 7, score = 100
            //   488b442428           | mov                 dword ptr [esp + 0x20], eax
            //   4889442430           | dec                 esp
            //   83bc24f000000000     | lea                 ecx, [esp + 0x1b0]
            //   7512                 | dec                 eax
            //   837c242000           | mov                 eax, dword ptr [esp + 0x1d0]
            //   750b                 | inc                 esp
            //   488b442430           | mov                 eax, dword ptr [eax + 0xc]

        $sequence_6 = { 48894c2408 4881ec78030000 488b842488030000 480564010000 4889442428 c744242000000000 eb0a }
            // n = 7, score = 100
            //   48894c2408           | mov                 eax, dword ptr [esp + 0xd8]
            //   4881ec78030000       | call                dword ptr [eax + 8]
            //   488b842488030000     | dec                 eax
            //   480564010000         | mov                 dword ptr [esp + 0x68], eax
            //   4889442428           | dec                 eax
            //   c744242000000000     | cmp                 dword ptr [esp + 0x68], 0
            //   eb0a                 | dec                 eax

        $sequence_7 = { e8???????? 33d2 48c7c1ffffffff ff9424b0000000 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   33d2                 | test                eax, eax
            //   48c7c1ffffffff       | jne                 0x1032
            //   ff9424b0000000       | dec                 eax

        $sequence_8 = { c7042400000000 8b0424 488b4c2420 0fb70441 85c0 }
            // n = 5, score = 100
            //   c7042400000000       | mov                 eax, dword ptr [esp + 0x240]
            //   8b0424               | dec                 eax
            //   488b4c2420           | mov                 dword ptr [esp + 0x330], eax
            //   0fb70441             | dec                 eax
            //   85c0                 | mov                 eax, dword ptr [esp + 0x248]

        $sequence_9 = { ff9424c0000000 4889842480010000 b875000000 6689842400010000 b872000000 }
            // n = 5, score = 100
            //   ff9424c0000000       | dec                 eax
            //   4889842480010000     | lea                 ecx, [esp + 0x48]
            //   b875000000           | dec                 eax
            //   6689842400010000     | lea                 ecx, [esp + 0x30]
            //   b872000000           | dec                 eax

    condition:
        7 of them and filesize < 115712
}
