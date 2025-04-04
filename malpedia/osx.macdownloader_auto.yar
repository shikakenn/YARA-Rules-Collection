rule osx_macdownloader_auto {

    meta:
        id = "1k42axnCMefiHLvpLAKlbr"
        fingerprint = "v1_sha256_53ee010a6e298b403ebca0f28d1624ac3e198ed98776743b094678dd06c81337"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.macdownloader"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 81fbfdffff5f 722d 48 8d0d00390100 bf07000000 be???????? ba???????? }
            // n = 7, score = 100
            //   81fbfdffff5f         | cmp                 ebx, 0x5ffffffd
            //   722d                 | jb                  0x2f
            //   48                   | dec                 eax
            //   8d0d00390100         | lea                 ecx, [0x13900]
            //   bf07000000           | mov                 edi, 7
            //   be????????           |                     
            //   ba????????           |                     

        $sequence_1 = { e8???????? 49 89c5 e9???????? 48 8d0def360100 bf08000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   49                   | dec                 ecx
            //   89c5                 | mov                 ebp, eax
            //   e9????????           |                     
            //   48                   | dec                 eax
            //   8d0def360100         | lea                 ecx, [0x136ef]
            //   bf08000000           | mov                 edi, 8

        $sequence_2 = { 8d0d93390100 bf07000000 be???????? ba???????? 41 b8???????? e8???????? }
            // n = 7, score = 100
            //   8d0d93390100         | lea                 ecx, [0x13993]
            //   bf07000000           | mov                 edi, 7
            //   be????????           |                     
            //   ba????????           |                     
            //   41                   | inc                 ecx
            //   b8????????           |                     
            //   e8????????           |                     

        $sequence_3 = { 89c7 e8???????? b901000000 f20f1005???????? 48 8b55e0 48 }
            // n = 7, score = 100
            //   89c7                 | mov                 edi, eax
            //   e8????????           |                     
            //   b901000000           | mov                 ecx, 1
            //   f20f1005????????     |                     
            //   48                   | dec                 eax
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   48                   | dec                 eax

        $sequence_4 = { e8???????? 48 8d05a3d90200 48 89c7 e8???????? 48 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8d05a3d90200         | lea                 eax, [0x2d9a3]
            //   48                   | dec                 eax
            //   89c7                 | mov                 edi, eax
            //   e8????????           |                     
            //   48                   | dec                 eax

        $sequence_5 = { 31c0 45 31ed 4c 8d3523a80100 }
            // n = 5, score = 100
            //   31c0                 | xor                 eax, eax
            //   45                   | inc                 ebp
            //   31ed                 | xor                 ebp, ebp
            //   4c                   | dec                 esp
            //   8d3523a80100         | lea                 esi, [0x1a823]

        $sequence_6 = { 41 0f95c0 41 80f0ff 48 89c7 44 }
            // n = 7, score = 100
            //   41                   | inc                 ecx
            //   0f95c0               | setne               al
            //   41                   | inc                 ecx
            //   80f0ff               | xor                 al, 0xff
            //   48                   | dec                 eax
            //   89c7                 | mov                 edi, eax
            //   44                   | inc                 esp

        $sequence_7 = { 8a08 84c9 75cc 48 8b45d0 4b 89043c }
            // n = 7, score = 100
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   84c9                 | test                cl, cl
            //   75cc                 | jne                 0xffffffce
            //   48                   | dec                 eax
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   4b                   | dec                 ebx
            //   89043c               | mov                 dword ptr [esp + edi], eax

        $sequence_8 = { 48 8d15af380100 b9???????? 44 }
            // n = 4, score = 100
            //   48                   | dec                 eax
            //   8d15af380100         | lea                 edx, [0x138af]
            //   b9????????           |                     
            //   44                   | inc                 esp

        $sequence_9 = { 8965d8 48 8d159e9a0000 4c 8d75c0 }
            // n = 5, score = 100
            //   8965d8               | mov                 dword ptr [ebp - 0x28], esp
            //   48                   | dec                 eax
            //   8d159e9a0000         | lea                 edx, [0x9a9e]
            //   4c                   | dec                 esp
            //   8d75c0               | lea                 esi, [ebp - 0x40]

    condition:
        7 of them and filesize < 580832
}
