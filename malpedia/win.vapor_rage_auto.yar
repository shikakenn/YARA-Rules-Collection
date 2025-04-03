rule win_vapor_rage_auto {

    meta:
        id = "5UCXHlf171nbl4GCS3w5r0"
        fingerprint = "v1_sha256_f25f99fbbd5c20118e31285e56e8f0280cb5b6b08bdd8f0f37cb8cec6e554ab7"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.vapor_rage."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vapor_rage"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b55f8 81ca80000000 8955f8 6a04 }
            // n = 4, score = 200
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   81ca80000000         | or                  edx, 0x80
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   6a04                 | push                4

        $sequence_1 = { 52 8b45e8 50 e8???????? 83c408 ff65e8 8b4de4 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   ff65e8               | jmp                 dword ptr [ebp - 0x18]
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]

        $sequence_2 = { f27502 f2c3 f2e94e030000 55 }
            // n = 4, score = 200
            //   f27502               | bnd jne             5
            //   f2c3                 | bnd ret             
            //   f2e94e030000         | bnd jmp             0x354
            //   55                   | push                ebp

        $sequence_3 = { f2c3 f2e94e030000 55 8bec }
            // n = 4, score = 200
            //   f2c3                 | bnd ret             
            //   f2e94e030000         | bnd jmp             0x354
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_4 = { 8945a4 8b55d4 52 e8???????? 83c404 }
            // n = 5, score = 200
            //   8945a4               | mov                 dword ptr [ebp - 0x5c], eax
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_5 = { c745f004000000 8d4df0 51 8d55f8 52 }
            // n = 5, score = 200
            //   c745f004000000       | mov                 dword ptr [ebp - 0x10], 4
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   51                   | push                ecx
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   52                   | push                edx

        $sequence_6 = { ff15???????? eb1e 8b4de4 51 ff15???????? }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   eb1e                 | jmp                 0x20
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_7 = { 746c 830d????????04 c705????????02000000 a900000008 7454 a9???????? }
            // n = 6, score = 200
            //   746c                 | je                  0x6e
            //   830d????????04       |                     
            //   c705????????02000000     |     
            //   a900000008           | test                eax, 0x8000000
            //   7454                 | je                  0x56
            //   a9????????           |                     

        $sequence_8 = { ff15???????? 8b4df8 81c900010000 894df8 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   81c900010000         | or                  ecx, 0x100
            //   894df8               | mov                 dword ptr [ebp - 8], ecx

        $sequence_9 = { 32db 885de7 c745fcfeffffff e8???????? 84db 0f8564ffffff e8???????? }
            // n = 7, score = 200
            //   32db                 | xor                 bl, bl
            //   885de7               | mov                 byte ptr [ebp - 0x19], bl
            //   c745fcfeffffff       | mov                 dword ptr [ebp - 4], 0xfffffffe
            //   e8????????           |                     
            //   84db                 | test                bl, bl
            //   0f8564ffffff         | jne                 0xffffff6a
            //   e8????????           |                     

    condition:
        7 of them and filesize < 296960
}
