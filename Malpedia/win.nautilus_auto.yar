rule win_nautilus_auto {

    meta:
        id = "23cymL2qZHkZiNrsWYoV9n"
        fingerprint = "v1_sha256_3519ef9bb4f52e1cd4586752506ba79e61c0e796a4c0e30324274e519044d1d2"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.nautilus."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nautilus"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { f20f11442430 c744242821000000 8364242000 488d0de0360100 ba0d000000 e8???????? e9???????? }
            // n = 7, score = 100
            //   f20f11442430         | jmp                 0x2b9
            //   c744242821000000     | inc                 ecx
            //   8364242000           | mov                 al, 1
            //   488d0de0360100       | test                eax, eax
            //   ba0d000000           | jne                 0x3ae
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_1 = { e8???????? be06000000 448d4601 85c0 7843 83f801 0f8e3b010000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   be06000000           | dec                 ecx
            //   448d4601             | mov                 dword ptr [ecx + 0x48], eax
            //   85c0                 | dec                 eax
            //   7843                 | mov                 ecx, dword ptr [esp + 0x2b0]
            //   83f801               | dec                 eax
            //   0f8e3b010000         | xor                 ecx, esp

        $sequence_2 = { e9???????? 413bfc 0f84c7000000 41be20000000 eb09 413bfc 0f84b6000000 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   413bfc               | dec                 eax
            //   0f84c7000000         | mov                 ecx, ebx
            //   41be20000000         | dec                 eax
            //   eb09                 | mov                 ecx, ebx
            //   413bfc               | dec                 eax
            //   0f84b6000000         | lea                 edx, [0x3fa9d]

        $sequence_3 = { 83f9ff 0f9dc0 85c0 7431 f20f1015???????? f20f5cd6 f20f5915???????? }
            // n = 7, score = 100
            //   83f9ff               | sub                 esp, 0x30
            //   0f9dc0               | dec                 eax
            //   85c0                 | mov                 edi, ecx
            //   7431                 | mov                 ebp, 2
            //   f20f1015????????     |                     
            //   f20f5cd6             | inc                 esp
            //   f20f5915????????     |                     

        $sequence_4 = { f30f7f00 f3410f7f0b 4883c010 4983eb10 493bc3 72e3 }
            // n = 6, score = 100
            //   f30f7f00             | lea                 ecx, [edx - 1]
            //   f3410f7f0b           | sete                al
            //   4883c010             | inc                 ecx
            //   4983eb10             | mov                 edx, edx
            //   493bc3               | inc                 esp
            //   72e3                 | or                  al, al

        $sequence_5 = { 8d43a0 894550 e8???????? 4c8b7de0 8bd8 85c0 0f851effffff }
            // n = 7, score = 100
            //   8d43a0               | mov                 ebp, edi
            //   894550               | inc                 esp
            //   e8????????           |                     
            //   4c8b7de0             | mov                 esp, edi
            //   8bd8                 | inc                 esp
            //   85c0                 | mov                 edi, edi
            //   0f851effffff         | inc                 esp

        $sequence_6 = { b9bb0b0000 e8???????? 418bc7 4585ed 7e10 488d4dff 8801 }
            // n = 7, score = 100
            //   b9bb0b0000           | mov                 esi, dword ptr [ebx + 0x444]
            //   e8????????           |                     
            //   418bc7               | dec                 eax
            //   4585ed               | mov                 eax, dword ptr [ebx]
            //   7e10                 | inc                 esp
            //   488d4dff             | cmp                 dword ptr [eax + 0x24], edx
            //   8801                 | jne                 0x184b

        $sequence_7 = { 744c 83f808 0f8483000000 83f81b 7564 4983c202 4983e802 }
            // n = 7, score = 100
            //   744c                 | xor                 edx, edx
            //   83f808               | xor                 ecx, ecx
            //   0f8483000000         | inc                 ebp
            //   83f81b               | xor                 eax, eax
            //   7564                 | xor                 edx, edx
            //   4983c202             | xor                 ecx, ecx
            //   4983e802             | inc                 ebp

        $sequence_8 = { 48896c2410 4889742418 57 4883ec20 488b4118 488be9 488bfa }
            // n = 7, score = 100
            //   48896c2410           | dec                 esp
            //   4889742418           | mov                 dword ptr [esp + 0x60], eax
            //   57                   | dec                 eax
            //   4883ec20             | mov                 dword ptr [edi + 0xc8], eax
            //   488b4118             | inc                 ecx
            //   488be9               | mov                 eax, 0x18
            //   488bfa               | dec                 eax

        $sequence_9 = { ff15???????? 8bd8 85c0 74a8 83f826 0f8521010000 448b442450 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8bd8                 | inc                 ebp
            //   85c0                 | xor                 eax, eax
            //   74a8                 | dec                 eax
            //   83f826               | mov                 edx, edi
            //   0f8521010000         | jmp                 0x3db
            //   448b442450           | mov                 edx, edi

    condition:
        7 of them and filesize < 1302528
}
