rule win_chiser_client_auto {

    meta:
        id = "2pJJSnJlS6Avevy7P2d5i1"
        fingerprint = "v1_sha256_4cf569331733e568f50794a1dc9bdd96595cb2c255defe55202f75e9deeee12b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.chiser_client."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chiser_client"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 48895c2408 48896c2410 4889742418 48897c2420 4156 0fb605???????? 488d7222 }
            // n = 7, score = 100
            //   48895c2408           | dec                 eax
            //   48896c2410           | mov                 dword ptr [eax + 0x10], esi
            //   4889742418           | dec                 eax
            //   48897c2420           | mov                 dword ptr [esp + 0x70], esi
            //   4156                 | dec                 eax
            //   0fb605????????       |                     
            //   488d7222             | mov                 dword ptr [ebp - 0x80], esi

        $sequence_1 = { 4d8bf0 4c8bfa 488bf9 488b5908 48895c2448 488bcb e8???????? }
            // n = 7, score = 100
            //   4d8bf0               | dec                 eax
            //   4c8bfa               | lea                 edx, [ecx + 8]
            //   488bf9               | dec                 eax
            //   488b5908             | mov                 ecx, dword ptr [esi + 8]
            //   48895c2448           | dec                 eax
            //   488bcb               | mov                 ecx, dword ptr [esi]
            //   e8????????           |                     

        $sequence_2 = { 8364242800 488d05e895feff 4889442430 488d4c2420 e8???????? 4c396b08 }
            // n = 6, score = 100
            //   8364242800           | pop                 edi
            //   488d05e895feff       | ret                 
            //   4889442430           | dec                 eax
            //   488d4c2420           | mov                 edx, dword ptr [edi + 0x40]
            //   e8????????           |                     
            //   4c396b08             | inc                 ebp

        $sequence_3 = { 48894a08 488d4808 e8???????? 488d055da00100 488903 }
            // n = 5, score = 100
            //   48894a08             | dec                 eax
            //   488d4808             | mov                 esi, edx
            //   e8????????           |                     
            //   488d055da00100       | inc                 eax
            //   488903               | push                edi

        $sequence_4 = { c705????????090400c0 c705????????01000000 c705????????01000000 b808000000 486bc000 488d0dae5e0400 }
            // n = 6, score = 100
            //   c705????????090400c0     |     
            //   c705????????01000000     |     
            //   c705????????01000000     |     
            //   b808000000           | mov                 eax, 2
            //   486bc000             | dec                 eax
            //   488d0dae5e0400       | mul                 edi

        $sequence_5 = { e8???????? b876000000 668945b7 488d55b7 488d4dd7 e8???????? b861000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   b876000000           | je                  0xc7f
            //   668945b7             | dec                 eax
            //   488d55b7             | lea                 ecx, [0x21797]
            //   488d4dd7             | dec                 eax
            //   e8????????           |                     
            //   b861000000           | mov                 dword ptr [eax], ecx

        $sequence_6 = { c7452700000000 e8???????? 4889451f 488d05d0e20100 48894517 4883653700 c6454700 }
            // n = 7, score = 100
            //   c7452700000000       | mov                 dword ptr [esp + 0x20], eax
            //   e8????????           |                     
            //   4889451f             | dec                 eax
            //   488d05d0e20100       | add                 esp, 0x38
            //   48894517             | ret                 
            //   4883653700           | dec                 eax
            //   c6454700             | sub                 esp, 0x48

        $sequence_7 = { 488b4c2478 4885c9 740b ff15???????? 4c89742478 488b4d88 4885c9 }
            // n = 7, score = 100
            //   488b4c2478           | push                edi
            //   4885c9               | dec                 eax
            //   740b                 | sub                 esp, 0x20
            //   ff15????????         |                     
            //   4c89742478           | dec                 eax
            //   488b4d88             | mov                 ebx, ecx
            //   4885c9               | dec                 eax

        $sequence_8 = { 4c8d0d82ac0200 8bda 4c8d0571ac0200 488bf9 488d15c7a60200 b908000000 }
            // n = 6, score = 100
            //   4c8d0d82ac0200       | mov                 dword ptr [esp + 0x28], eax
            //   8bda                 | dec                 ebp
            //   4c8d0571ac0200       | mov                 eax, ebp
            //   488bf9               | dec                 eax
            //   488d15c7a60200       | lea                 eax, [ebp - 1]
            //   b908000000           | dec                 eax

        $sequence_9 = { 4883ec20 488bd9 488bc2 488d0dd9150200 48890b 488d5308 33c9 }
            // n = 7, score = 100
            //   4883ec20             | inc                 ecx
            //   488bd9               | movzx               ecx, dh
            //   488bc2               | shr                 cl, 2
            //   488d0dd9150200       | inc                 eax
            //   48890b               | add                 bh, al
            //   488d5308             | movzx               eax, cl
            //   33c9                 | inc                 ecx

    condition:
        7 of them and filesize < 714752
}
