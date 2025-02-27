rule win_karagany_auto {

    meta:
        id = "2SL9SmjHhxDHPUHTN1Ydzw"
        fingerprint = "v1_sha256_e11ee77bbad2aed0526f0917e5fec6612f23198efabc3eebf7b6abb2227dd310"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.karagany."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.karagany"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a40 6800300000 6800000300 6a00 ff15???????? }
            // n = 5, score = 400
            //   6a40                 | push                0x40
            //   6800300000           | push                0x3000
            //   6800000300           | push                0x30000
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_1 = { ff15???????? 6a64 ff15???????? 5f 5e 33c0 5b }
            // n = 7, score = 400
            //   ff15????????         |                     
            //   6a64                 | push                0x64
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx

        $sequence_2 = { 55 8bec 81ec60060000 53 56 57 33c0 }
            // n = 7, score = 400
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec60060000         | sub                 esp, 0x660
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   33c0                 | xor                 eax, eax

        $sequence_3 = { ff15???????? 6a00 53 68???????? }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   68????????           |                     

        $sequence_4 = { 57 8bf8 6a03 57 ffd6 85c0 }
            // n = 6, score = 400
            //   57                   | push                edi
            //   8bf8                 | mov                 edi, eax
            //   6a03                 | push                3
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax

        $sequence_5 = { c745a444000000 e8???????? 83c40c 8d45ec }
            // n = 4, score = 400
            //   c745a444000000       | mov                 dword ptr [ebp - 0x5c], 0x44
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d45ec               | lea                 eax, [ebp - 0x14]

        $sequence_6 = { 8945d0 8945d8 8945e0 8945e8 }
            // n = 4, score = 400
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax

        $sequence_7 = { 50 ff15???????? 6a00 53 68???????? }
            // n = 5, score = 400
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   68????????           |                     

        $sequence_8 = { 6a03 53 ffd6 85c0 }
            // n = 4, score = 400
            //   6a03                 | push                3
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8945d8 8945e0 8945e8 8945ec 8945f4 }
            // n = 5, score = 400
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

    condition:
        7 of them and filesize < 180224
}
