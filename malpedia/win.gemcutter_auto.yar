rule win_gemcutter_auto {

    meta:
        id = "6jw0WEvCNYqNY713bKIWfd"
        fingerprint = "v1_sha256_9745c8061ab88116351043d55251d3e8c32737ca442027c8a6620480abc8c8bf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.gemcutter."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gemcutter"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { fec8 8886a0314000 8a843579ffffff 46 ebea 395d08 889ea0314000 }
            // n = 7, score = 100
            //   fec8                 | dec                 al
            //   8886a0314000         | mov                 byte ptr [esi + 0x4031a0], al
            //   8a843579ffffff       | mov                 al, byte ptr [ebp + esi - 0x87]
            //   46                   | inc                 esi
            //   ebea                 | jmp                 0xffffffec
            //   395d08               | cmp                 dword ptr [ebp + 8], ebx
            //   889ea0314000         | mov                 byte ptr [esi + 0x4031a0], bl

        $sequence_1 = { 8d85f0fcffff 53 50 ffd6 8d85f0fcffff }
            // n = 5, score = 100
            //   8d85f0fcffff         | lea                 eax, [ebp - 0x310]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8d85f0fcffff         | lea                 eax, [ebp - 0x310]

        $sequence_2 = { 68???????? e8???????? 83c424 8b3d???????? 56 }
            // n = 5, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   8b3d????????         |                     
            //   56                   | push                esi

        $sequence_3 = { 6a01 ff15???????? 6a01 68???????? e8???????? 6a01 }
            // n = 6, score = 100
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   68????????           |                     
            //   e8????????           |                     
            //   6a01                 | push                1

        $sequence_4 = { e8???????? 83c424 8b3d???????? 56 33f6 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   8b3d????????         |                     
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi

        $sequence_5 = { 83c410 8d85f0fdffff 53 50 ffd6 8b3d???????? 8d85f0fdffff }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8b3d????????         |                     
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]

        $sequence_6 = { 57 53 6801001f00 ff15???????? 3bc3 be???????? }
            // n = 6, score = 100
            //   57                   | push                edi
            //   53                   | push                ebx
            //   6801001f00           | push                0x1f0001
            //   ff15????????         |                     
            //   3bc3                 | cmp                 eax, ebx
            //   be????????           |                     

        $sequence_7 = { 56 ff15???????? 8bf8 8d8500fcffff }
            // n = 4, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   8d8500fcffff         | lea                 eax, [ebp - 0x400]

        $sequence_8 = { fec8 8886a0314000 8a843579ffffff 46 ebea 395d08 }
            // n = 6, score = 100
            //   fec8                 | dec                 al
            //   8886a0314000         | mov                 byte ptr [esi + 0x4031a0], al
            //   8a843579ffffff       | mov                 al, byte ptr [ebp + esi - 0x87]
            //   46                   | inc                 esi
            //   ebea                 | jmp                 0xffffffec
            //   395d08               | cmp                 dword ptr [ebp + 8], ebx

        $sequence_9 = { 6a00 6801001f00 ff15???????? 85c0 7517 68e8030000 ff15???????? }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6801001f00           | push                0x1f0001
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7517                 | jne                 0x19
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 40960
}
