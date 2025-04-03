rule win_quasar_rat_auto {

    meta:
        id = "1ii0jEYZhzmr1iFBXxITMC"
        fingerprint = "v1_sha256_e8a8f0c1d41afaabf179a2e29e162408f00f3e4ced264373e6d1dd20b845a1f2"
        version = "1"
        date = "2018-11-23"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator 0.1a"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat"
        malpedia_version = "20180607"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 24c1 0430 e800000000 8408 }
            // n = 4, score = 1000
            //   24c1                 | and                 al, 0xc1
            //   0430                 | add                 al, 0x30
            //   e800000000           | call                0x42394c
            //   8408                 | test                byte ptr [eax], cl

        $sequence_1 = { e800000000 8408 d408 0100 }
            // n = 4, score = 1000
            //   e800000000           | call                0x42394c
            //   8408                 | test                byte ptr [eax], cl
            //   d408                 | aam                 8
            //   0100                 | add                 dword ptr [eax], eax

        $sequence_2 = { c508 0100 5a 24c1 }
            // n = 4, score = 1000
            //   c508                 | lds                 ecx, ptr [eax]
            //   0100                 | add                 dword ptr [eax], eax
            //   5a                   | pop                 edx
            //   24c1                 | and                 al, 0xc1

        $sequence_3 = { 61 00c0 0428 e800000000 }
            // n = 4, score = 1000
            //   61                   | popal               
            //   00c0                 | add                 al, al
            //   0428                 | add                 al, 0x28
            //   e800000000           | call                0x42393c

        $sequence_4 = { 00c0 0428 e800000000 8408 }
            // n = 4, score = 1000
            //   00c0                 | add                 al, al
            //   0428                 | add                 al, 0x28
            //   e800000000           | call                0x42393c
            //   8408                 | test                byte ptr [eax], cl

        $sequence_5 = { e800000000 8408 c508 0100 }
            // n = 4, score = 1000
            //   e800000000           | call                0x42393c
            //   8408                 | test                byte ptr [eax], cl
            //   c508                 | lds                 ecx, ptr [eax]
            //   0100                 | add                 dword ptr [eax], eax

        $sequence_6 = { 60 24c1 043c e800000000 }
            // n = 4, score = 1000
            //   60                   | pushal              
            //   24c1                 | and                 al, 0xc1
            //   043c                 | add                 al, 0x3c
            //   e800000000           | call                0x42395c

        $sequence_7 = { d408 0100 60 24c1 }
            // n = 4, score = 1000
            //   d408                 | aam                 8
            //   0100                 | add                 dword ptr [eax], eax
            //   60                   | pushal              
            //   24c1                 | and                 al, 0xc1

        $sequence_8 = { e800000000 8418 ee 0200 }
            // n = 4, score = 1000
            //   e800000000           | call                0x42395c
            //   8418                 | test                byte ptr [eax], bl
            //   ee                   | out                 dx, al
            //   0200                 | add                 al, byte ptr [eax]

        $sequence_9 = { 0100 5a 24c1 0430 }
            // n = 4, score = 1000
            //   0100                 | add                 dword ptr [eax], eax
            //   5a                   | pop                 edx
            //   24c1                 | and                 al, 0xc1
            //   0430                 | add                 al, 0x30

    condition:
        7 of them
}
