rule win_luzo_auto {

    meta:
        id = "24Mq9CrDnxDsybno0VmqEL"
        fingerprint = "v1_sha256_8f1ca6d052d3446ebe4894142944ffaab2087a5e0687c53010e6cd7a10430b8d"
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
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.luzo"
        malpedia_version = "20180607"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff2510104000 ff251c104000 ff2568104000 ff2574104000 }
            // n = 4, score = 1000
            //   ff2510104000         | jmp                 dword ptr [0x401010]
            //   ff251c104000         | jmp                 dword ptr [0x40101c]
            //   ff2568104000         | jmp                 dword ptr [0x401068]
            //   ff2574104000         | jmp                 dword ptr [0x401074]

        $sequence_1 = { ff252c104000 ff2540104000 ff2564104000 ff2504104000 }
            // n = 4, score = 1000
            //   ff252c104000         | jmp                 dword ptr [0x40102c]
            //   ff2540104000         | jmp                 dword ptr [0x401040]
            //   ff2564104000         | jmp                 dword ptr [0x401064]
            //   ff2504104000         | jmp                 dword ptr [0x401004]

        $sequence_2 = { ff2528104000 ff255c104000 ff2550104000 ff2508104000 }
            // n = 4, score = 1000
            //   ff2528104000         | jmp                 dword ptr [0x401028]
            //   ff255c104000         | jmp                 dword ptr [0x40105c]
            //   ff2550104000         | jmp                 dword ptr [0x401050]
            //   ff2508104000         | jmp                 dword ptr [0x401008]

        $sequence_3 = { ff250c104000 ff2570104000 ff2524104000 ff2538104000 }
            // n = 4, score = 1000
            //   ff250c104000         | jmp                 dword ptr [0x40100c]
            //   ff2570104000         | jmp                 dword ptr [0x401070]
            //   ff2524104000         | jmp                 dword ptr [0x401024]
            //   ff2538104000         | jmp                 dword ptr [0x401038]

        $sequence_4 = { ff2534104000 ff2520104000 ff2530104000 ff2500104000 }
            // n = 4, score = 1000
            //   ff2534104000         | jmp                 dword ptr [0x401034]
            //   ff2520104000         | jmp                 dword ptr [0x401020]
            //   ff2530104000         | jmp                 dword ptr [0x401030]
            //   ff2500104000         | jmp                 dword ptr [0x401000]

        $sequence_5 = { ff2558104000 ff250c104000 ff2570104000 ff2524104000 }
            // n = 4, score = 1000
            //   ff2558104000         | jmp                 dword ptr [0x401058]
            //   ff250c104000         | jmp                 dword ptr [0x40100c]
            //   ff2570104000         | jmp                 dword ptr [0x401070]
            //   ff2524104000         | jmp                 dword ptr [0x401024]

        $sequence_6 = { ff2544104000 ff253c104000 ff254c104000 ff2514104000 }
            // n = 4, score = 1000
            //   ff2544104000         | jmp                 dword ptr [0x401044]
            //   ff253c104000         | jmp                 dword ptr [0x40103c]
            //   ff254c104000         | jmp                 dword ptr [0x40104c]
            //   ff2514104000         | jmp                 dword ptr [0x401014]

        $sequence_7 = { ff2540104000 ff2564104000 ff2504104000 ff256c104000 }
            // n = 4, score = 1000
            //   ff2540104000         | jmp                 dword ptr [0x401040]
            //   ff2564104000         | jmp                 dword ptr [0x401064]
            //   ff2504104000         | jmp                 dword ptr [0x401004]
            //   ff256c104000         | jmp                 dword ptr [0x40106c]

        $sequence_8 = { ff253c104000 ff254c104000 ff2514104000 ff2558104000 }
            // n = 4, score = 1000
            //   ff253c104000         | jmp                 dword ptr [0x40103c]
            //   ff254c104000         | jmp                 dword ptr [0x40104c]
            //   ff2514104000         | jmp                 dword ptr [0x401014]
            //   ff2558104000         | jmp                 dword ptr [0x401058]

        $sequence_9 = { ff2508104000 ff2518104000 ff2554104000 ff2544104000 }
            // n = 4, score = 1000
            //   ff2508104000         | jmp                 dword ptr [0x401008]
            //   ff2518104000         | jmp                 dword ptr [0x401018]
            //   ff2554104000         | jmp                 dword ptr [0x401054]
            //   ff2544104000         | jmp                 dword ptr [0x401044]

    condition:
        7 of them
}
