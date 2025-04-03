rule Linux_Trojan_Tsunami_d9e6b88e {
    meta:
        id = "2WxucndXvlBqFmaC126P7Y"
        fingerprint = "v1_sha256_979d2ae62efca0f719ed1db2ff832dc9a0aa0347dcd50ccede29ec35cba6d296"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "a4ac275275e7be694a200fe6c5c5746256398c109cf54f45220637fe5d9e26ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 04 02 01 20 03 20 02 C9 07 40 4E 00 60 01 C0 04 17 B6 92 07 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_30c039e2 {
    meta:
        id = "1Ma8XXa8fl5jYSo1r40pKB"
        fingerprint = "v1_sha256_a9dbfede68a3209b403aa40dbc5b69326c3e1c14259ed6bc6351f0f9412cfce2"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "b494ca3b7bae2ab9a5197b81e928baae5b8eac77dfdc7fe1223fee8f27024772"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 E0 0F B6 00 84 C0 74 1F 48 8B 45 E0 48 8D 50 01 48 8B 45 E8 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_c94eec37 {
    meta:
        id = "7i68nImCZJMItjS4o9379J"
        fingerprint = "v1_sha256_39a49e1661ac2ca6a43a56b0bd136976f6d506c0779d862a43ba2c25d6947fee"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "294fcdd57fc0a53e2d63b620e85fa65c00942db2163921719d052d341aa2dc30"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 05 88 10 8B 45 E4 0F B6 10 83 E2 0F 83 CA 40 88 10 8B 45 E4 C6 40 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_f806d5d9 {
    meta:
        id = "2WLuxkFhy1Qh8jENhZkBvN"
        fingerprint = "v1_sha256_86336f662e3abcf2fe7635155782c549fc9eef514356bf78bfbc3b65192e2d90"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "5259495788f730a2a3bad7478c1873c8a6296506a778f18bc68e39ce48b979da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 54 45 48 54 54 50 20 3C 68 6F 73 74 3E 20 3C 73 72 63 3A }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_0fa3a6e9 {
    meta:
        id = "2yLjIA0cW4KbZ6gPhlnuXj"
        fingerprint = "v1_sha256_970062e909ffe5356b750605f2c44a6e893949bc5bc71be3ea98b16e51629d4d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "40a15a186373a062bfb476b37a73c61e1ba84e5fa57282a7f9ec0481860f372a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EC 8B 55 EC C1 FA 10 0F B7 45 EC 01 C2 89 55 EC 8B 45 EC C1 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_36a98405 {
    meta:
        id = "1DlkRMUijzf78FbRUouu7h"
        fingerprint = "v1_sha256_a32d324d1865a7796faefbc2f209e6043008a696929fe7837afbbc770e6f4c74"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "a57de6cd3468f55b4bfded5f1eed610fdb2cbffbb584660ae000c20663d5b304"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 05 88 85 50 FF FF FF 0F B6 85 50 FF FF FF 83 E0 0F 83 C8 40 88 85 50 FF }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_0c6686b8 {
    meta:
        id = "2OYEKUZleoNG97nAXTtkSo"
        fingerprint = "v1_sha256_731bb3f9957e8777040c0b7b316a818f4ee1ca9a113fb9eed24ee61bfc71e11d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 F8 31 C0 48 8B 45 C8 0F B7 40 02 66 89 45 D0 48 8B 45 C8 8B }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_9ce5b69f {
    meta:
        id = "5xnw3aXsXRnHGGYast4s2R"
        fingerprint = "v1_sha256_b9756eb99e59ba3a9a616b391bcf26bda26a6ac0de115460f9ba52129f590764"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "ad63fbd15b7de4da0db1b38609b7481253c100e3028c19831a5d5c1926351829"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F4 8B 54 85 B4 8B 45 E4 8D 04 02 C6 00 00 FF 45 F4 8B 45 E4 01 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_55a80ab6 {
    meta:
        id = "3eWYIZaqjgyNkzYEn4EvuO"
        fingerprint = "v1_sha256_1fc29f98e9ea2a5b67d0a88f37813a5e62b5f1d2a26aee74f90e9ead445dc713"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "5259495788f730a2a3bad7478c1873c8a6296506a778f18bc68e39ce48b979da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 74 68 65 20 63 75 72 72 65 6E 74 20 73 70 6F 6F 66 69 6E 67 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_e98b83ee {
    meta:
        id = "2dpaC25b8sZwe38aVUggto"
        fingerprint = "v1_sha256_8b16c0fee991ee2143a20998097066a90b1f20060bac7b42e5c3188adcdc7907"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 FE 00 00 EB 16 48 8B 55 D8 0F B7 02 0F B7 C0 01 45 E0 48 83 45 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_8a11f9be {
    meta:
        id = "4kdY3ZBniH3fVYl0xYXJkY"
        fingerprint = "v1_sha256_f80dcb3579a76da787e9bb2bfb02ef86e464aec1bea405f02642b8c8902c7663"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "1f773d0e00d40eecde9e3ab80438698923a2620036c2fc33315ef95229e98571"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 3E 20 3C 70 6F 72 74 3E 20 3C 72 65 66 6C 65 63 74 69 6F 6E 20 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_2462067e {
    meta:
        id = "5kNqvoD24EqeVfo9ejJEF4"
        fingerprint = "v1_sha256_cf6c0703f9108f8193e0a9c18ba3d76263527a13fe44e194fa464d399512ae05"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "3847f1c7c15ce771613079419de3d5e8adc07208e1fefa23f7dd416b532853a1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 45 F4 8B 40 0C 89 C1 8B 45 F4 8B 40 10 8B 10 8D 45 E4 89 C7 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_0a028640 {
    meta:
        id = "2IRcLZrAYrbVvVrXaQAEKJ"
        fingerprint = "v1_sha256_663f110c7214498466759b66a83ff1844f5bf45ce706fa8ad0e8b205cc9c8f72"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "e36081f0dbd6d523c9378cdd312e117642b0359b545b29a61d8f9027d8c0f2f0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 85 C0 74 2D 8B 45 0C 0F B6 00 84 C0 74 19 8B 45 0C 83 C0 01 83 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_47f93be2 {
    meta:
        id = "3zndoY6ktExLBtmnFWVhWP"
        fingerprint = "v1_sha256_5db2ac31ecacfbce1dedc64d0ce4c7d6be5857b51558d4b8a4d633f47240f77b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "2e4f89c76dfefd4b2bfd1cf0467ac0324026355723950d12d7ed51195fd998cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FA 48 63 C6 48 89 94 C5 70 FF FF FF 8B 85 5C FF FF FF 8D 78 01 48 8D 95 60 FF }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_6b3974b2 {
    meta:
        id = "1mjbTtYdWYqpKMkHJPqRtX"
        fingerprint = "v1_sha256_7c44a0abcd51a6b775fc379b592652ebb10faf16c039ca23b20984183340cada"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "2216776ba5c6495d86a13f6a3ce61b655b72a328ca05b3678d1abb7a20829d04"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F4 89 45 EC 8B 45 EC C9 C3 55 89 E5 57 83 EC 0C EB 1F 8B 45 08 B9 FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_87bcb848 {
    meta:
        id = "6YM0e1iTtL9NwgR9oCfsre"
        fingerprint = "v1_sha256_60e8aa7e27ea0bec665075a373ce150c21af4cddfd511b7ec771293126f0006c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "575b0dc887d132aa3983e5712b8f642b03762b0685fbd5a32c104bca72871857"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 65 6D 6F 74 65 00 52 65 6D 6F 74 65 20 49 52 43 20 42 6F 74 00 23 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_ad60d7e8 {
    meta:
        id = "TlfEcZG1EuLelNUw2zJaX"
        fingerprint = "v1_sha256_1253a8cd1a5230f1ec1f8c7ecd07f89f28acf5c2aa92395c6cb9e635c16a1e25"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4E 4F 54 49 43 45 20 25 73 20 3A 53 70 6F 6F 66 73 3A 20 25 64 2E 25 64 2E 25 64 2E 25 64 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_22646c0d {
    meta:
        id = "5GwSmEnovva7zII77wze1I"
        fingerprint = "v1_sha256_548f531429132392f6d9bccff706b56ba87d8e44763116dedca5d0baa5097b92"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "20439a8fc21a94c194888725fbbb7a7fbeef5faf4b0f704559d89f1cd2e57d9d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { CB 01 00 00 55 53 51 52 48 01 FE 56 48 89 FE 48 89 D7 31 DB }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_019f0e75 {
    meta:
        id = "7k0FzfMYdnbWN5adL7PuLp"
        fingerprint = "v1_sha256_7a63eb94266b04a31ba67165c512e2e060c3e344665aeed748a51943143b2219"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "575b0dc887d132aa3983e5712b8f642b03762b0685fbd5a32c104bca72871857"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 2E 0A 00 2B 73 74 64 00 2B 73 74 6F 70 00 2B 75 6E 6B 6E 6F }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_7c545abf {
    meta:
        id = "5umbZ0XeNPqMJ36SdbKfVz"
        fingerprint = "v1_sha256_fa50ccc4c85417d18a84b7f117f853609c44b17c488a937cdc7495e2d32757f7"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "95691c7ad1d80f7f1b5541e1d1a1dbeba30a26702a4080d256f14edb75851c5d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 03 FC DF 40 9C B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_32c0b950 {
    meta:
        id = "2AumS7rkJZSnx2BbwDmbR2"
        fingerprint = "v1_sha256_db077e5916327ca78fcc9dc35f64e5c497dbbe60c4a0c1eb7abb49c555765681"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "214c1caf20ceae579476d3bf97f489484df4c5f1c0c44d37ff9b9066072cd83c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 05 20 BC F8 41 B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_cbf50d9c {
    meta:
        id = "2kwHLC6AKnUORZYubfGt0R"
        fingerprint = "v1_sha256_331a35fb3ecc54022b1d4d05bd64e7c5c6a7997b06dbea3a36c33ccc0a2f7086"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "b64d0cf4fc4149aa4f63900e61b6739e154d328ea1eb31f4c231016679fc4aa5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 07 F8 BF 81 9C B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_40c25a06 {
    meta:
        id = "7j6kyxaLigDo7KXJbOWOZZ"
        fingerprint = "v1_sha256_38976911ff9e56fae27fad8b9df01063ed703f43c8220b1fbcef7a3945b3f1ad"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "61af6bb7be25465e7d469953763be5671f33c197d4b005e4a78227da11ae91e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 20 74 13 9C B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_35806adc {
    meta:
        id = "3m3lS6X8MinIMzzOtsK6MM"
        fingerprint = "v1_sha256_6e9d3e5c0a33208d1b5f4f84f8634955e70bd63395b367cd1ece67798ce5e502"
        version = "1.0"
        date = "2021-12-13"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "15e7942ebf88a51346d3a5975bb1c2d87996799e6255db9e92aed798d279b36b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 85 3C 93 48 1F 03 36 84 C0 4B 28 7F 18 86 13 08 10 1F EC B0 73 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_d74d7f0c {
    meta:
        id = "5a1YD9FUdz1NCKG3zdYrkI"
        fingerprint = "v1_sha256_6f5313fc9e838bd06bd4e797ea7fb448073849dc714ecf18809f94900fa11ca2"
        version = "1.0"
        date = "2021-12-13"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "b0a8b2259c00d563aa387d7e1a1f1527405da19bf4741053f5822071699795e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 20 79 6F 2C 0A 59 6A 02 5B 6A 04 58 CD 80 B3 7F 6A 01 58 CD }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_71d31510 {
    meta:
        id = "17XLCZQzdIrouVMS1yK5Ad"
        fingerprint = "v1_sha256_18bfe9347faf1811686a61e0ee0de5cef842beb25fb06793947309135c41de89"
        version = "1.0"
        date = "2021-12-13"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "33dd6c0af99455a0ca3908c0117e16a513b39fabbf9c52ba24c7b09226ad8626"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 5C B3 C0 19 17 5E 7B 8B 22 16 17 E0 DE 6E 21 46 FB DD 17 67 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_97288af8 {
    meta:
        id = "vvVgoLAP4DLzHR9RF6FbW"
        fingerprint = "v1_sha256_c5b521cc887236a189dca419476758cee0f1513a8ad81c94b1ff42e4fe232b8e"
        version = "1.0"
        date = "2021-12-13"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "c39eb055c5f71ebfd6881ff04e876f49495c0be5560687586fc47bf5faee0c84"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 61 6E 64 65 6D 6F 20 73 68 69 72 61 6E 61 69 20 77 61 20 79 6F 2C }
    condition:
        all of them
}

