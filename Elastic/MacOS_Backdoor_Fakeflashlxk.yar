rule MacOS_Backdoor_Fakeflashlxk_06fd8071 {
    meta:
        id = "2UdGuxKdFhbOYCWKnZ0DNX"
        fingerprint = "v1_sha256_853d44465a472786bb48bbe1009e0ff925f79e4fd72f0eac537dd271c1ec3703"
        version = "1.0"
        date = "2021-11-11"
        modified = "2022-07-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Backdoor.Fakeflashlxk"
        reference_sample = "107f844f19e638866d8249e6f735daf650168a48a322d39e39d5e36cfc1c8659"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $s1 = "/Users/lxk/Library/Developer/Xcode/DerivedData"
        $s2 = "Desktop/SafariFlashActivity/SafariFlashActivity/SafariFlashActivity/"
        $s3 = "/Debug/SafariFlashActivity.build/Objects-normal/x86_64/AppDelegate.o"
    condition:
        2 of them
}

