rule MacOS_Backdoor_Kagent_64ca1865 {
    meta:
        id = "2fJPA3anrOtKdrGomzE84s"
        fingerprint = "v1_sha256_dea0a1bbe8c3065b395de50b5ffc2fbdf479ed35ce284fa33298d6ed55e960c6"
        version = "1.0"
        date = "2021-11-11"
        modified = "2022-07-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Backdoor.Kagent"
        reference_sample = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $s1 = "save saveCaptureInfo"
        $s2 = "savephoto success screenCaptureInfo"
        $s3 = "no auto bbbbbaaend:%d path %s"
        $s4 = "../screencapture/screen_capture_thread.cpp"
        $s5 = "%s:%d, m_autoScreenCaptureQueue: %x"
        $s6 = "auto bbbbbaaend:%d path %s"
        $s7 = "auto aaaaaaaastartTime:%d path %s"
    condition:
        4 of them
}

