rule Windows_RemoteAdmin_UltraVNC_965f054a {
    meta:
        id = "2Fz2ZAjGsXCu3L5LJLlnH"
        fingerprint = "v1_sha256_a9b9d0958f09b23fa7b27ef7ec32b3feb98edca3be5a21552a3a2f50e3fd41c1"
        version = "1.0"
        date = "2023-03-18"
        modified = "2023-04-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.RemoteAdmin.UltraVNC"
        reference_sample = "59bddb5ccdc1c37c838c8a3d96a865a28c75b5807415fd931eaff0af931d1820"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = ".\\vncsockconnect.cpp"
        $s2 = ".\\vnchttpconnect.cpp"
        $s3 = ".\\vncdesktopthread.cpp"
        $s4 = "Software\\UltraVNC"
        $s5 = "VncCanvas.class"
        $s6 = "WinVNC_Win32_Instance_Mutex"
        $s7 = "WinVNC.AddClient"
    condition:
        5 of them
}

