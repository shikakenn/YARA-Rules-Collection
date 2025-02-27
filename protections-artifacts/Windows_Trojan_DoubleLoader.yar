rule Windows_Trojan_DoubleLoader_3660c98a {
    meta:
        id = "129Gff8hrRITyhSKH0nJuW"
        fingerprint = "v1_sha256_5e4ad7044cf00c64910912a4381d32ff78765ff950136b924bbe47c8c9787bc9"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DoubleLoader"
        reference_sample = "d94f7224a065a09a9f0c116bcb021bae2e941e2cd544eb0a0b1d1a325ae87667"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "GetSettingsFromRegistry failed" ascii fullword
        $str2 = "Install persistence failed" ascii fullword
        $str3 = "Connect to remote port using Afd driver failed" ascii fullword
        $str4 = "/obfdownload/DoubleLoaderDll.dll" ascii fullword
        $str5 = "Invalid response status code for download file. not 200 OK" ascii fullword
        $str6 = "Failed to send HTTP/1.1 request to server for download file" ascii fullword
        $path = "D:\\projects\\DoubleLoader_net4\\DoubleLoader\\x64\\Release\\Loader.pdb" ascii fullword
        $path2 = "d:\\projects\\doubleloader_net4\\doubleloader\\cryptopp\\sha_simd.cpp" ascii fullword
        $path3 = "d:\\projects\\doubleloader_net4\\doubleloader\\cryptopp\\gf2n_simd.cpp" ascii fullword
    condition:
        4 of ($str*) or 1 of ($path*)
}

