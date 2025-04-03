rule shimrat {
    meta:
        id = "5ZlHvEDmY0lt5SSxMhozVA"
        fingerprint = "v1_sha256_0dd19e6a65b06bd5846ec224f01c3feea066540317223d1991154b2305882b20"
        version = "1.0"
        date = "20/11/2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yonathan Klijnsma (yonathan.klijnsma@fox-it.com)"
        description = "Detects ShimRat and the ShimRat loader"
        category = "INFO"

   strings:
      $dll = ".dll"
      $dat = ".dat"
      $headersig = "QWERTYUIOPLKJHG"
      $datasig = "MNBVCXZLKJHGFDS"
      $datamarker1 = "Data$$00"
      $datamarker2 = "Data$$01%c%sData"
      $cmdlineformat = "ping localhost -n 9 /c %s > nul"
      $demoproject_keyword1 = "Demo"
      $demoproject_keyword2 = "Win32App"
      $comspec = "COMSPEC"
      $shim_func1 = "ShimMain"
      $shim_func2 = "NotifyShims"
      $shim_func3 = "GetHookAPIs"
   condition:
      ($dll and $dat and $headersig and $datasig) or
      ($datamarker1 and $datamarker2) or
      ($cmdlineformat and $demoproject_keyword1 and $demoproject_keyword2 and $comspec) or
      ($dll and $dat and $shim_func1 and $shim_func2 and $shim_func3)
}

rule shimratreporter {
    meta:
        id = "5OV54UuZ9SyPHm65kCwSq"
        fingerprint = "v1_sha256_931d65628e5f0b7c63fe270b0a6cd3890f41a4ee7e253ce056b37f2d55542258"
        version = "1.0"
        date = "20/11/2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Yonathan Klijnsma (yonathan.klijnsma@fox-it.com)"
        description = "Detects ShimRatReporter"
        category = "INFO"

   strings:
      $IpInfo = "IP-INFO"
      $NetworkInfo = "Network-INFO"
      $OsInfo = "OS-INFO"
      $ProcessInfo = "Process-INFO"
      $BrowserInfo = "Browser-INFO"
      $QueryUserInfo = "QueryUser-INFO"
      $UsersInfo = "Users-INFO"
      $SoftwareInfo = "Software-INFO"
      $AddressFormat = "%02X-%02X-%02X-%02X-%02X-%02X"
      $proxy_str = "(from environment) = %s"
      $netuserfun = "NetUserEnum"
      $networkparams = "GetNetworkParams"
   condition:
      all of them
}
