rule rietspoof_loader {
   
    meta:
        id = "7M8hVD8o8UcPCScxxFdLAJ"
        fingerprint = "v1_sha256_d72b58ff452070e03d0b25bc433ef5c677df77dd440adc1ecdb592cee24235fb"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the Rietspoof loader"
        category = "INFO"
        reference = "https://blog.avast.com/rietspoof-malware-increases-activity"
        rule_version = "v1"
        malware_family = "Loader:W32/Rietspoof"
        actor_group = "Unknown"

   strings:

      $x1 = "\\Work\\d2Od7s43\\techloader\\loader" fullword ascii
    
   condition:

      uint16(0) == 0x5a4d and
      all of them
}
