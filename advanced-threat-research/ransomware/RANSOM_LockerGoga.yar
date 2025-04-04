rule LockerGogaRansomware {
   
    meta:
        id = "3eZf1bREJ36YLv79NtO4uO"
        fingerprint = "v1_sha256_165fa0fa044b2e0d2344626c2064162f23e13dc17310a772b703dbbe9457bd99"
        version = "1.0"
        date = "2019-03-20"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Christiaan Beek - McAfee ATR team"
        description = "LockerGoga Ransomware"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        hash = "ba15c27f26265f4b063b65654e9d7c248d0d651919fafb68cb4765d1e057f93f"
        rule_version = "v1"
        malware_family = "Ransom:W32/LockerGoga"
        actor_group = "Unknown"

   strings:

      $1 = "boost::interprocess::spin_recursive_mutex recursive lock overflow" fullword ascii
      $2 = ".?AU?$error_info_injector@Usync_queue_is_closed@concurrent@boost@@@exception_detail@boost@@" fullword ascii
      $3 = ".?AV?$CipherModeFinalTemplate_CipherHolder@V?$BlockCipherFinal@$00VDec@RC6@CryptoPP@@@CryptoPP@@VCBC_Decryption@2@@CryptoPP@@" fullword ascii
      $4 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $5 = "cipher.exe" fullword ascii
      $6 = ".?AU?$placement_destroy@Utrace_queue@@@ipcdetail@interprocess@boost@@" fullword ascii
      $7 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $8 = "CreateProcess failed" fullword ascii
      $9 = "boost::dll::shared_library::load() failed" fullword ascii
      $op1 = { 8b df 83 cb 0f 81 fb ff ff ff 7f 76 07 bb ff ff }
      $op2 = { 8b df 83 cb 0f 81 fb ff ff ff 7f 76 07 bb ff ff }

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 2000KB and
      ( 6 of them ) and
      all of ($op*)) or
      ( all of them )
}
