rule ransom_Linux_HelloKitty_0721 {
    meta:
        id = "2Khsy414BFFmbQ8xqK5fmn"
        fingerprint = "v1_sha256_77a3809df4c7c591a855aaecd702af62935952937bb81661aa7f68e64dcf4fb4"
        version = "1.0"
        date = "2021-07-19"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Christiaan @ ATR"
        description = "rule to detect Linux variant of the Hello Kitty Ransomware"
        category = "INFO"
        Rule_Version = "v1"
        malware_family = "Ransom:Linux/HelloKitty"
        hash1 = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
        hash2 = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"

   strings:
      $v1 = "esxcli vm process kill -t=force -w=%d" fullword ascii
      $v2 = "esxcli vm process kill -t=hard -w=%d" fullword ascii
      $v3 = "esxcli vm process kill -t=soft -w=%d" fullword ascii
      $v4 = "error encrypt: %s rename back:%s" fullword ascii
      $v5 = "esxcli vm process list" fullword ascii
      $v6 = "Total VM run on host:" fullword ascii
      $v7 = "error lock_exclusively:%s owner pid:%d" fullword ascii
      $v8 = "Error open %s in try_lock_exclusively" fullword ascii
      $v9 = "Mode:%d  Verbose:%d Daemon:%d AESNI:%d RDRAND:%d " fullword ascii
      $v10 = "pthread_cond_signal() error" fullword ascii
      $v11 = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>" fullword ascii

   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}
