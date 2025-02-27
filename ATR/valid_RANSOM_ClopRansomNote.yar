rule clop_ransom_note {

    meta:
        id = "4OOuINHzf4f70ue7ELBm3g"
        fingerprint = "v1_sha256_a90862e9dc59b1a8f38b777b4f529d5de740d0f49175813cae64f10ca9677826"
        version = "1.0"
        date = "2019-08-01"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Clop Ransomware Note"
        category = "INFO"
        reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/clop-ransomware/"
        rule_version = "v1"
        malware_family = "Ransom:W32/Clop"
        actor_group = "Unknown"

   strings:

      $s1 = "If you want to restore your files write to emails" fullword ascii
      $s2 = "All files on each host in the network have been encrypted with a strong algorithm." fullword ascii
      $s3 = "Shadow copies also removed, so F8 or any other methods may damage encrypted data but not recover." fullword ascii
      $s4 = "You will receive decrypted samples and our conditions how to get the decoder." fullword ascii
      $s5 = "DO NOT RENAME OR MOVE the encrypted and readme files." fullword ascii
      $s6 = "(Less than 6 Mb each, non-archived and your files should not contain valuable information" fullword ascii
      $s7 = "We exclusively have decryption software for your situation" fullword ascii
      $s8 = "Do not rename encrypted files." fullword ascii
      $s9 = "DO NOT DELETE readme files." fullword ascii
      $s10 = "Nothing personal just business" fullword ascii
      $s11 = "eqaltech.su" fullword ascii

   condition:

      ( uint16(0) == 0x6f59) and 
      filesize < 10KB and
      all of them
}
