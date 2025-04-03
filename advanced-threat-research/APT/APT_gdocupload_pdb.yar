rule apt_gdocupload_glooxmail {

    meta:
        id = "2lgxoNSwv592GolQ7zZ7Ij"
        fingerprint = "v1_sha256_e016bb636af22fae79875bebaf1b4bd4f2a403e797d7ee52ea0691b4d7a54cf8"
        version = "1.0"
        date = "2013-02-19"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect gdocupload tool used by APT1"
        category = "MALWARE"
        malware_type = "BACKDOOR"
        actor_type = "CRIMEWARE"
        reference = "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
        hash = "295c5c7aa5fa29628dec9f42ed657fce0bc789079c4e51932bcbc99a28dfd440"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Gdocupload"
        actor_group = "Unknown"

   strings:

      $s1 = "https://www.google.com/accounts/ServiceLogin?service=writely&passive=1209600&continue=http://docs.google.com/&followup=http://do" ascii
      $s2 = "Referer: http://sn114w.snt114.mail.live.com/mail/AttachmentUploader.aspx?_ec=1" fullword ascii
      $s3 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET " ascii
      $s4 = "e:\\Project\\mm\\Webmail\\Bin\\gdocs.pdb" fullword ascii
      $s5 = "http://docs.google.com/?auth=" fullword ascii
      $s6 = "x-guploader-client-info: mechanism=scotty flash; clientVersion=18067216" fullword ascii
      $s7 = "http://docs.google.com/" fullword ascii
      $s8 = "Referer: http://sn114w.snt114.mail.live.com/mail/EditMessageLight.aspx?n=%s" fullword ascii
   
   condition:

      uint16(0) == 0x5a4d and 
      filesize < 300KB and 
      all of them
}
