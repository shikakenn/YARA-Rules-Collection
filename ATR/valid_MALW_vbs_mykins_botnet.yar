rule vbs_mykins_botnet {

    meta:
        id = "5UO2OJNxSxwAYU1bUo0ruj"
        fingerprint = "v1_sha256_ee48a2961e40c6be96b007794f585547ef337a46ca003152f15470069e2d2580"
        version = "1.0"
        date = "2018-01-24"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the VBS files used in Mykins botnet"
        category = "INFO"
        reference = "https://blog.netlab.360.com/mykings-the-botnet-behind-multiple-active-spreading-botnets/"
        rule_version = "v1"
        malware_family = "Botnet:W32/MyKins"
        actor_group = "Unknown"

   strings:

      $s1 = "fso.DeleteFile(WScript.ScriptFullName)" fullword ascii
      $s2 = "Set ws = CreateObject(\"Wscript.Shell\")" fullword ascii
      $s3 = "Set fso = CreateObject(\"Scripting.Filesystemobject\")" fullword ascii
      $r = /Windows\\ime|web|inf|\\c[0-9].bat/

   condition:

      uint16(0) == 0x6553 and
      filesize < 1KB 
      and any of ($s*) and
      $r  
      
}
