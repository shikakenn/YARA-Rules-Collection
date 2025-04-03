import "pe"
import "hash"

rule ransom_egregor {

    meta:
        id = "6FiRm0LSla8vBeWMnap7dQ"
        fingerprint = "v1_sha256_8077c656eed0b1633da54f8d017d4eff122f2f4e486c4e1af6f6434ea33c0675"
        version = "1.0"
        date = "2020-10-28"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Thomas Roccia | McAfee ATR team"
        description = "Detect Egregor ransomware"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        reference = "https://bazaar.abuse.ch/sample/004a2dc3ec7b98fa7fe6ae9c23a8b051ec30bcfcd2bc387c440c07ff5180fe9a/"
        hash = "5f9fcbdf7ad86583eb2bbcaa5741d88a"
        rule_version = "v1"
        malware_family = "Ransom/Egregor"
        actor_group = "egregor"

   strings:
      $p1 = "ewdk.pdb" fullword ascii
      $p2 = "testbuild.pdb" fullword ascii

      $s1 = "M:\\" nocase ascii
      $s2 = "1z1M9U9" fullword wide
      $s3 = "C:\\Logmein\\{888-8888-9999}\\Logmein.log" fullword wide

   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      hash.sha256(pe.rich_signature.clear_data) == "b030ed1a7ca222a0923a59f321be7e55b8d0fc24c1134df1ba775bcf0994c79c" or
      (pe.sections[4].name == ".gfids" and pe.sections[5].name == ".00cfg") and
      (any of ($p*) or 2 of ($s*))
}
