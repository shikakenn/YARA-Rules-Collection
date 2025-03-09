rule BernhardPOS {
    meta:
        id = "3UeL6e4gz645f60T7PD5zx"
        fingerprint = "v1_sha256_c00f2fda5a391b44767d918945069f18cef084dd4dc6aa94d8f945bf97ac462a"
        version = "1.0"
        score = 70
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MORPHICK INC."
        author = "Nick Hoffman / Jeremy Humble"
        description = "BernhardPOS Credit Card dumping tool"
        category = "INFO"
        reference = "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick"
        last_update = "2015-07-14"
        md5 = "e49820ef02ba5308ff84e4c8c12e7c3d"

     strings:
          $shellcode_kernel32_with_junk_code = { 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }
          $mutex_name = "OPSEC_BERNHARD" 
          $build_path = "C:\\bernhard\\Debug\\bernhard.pdb" 
          $string_decode_routine = { 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }
     condition:
          any of them
 }
