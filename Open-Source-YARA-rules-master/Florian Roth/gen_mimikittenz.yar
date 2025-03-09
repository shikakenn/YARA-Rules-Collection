/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-07-19
    Identifier: Mimikittenz
*/

/* Rule Set ----------------------------------------------------------------- */

rule Invoke_mimikittenz {
    meta:
        id = "27Add5T2AAtzUX8TSIYYOq"
        fingerprint = "v1_sha256_f0410a0290d09d3574854b55ffe578f6f799368e14677b581cd65d18700a8656"
        version = "1.0"
        score = 90
        date = "2016-07-19"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Mimikittenz - file Invoke-mimikittenz.ps1"
        category = "INFO"
        reference = "https://github.com/putterpanda/mimikittenz"
        hash1 = "14e2f70470396a18c27debb419a4f4063c2ad5b6976f429d47f55e31066a5e6a"

    strings:
        $x1 = "[mimikittenz.MemProcInspector]" ascii

        $s1 = "PROCESS_ALL_ACCESS = PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION |" fullword ascii
        $s2 = "IntPtr processHandle = MInterop.OpenProcess(MInterop.PROCESS_WM_READ | MInterop.PROCESS_QUERY_INFORMATION, false, process.Id);" fullword ascii
        $s3 = "&email=.{1,48}&create=.{1,2}&password=.{1,22}&metadata1=" ascii
        $s4 = "[DllImport(\"kernel32.dll\", SetLastError = true)]" fullword ascii
    condition:
        ( uint16(0) == 0x7566 and filesize < 60KB and 2 of them ) or $x1
}
