rule leverage_a
{
    meta:
        id = "4GUNtcO109hiTvDTz8UPt6"
        fingerprint = "v1_sha256_7ab5c9180433ef3ff7488f79731c21770e77008d9e9ae29b247dc0bdc6e7d022"
        version = "1.0"
        date = "2013/09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "earada@alienvault.com"
        description = "OSX/Leverage.A"
        category = "INFO"

    strings:
        $a1 = "ioreg -l | grep \"IOPlatformSerialNumber\" | awk -F"
        $a2 = "+:Users:Shared:UserEvent.app:Contents:MacOS:"
        $a3 = "rm '/Users/Shared/UserEvent.app/Contents/Resources/UserEvent.icns'"
        $script1 = "osascript -e 'tell application \"System Events\" to get the hidden of every login item'"
        $script2 = "osascript -e 'tell application \"System Events\" to get the name of every login item'"
        $script3 = "osascript -e 'tell application \"System Events\" to get the path of every login item'"
        $properties = "serverVisible \x00"
    condition:
        all of them
}
