rule CreateMiniDump
{
    meta:
        atk_type = "CreateMiniDump"
        id = "kMNDXhwJQURe8ehDOueqk"
        fingerprint = "b391a564b4730559271e11de0b80dce1562a9038c230a2be729a896913c7f6b5"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies CreateMiniDump, tool to dump LSASS."
        category = "HACKTOOL"
        tool = "CREATEMINIDUMP"
        reference = "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass"


    strings:
        $ = "[+] Got lsass.exe PID:" ascii wide
        $ = "[+] lsass dumped successfully!" ascii wide
        $ = { 40 55 57 4? 81 ec e8 04 00 00 4? 8d ?? ?4 40 4? 8b fc b9 3a 01 00 00 b8 cc cc cc cc f3 ab 4? 
  8b 05 ?? ?? ?? ?? 4? 33 c5 4? 89 8? ?? ?? ?? ?? c7 4? ?? 00 00 00 00 4? c7 4? ?? 00 00 00 00 4? 
  c7 44 ?? ?? 00 00 00 00 c7 44 ?? ?? 80 00 00 00 c7 44 ?? ?? 02 00 00 00 45 33 c9 45 33 c0 ba 00 
  00 00 10 4? 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4? 89 4? ?? 33 d2 b9 02 00 00 00 e8 ?? ?? ?? ?? 
  4? 89 4? ?? 4? 8d ?? 90 00 00 00 4? 8b f8 33 c0 b9 38 02 00 00 f3 aa c7 8? ?? ?? ?? ?? 38 02 00
  00 4? 8d 05 ?? ?? ?? ?? 4? 89 ?? ?? ?? ?? ?? 4? 8d ?? 90 00 00 00 4? 8b 4? ?? e8 ?? ?? ?? ?? 85 
  c0 74 ?? 4? 8d 15 ?? ?? ?? ?? 4? 8b ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 74 ?? 4? 8d ?? 90 00 
  00 00 4? 8b 4? ?? e8 ?? ?? ?? ?? 4? 8d ?? bc 00 00 00 4? 89 8? ?? ?? ?? ?? 8b 8? ?? ?? ?? ?? 89 4? ?? }

    condition:
        any of them
}