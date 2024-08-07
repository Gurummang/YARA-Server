rule Detect_XLS_Macro
{
    meta:
        description = "Detects macros in XLS files"
        author = "Your Name"
        date = "2024-06-25"
        atk_type = "Exploit"

    strings:
        $ole_header = {D0 CF 11 E0 A1 B1 1A E1}
        $macro = {4D 61 63 72 6F 73}

    condition:
        $ole_header at 0 and $macro
}

rule Detect_XLSX_External_Connections
{
    meta:
        description = "Detects external connections in XLSX files"
        author = "Your Name"
        date = "2024-06-25"
        atk_type = "Exploit"

    strings:
        $zip_header = {50 4B 03 04}
        $external_connection = /externalConnection/

    condition:
        $zip_header at 0 and $external_connection
}

rule Detect_XLSX_Hidden_Sheets
{
    meta:
        atk_type = "Macro"
        description = "Detects hidden sheets in XLSX files"
        author = "Your Name"
        date = "2024-06-25"

    strings:
        $zip_header = {50 4B 03 04}
        $hidden_sheet = /state="hidden"/

    condition:
        $zip_header at 0 and $hidden_sheet
}



