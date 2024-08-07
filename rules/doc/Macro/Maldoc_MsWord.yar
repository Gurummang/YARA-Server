rule Detect_DOC_VBA_Macro
{
    meta:
        description = "Detects VBA Macros in DOC files"
        author = "Your Name"
        date = "2024-06-25"
        atk_type = "Macro"

    strings:
        $ole_header = {D0 CF 11 E0 A1 B1 1A E1}
        $vba_macro = {57 00 6F 00 72 00 64 00 56 00 42 00 41}

    condition:
        $ole_header at 0 and $vba_macro
}

rule Detect_DOCX_Embedded_Objects
{
    meta:
        description = "Detects embedded objects in DOCX files"
        author = "Your Name"
        date = "2024-06-25"

    strings:
        $zip_header = {50 4B 03 04}
        $object_path = /word\/embeddings\//

    condition:
        $zip_header at 0 and $object_path
}

rule Detect_DOCX_External_Links
{
    meta:
      atk_type = "Macro"
        description = "Detects external links in DOCX files"
        author = "Your Name"
        date = "2024-06-25"

    strings:
        $zip_header = {50 4B 03 04}
        $external_link = /externalLink/

    condition:
        $zip_header at 0 and $external_link
}



