rule svg_basic_structure_with_xml
{
    meta:
        description = "Checks basic SVG file structure, including optional XML declaration."
        author = "your_name"
        date = "2024/08/06"
    strings:
        // XML declaration at the beginning
        $xml_decl = "<?xml "
        // SVG start tag
        $svg_start = "<svg "
        // SVG end tag
        $svg_end = "</svg>"
        // XML namespace attribute
        $xmlns = "xmlns="
        // SVG file signature
        $svg_header = "<?xml "  // Including "<?xml " part of the header
    condition:
        $svg_header at 0 and // Ensure it is an SVG file by checking the header
        (
            ($xml_decl in (0..1000) or $svg_start in (0..filesize)) and
            $svg_end in (filesize - 1000..filesize) and
            $xmlns in (0..filesize)
        )
}
