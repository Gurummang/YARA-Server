rule TweetablePolyglotImage
{
    meta:
        atk_type = "packer"
        description = "Detects polyglot files for PNG, JPG, SVG, WEBP, and GIF"
        author = "Manfred Kaiser, Adapted by OpenAI"
    strings:
        // PNG magic bytes
        $magic_png1 = { 89 50 4E 47 0D 0A 1A 0A }
        // JPG magic bytes
        $magic_jpg1 = { FF D8 FF E0 }
        // SVG magic bytes (XML header)
        $magic_svg1 = { 3C 3F 78 6D 6C 20 }
        // WEBP magic bytes
        $magic_webp1 = { 52 49 46 46 } // RIFF header for WEBP
        $magic_webp2 = { 57 45 42 50 } // WEBP specific signature
        // GIF magic bytes
        $magic_gif1 = { 47 49 46 38 37 61 }
        $magic_gif2 = { 47 49 46 38 39 61 }

        // ZIP magic bytes
        $magic_zip1 = { 50 4B 01 02 } // Local file header
        $magic_zip2 = { 50 4B 03 04 } // Central directory header
        $magic_zip3 = { 50 4B 05 06 } // End of central directory

    condition:
        // Check for PNG, JPG, SVG, WEBP, or GIF magic bytes in the file
        (
            (uint32be(0) == 0x89504E47 and $magic_png1) or
            (uint32be(0) == 0xFFD8FFE0 and $magic_jpg1) or
            (uint32be(0) == 0x3C3F786D and $magic_svg1) or
            (uint32be(0) == 0x52494646 and $magic_webp1 and $magic_webp2) or
            (uint32be(0) == 0x47494638 and $magic_gif1 and $magic_gif2)
        ) and
        // Check for ZIP signatures in the file
        ($magic_zip1 and $magic_zip2 and $magic_zip3)
}
