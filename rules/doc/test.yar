rule Detect_JS_in_PDF
{
    meta:
        description = "Detects presence of JavaScript in PDF files"
        author = "Assistant"
        date = "2023-08-02"
        version = "1.0"

    strings:
        $pdf = "%PDF-"
        $js_comment = "/JavaScript"
        $js_script = "/JS"
        $open_action = "/OpenAction"
        $aa = "/AA"
        $launch = "/Launch"
        $jscode1 = "eval("
        $jscode2 = "unescape("
        $jscode3 = "this.getField("

    condition:
        $pdf at 0 and 2 of ($js_comment, $js_script, $open_action, $aa, $launch) and 1 of ($jscode*)
}