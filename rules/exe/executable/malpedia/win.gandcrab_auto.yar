rule win_gandcrab_auto {

    meta:
        atk_type = "win.gandcrab."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.gandcrab."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gandcrab"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { ff15???????? ff7728 8bf0 ff15???????? 03c3 8d5e04 }
            // n = 6, score = 2100
            //   ff15????????         |                     
            //   ff7728               | push                dword ptr [edi + 0x28]
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   03c3                 | add                 eax, ebx
            //   8d5e04               | lea                 ebx, [esi + 4]

        $sequence_1 = { 7403 83c314 837f7400 741b ff777c ff15???????? ff7778 }
            // n = 7, score = 2100
            //   7403                 | je                  5
            //   83c314               | add                 ebx, 0x14
            //   837f7400             | cmp                 dword ptr [edi + 0x74], 0
            //   741b                 | je                  0x1d
            //   ff777c               | push                dword ptr [edi + 0x7c]
            //   ff15????????         |                     
            //   ff7778               | push                dword ptr [edi + 0x78]

        $sequence_2 = { 8d5e04 03d8 837f2400 741b ff772c }
            // n = 5, score = 2100
            //   8d5e04               | lea                 ebx, [esi + 4]
            //   03d8                 | add                 ebx, eax
            //   837f2400             | cmp                 dword ptr [edi + 0x24], 0
            //   741b                 | je                  0x1d
            //   ff772c               | push                dword ptr [edi + 0x2c]

        $sequence_3 = { ff774c 8bf0 ff15???????? 03c3 8d5e04 03d8 }
            // n = 6, score = 2100
            //   ff774c               | push                dword ptr [edi + 0x4c]
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   03c3                 | add                 eax, ebx
            //   8d5e04               | lea                 ebx, [esi + 4]
            //   03d8                 | add                 ebx, eax

        $sequence_4 = { 03c3 8d5e04 03d8 837f5400 741b }
            // n = 5, score = 2100
            //   03c3                 | add                 eax, ebx
            //   8d5e04               | lea                 ebx, [esi + 4]
            //   03d8                 | add                 ebx, eax
            //   837f5400             | cmp                 dword ptr [edi + 0x54], 0
            //   741b                 | je                  0x1d

        $sequence_5 = { 03c3 8d5e04 03d8 837f3000 741b }
            // n = 5, score = 2100
            //   03c3                 | add                 eax, ebx
            //   8d5e04               | lea                 ebx, [esi + 4]
            //   03d8                 | add                 ebx, eax
            //   837f3000             | cmp                 dword ptr [edi + 0x30], 0
            //   741b                 | je                  0x1d

        $sequence_6 = { ff774c 8bf0 ff15???????? 03c3 8d5e04 }
            // n = 5, score = 2100
            //   ff774c               | push                dword ptr [edi + 0x4c]
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   03c3                 | add                 eax, ebx
            //   8d5e04               | lea                 ebx, [esi + 4]

        $sequence_7 = { 837f1800 741b ff7720 ff15???????? }
            // n = 4, score = 2100
            //   837f1800             | cmp                 dword ptr [edi + 0x18], 0
            //   741b                 | je                  0x1d
            //   ff7720               | push                dword ptr [edi + 0x20]
            //   ff15????????         |                     

        $sequence_8 = { 03d8 837f6000 7403 83c314 837f7400 741b ff777c }
            // n = 7, score = 2100
            //   03d8                 | add                 ebx, eax
            //   837f6000             | cmp                 dword ptr [edi + 0x60], 0
            //   7403                 | je                  5
            //   83c314               | add                 ebx, 0x14
            //   837f7400             | cmp                 dword ptr [edi + 0x74], 0
            //   741b                 | je                  0x1d
            //   ff777c               | push                dword ptr [edi + 0x7c]

        $sequence_9 = { ff15???????? 03c3 8d5e04 03d8 837f3000 }
            // n = 5, score = 2100
            //   ff15????????         |                     
            //   03c3                 | add                 eax, ebx
            //   8d5e04               | lea                 ebx, [esi + 4]
            //   03d8                 | add                 ebx, eax
            //   837f3000             | cmp                 dword ptr [edi + 0x30], 0

    condition:
        7 of them and filesize < 1024000
}