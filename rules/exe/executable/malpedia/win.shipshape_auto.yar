rule win_shipshape_auto {

    meta:
        atk_type = "win.shipshape."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.shipshape."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shipshape"
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
        $sequence_0 = { 68???????? 68???????? 8d942440020000 68???????? 52 }
            // n = 5, score = 100
            //   68????????           |                     
            //   68????????           |                     
            //   8d942440020000       | lea                 edx, [esp + 0x240]
            //   68????????           |                     
            //   52                   | push                edx

        $sequence_1 = { 83e103 50 f3a4 ffd3 e9???????? 56 e8???????? }
            // n = 7, score = 100
            //   83e103               | and                 ecx, 3
            //   50                   | push                eax
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   ffd3                 | call                ebx
            //   e9????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_2 = { 68???????? 8d942440020000 68???????? 52 e8???????? 83c434 }
            // n = 6, score = 100
            //   68????????           |                     
            //   8d942440020000       | lea                 edx, [esp + 0x240]
            //   68????????           |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c434               | add                 esp, 0x34

        $sequence_3 = { c1f905 8b0c8d60d54000 f644c10401 8d04c1 7403 8b00 }
            // n = 6, score = 100
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d60d54000       | mov                 ecx, dword ptr [ecx*4 + 0x40d560]
            //   f644c10401           | test                byte ptr [ecx + eax*8 + 4], 1
            //   8d04c1               | lea                 eax, [ecx + eax*8]
            //   7403                 | je                  5
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_4 = { 8d542438 8d842400070000 52 50 }
            // n = 4, score = 100
            //   8d542438             | lea                 edx, [esp + 0x38]
            //   8d842400070000       | lea                 eax, [esp + 0x700]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_5 = { 8d84244c040000 68???????? 50 e8???????? 8d8c2454040000 51 }
            // n = 6, score = 100
            //   8d84244c040000       | lea                 eax, [esp + 0x44c]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8c2454040000       | lea                 ecx, [esp + 0x454]
            //   51                   | push                ecx

        $sequence_6 = { 8d4c2414 50 51 6a00 6a00 6a00 }
            // n = 6, score = 100
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_7 = { 5b 81c440060000 c3 56 57 }
            // n = 5, score = 100
            //   5b                   | pop                 ebx
            //   81c440060000         | add                 esp, 0x640
            //   c3                   | ret                 
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_8 = { 50 51 ffd3 5f 5e 33c0 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ffd3                 | call                ebx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { 83c418 3bc6 7e0f 5f 5e }
            // n = 5, score = 100
            //   83c418               | add                 esp, 0x18
            //   3bc6                 | cmp                 eax, esi
            //   7e0f                 | jle                 0x11
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 338386
}