rule win_ramdo_auto {

    meta:
        atk_type = "win.ramdo."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.ramdo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ramdo"
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
        $sequence_0 = { 6813299e13 6a00 6a00 e8???????? }
            // n = 4, score = 600
            //   6813299e13           | push                0x139e2913
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_1 = { ff55f8 8945fc 837dfcff 7411 }
            // n = 4, score = 600
            //   ff55f8               | call                dword ptr [ebp - 8]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   837dfcff             | cmp                 dword ptr [ebp - 4], -1
            //   7411                 | je                  0x13

        $sequence_2 = { 688fe57c18 6a03 6a00 e8???????? }
            // n = 4, score = 600
            //   688fe57c18           | push                0x187ce58f
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_3 = { 681186933f 6a03 6a00 e8???????? }
            // n = 4, score = 600
            //   681186933f           | push                0x3f938611
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_4 = { 68b20cdc96 6a03 6a00 e8???????? }
            // n = 4, score = 600
            //   68b20cdc96           | push                0x96dc0cb2
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_5 = { 6a00 6a00 ff95dcfeffff 8945fc }
            // n = 4, score = 600
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff95dcfeffff         | call                dword ptr [ebp - 0x124]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_6 = { e8???????? 3db7000000 7405 8b45fc }
            // n = 4, score = 600
            //   e8????????           |                     
            //   3db7000000           | cmp                 eax, 0xb7
            //   7405                 | je                  7
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_7 = { 681b313f7d 6a03 6a00 e8???????? }
            // n = 4, score = 600
            //   681b313f7d           | push                0x7d3f311b
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_8 = { 68e9b528b6 6a03 6a00 e8???????? }
            // n = 4, score = 600
            //   68e9b528b6           | push                0xb628b5e9
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_9 = { 68c29e34ea 6a03 6a00 e8???????? }
            // n = 4, score = 600
            //   68c29e34ea           | push                0xea349ec2
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   e8????????           |                     

    condition:
        7 of them and filesize < 548864
}