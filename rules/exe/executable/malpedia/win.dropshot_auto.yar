rule win_dropshot_auto {

    meta:
        atk_type = "win.dropshot."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.dropshot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dropshot"
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
        $sequence_0 = { e8???????? 83c40c 6a04 6800100000 6804010000 6a00 ff15???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a04                 | push                4
            //   6800100000           | push                0x1000
            //   6804010000           | push                0x104
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_1 = { ff15???????? 5d c3 3b0d???????? f27502 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     
            //   f27502               | bnd jne             5

        $sequence_2 = { 6a64 ff15???????? 6800800000 6a00 }
            // n = 4, score = 200
            //   6a64                 | push                0x64
            //   ff15????????         |                     
            //   6800800000           | push                0x8000
            //   6a00                 | push                0

        $sequence_3 = { 6a05 ff15???????? ff15???????? 6a00 }
            // n = 4, score = 200
            //   6a05                 | push                5
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   6a00                 | push                0

        $sequence_4 = { eb05 e8???????? 68e8030000 ff15???????? }
            // n = 4, score = 200
            //   eb05                 | jmp                 7
            //   e8????????           |                     
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     

        $sequence_5 = { ff15???????? 6a04 6800100000 6808020000 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   6a04                 | push                4
            //   6800100000           | push                0x1000
            //   6808020000           | push                0x208

        $sequence_6 = { ff15???????? 6a00 ff15???????? 6a00 ff15???????? 6a05 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a05                 | push                5

        $sequence_7 = { 6a00 6a00 68???????? 6a00 ff15???????? b801000000 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   b801000000           | mov                 eax, 1

    condition:
        7 of them and filesize < 483328
}