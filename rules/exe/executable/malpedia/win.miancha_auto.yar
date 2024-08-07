rule win_miancha_auto {

    meta:
        atk_type = "win.miancha."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.miancha."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miancha"
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
        $sequence_0 = { 7412 8d542418 52 ff15???????? }
            // n = 4, score = 200
            //   7412                 | je                  0x14
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_1 = { 6803000080 ff15???????? 85c0 741f 6a00 }
            // n = 5, score = 200
            //   6803000080           | push                0x80000003
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   741f                 | je                  0x21
            //   6a00                 | push                0

        $sequence_2 = { 8b15???????? 894808 8a0d???????? 89500c 884810 }
            // n = 5, score = 200
            //   8b15????????         |                     
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   8a0d????????         |                     
            //   89500c               | mov                 dword ptr [eax + 0xc], edx
            //   884810               | mov                 byte ptr [eax + 0x10], cl

        $sequence_3 = { 40 50 56 8b35???????? 6a02 6a00 }
            // n = 6, score = 200
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   56                   | push                esi
            //   8b35????????         |                     
            //   6a02                 | push                2
            //   6a00                 | push                0

        $sequence_4 = { 85f6 7412 8d542418 52 ff15???????? 50 }
            // n = 6, score = 200
            //   85f6                 | test                esi, esi
            //   7412                 | je                  0x14
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_5 = { ff15???????? 50 ffd6 85c0 741a }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   741a                 | je                  0x1c

        $sequence_6 = { 8d542418 52 ff15???????? 50 ffd6 85c0 }
            // n = 6, score = 200
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax

        $sequence_7 = { 50 68???????? e8???????? 33f6 83c408 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   33f6                 | xor                 esi, esi
            //   83c408               | add                 esp, 8

        $sequence_8 = { 8910 8b15???????? 894804 8b0d???????? 895008 8a15???????? }
            // n = 6, score = 200
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b15????????         |                     
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   8b0d????????         |                     
            //   895008               | mov                 dword ptr [eax + 8], edx
            //   8a15????????         |                     

        $sequence_9 = { 8910 8b15???????? 894804 8b0d???????? 895008 8a15???????? 89480c }
            // n = 7, score = 200
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b15????????         |                     
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   8b0d????????         |                     
            //   895008               | mov                 dword ptr [eax + 8], edx
            //   8a15????????         |                     
            //   89480c               | mov                 dword ptr [eax + 0xc], ecx

    condition:
        7 of them and filesize < 376832
}