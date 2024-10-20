rule win_neteagle_auto {

    meta:
        atk_type = "win.neteagle."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.neteagle."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.neteagle"
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
        $sequence_0 = { 8d4c2418 e8???????? 8d4c2418 e8???????? 8b84241c300000 89742410 3bc6 }
            // n = 7, score = 100
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   e8????????           |                     
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   e8????????           |                     
            //   8b84241c300000       | mov                 eax, dword ptr [esp + 0x301c]
            //   89742410             | mov                 dword ptr [esp + 0x10], esi
            //   3bc6                 | cmp                 eax, esi

        $sequence_1 = { 83c408 50 51 8d442428 }
            // n = 4, score = 100
            //   83c408               | add                 esp, 8
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8d442428             | lea                 eax, [esp + 0x28]

        $sequence_2 = { c68424240200000d 8bcc 8964242c 68???????? e8???????? }
            // n = 5, score = 100
            //   c68424240200000d     | mov                 byte ptr [esp + 0x224], 0xd
            //   8bcc                 | mov                 ecx, esp
            //   8964242c             | mov                 dword ptr [esp + 0x2c], esp
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_3 = { 6a00 6a00 57 56 6840800000 ff15???????? }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   57                   | push                edi
            //   56                   | push                esi
            //   6840800000           | push                0x8040
            //   ff15????????         |                     

        $sequence_4 = { c684241802000018 8bcc 89642424 8d542428 52 e8???????? 8d442420 }
            // n = 7, score = 100
            //   c684241802000018     | mov                 byte ptr [esp + 0x218], 0x18
            //   8bcc                 | mov                 ecx, esp
            //   89642424             | mov                 dword ptr [esp + 0x24], esp
            //   8d542428             | lea                 edx, [esp + 0x28]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8d442420             | lea                 eax, [esp + 0x20]

        $sequence_5 = { 8d4dec e8???????? 6800100000 8d4dec c645fc0d e8???????? 8b16 }
            // n = 7, score = 100
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   e8????????           |                     
            //   6800100000           | push                0x1000
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   c645fc0d             | mov                 byte ptr [ebp - 4], 0xd
            //   e8????????           |                     
            //   8b16                 | mov                 edx, dword ptr [esi]

        $sequence_6 = { 8d4c2428 c68424540c000006 e8???????? 8d542414 68???????? 8d442414 52 }
            // n = 7, score = 100
            //   8d4c2428             | lea                 ecx, [esp + 0x28]
            //   c68424540c000006     | mov                 byte ptr [esp + 0xc54], 6
            //   e8????????           |                     
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   68????????           |                     
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   52                   | push                edx

        $sequence_7 = { c684241002000004 e8???????? 8d4e34 c684241002000005 e8???????? 8d4e38 c684241002000006 }
            // n = 7, score = 100
            //   c684241002000004     | mov                 byte ptr [esp + 0x210], 4
            //   e8????????           |                     
            //   8d4e34               | lea                 ecx, [esi + 0x34]
            //   c684241002000005     | mov                 byte ptr [esp + 0x210], 5
            //   e8????????           |                     
            //   8d4e38               | lea                 ecx, [esi + 0x38]
            //   c684241002000006     | mov                 byte ptr [esp + 0x210], 6

        $sequence_8 = { 52 6a00 6a00 8b3d???????? ffd7 83f820 7f1b }
            // n = 7, score = 100
            //   52                   | push                edx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8b3d????????         |                     
            //   ffd7                 | call                edi
            //   83f820               | cmp                 eax, 0x20
            //   7f1b                 | jg                  0x1d

        $sequence_9 = { 888c0414010000 40 3bc6 7ced 8d942414010000 8d4c240c 52 }
            // n = 7, score = 100
            //   888c0414010000       | mov                 byte ptr [esp + eax + 0x114], cl
            //   40                   | inc                 eax
            //   3bc6                 | cmp                 eax, esi
            //   7ced                 | jl                  0xffffffef
            //   8d942414010000       | lea                 edx, [esp + 0x114]
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 262144
}