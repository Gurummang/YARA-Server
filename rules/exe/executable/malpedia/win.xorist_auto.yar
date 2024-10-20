rule win_xorist_auto {

    meta:
        atk_type = "win.xorist."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.xorist."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xorist"
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
        $sequence_0 = { ff15???????? 8bcf ffd6 be00080000 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8bcf                 | mov                 ecx, edi
            //   ffd6                 | call                esi
            //   be00080000           | mov                 esi, 0x800

        $sequence_1 = { ff15???????? 50 68???????? 8d858ceeffff }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   8d858ceeffff         | lea                 eax, [ebp - 0x1174]

        $sequence_2 = { 8d4b24 50 896c2428 e8???????? }
            // n = 4, score = 100
            //   8d4b24               | lea                 ecx, [ebx + 0x24]
            //   50                   | push                eax
            //   896c2428             | mov                 dword ptr [esp + 0x28], ebp
            //   e8????????           |                     

        $sequence_3 = { 84c0 7522 6a02 b9???????? }
            // n = 4, score = 100
            //   84c0                 | test                al, al
            //   7522                 | jne                 0x24
            //   6a02                 | push                2
            //   b9????????           |                     

        $sequence_4 = { 50 51 8b4e10 ff15???????? }
            // n = 4, score = 100
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   ff15????????         |                     

        $sequence_5 = { 8bd9 ff15???????? 8d7b1c 57 }
            // n = 4, score = 100
            //   8bd9                 | mov                 ebx, ecx
            //   ff15????????         |                     
            //   8d7b1c               | lea                 edi, [ebx + 0x1c]
            //   57                   | push                edi

        $sequence_6 = { 50 8b4e20 ff15???????? ff5620 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   8b4e20               | mov                 ecx, dword ptr [esi + 0x20]
            //   ff15????????         |                     
            //   ff5620               | call                dword ptr [esi + 0x20]

        $sequence_7 = { 8b450c 33c9 83e0f0 384d14 }
            // n = 4, score = 100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   33c9                 | xor                 ecx, ecx
            //   83e0f0               | and                 eax, 0xfffffff0
            //   384d14               | cmp                 byte ptr [ebp + 0x14], cl

    condition:
        7 of them and filesize < 1402880
}