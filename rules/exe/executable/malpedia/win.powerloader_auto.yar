rule win_powerloader_auto {

    meta:
        atk_type = "win.powerloader."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.powerloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.powerloader"
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
        $sequence_0 = { e8???????? eb22 33c9 66666666660f1f840000000000 0fb6840c30010000 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   eb22                 | mov                 dword ptr [esp + 0x380], ebx
            //   33c9                 | nop                 word ptr [eax + eax]
            //   66666666660f1f840000000000     | dec    eax
            //   0fb6840c30010000     | lea                 ecx, [esp + 0x251]

        $sequence_1 = { 8bf2 32db e8???????? 3bc7 7349 }
            // n = 5, score = 300
            //   8bf2                 | lea                 edx, [ebp - 1]
            //   32db                 | dec                 esp
            //   e8????????           |                     
            //   3bc7                 | lea                 eax, [0x3fe6]
            //   7349                 | dec                 esp

        $sequence_2 = { e8???????? 0fb6d8 84c0 7514 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   0fb6d8               | je                  0x107
            //   84c0                 | mov                 bl, al
            //   7514                 | test                bl, bl

        $sequence_3 = { e8???????? 0fb6d8 84c0 7514 ff15???????? }
            // n = 5, score = 300
            //   e8????????           |                     
            //   0fb6d8               | dec                 eax
            //   84c0                 | lea                 eax, [esp + 0x20]
            //   7514                 | dec                 eax
            //   ff15????????         |                     

        $sequence_4 = { 33d2 c605????????00 e8???????? 0fb6c3 }
            // n = 4, score = 300
            //   33d2                 | dec                 eax
            //   c605????????00       |                     
            //   e8????????           |                     
            //   0fb6c3               | mov                 dword ptr [esp + 0x30], eax

        $sequence_5 = { 32db e8???????? 3bc7 7349 }
            // n = 4, score = 300
            //   32db                 | test                al, al
            //   e8????????           |                     
            //   3bc7                 | jne                 0x13
            //   7349                 | dec                 eax

        $sequence_6 = { e8???????? eb22 33c9 66666666660f1f840000000000 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   eb22                 | mov                 ebx, ecx
            //   33c9                 | dec                 eax
            //   66666666660f1f840000000000     | lea    edx, [0x2cc2]

        $sequence_7 = { e8???????? 8b7c2430 85ed 740d }
            // n = 4, score = 300
            //   e8????????           |                     
            //   8b7c2430             | movzx               eax, byte ptr [esp + 0x4d8]
            //   85ed                 | dec                 eax
            //   740d                 | mov                 edx, edi

        $sequence_8 = { ff15???????? 83f81f 7323 ff15???????? }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   83f81f               | lea                 ecx, [esp + 0x40]
            //   7323                 | dec                 eax
            //   ff15????????         |                     

        $sequence_9 = { ff15???????? 83f803 7405 83f802 7530 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   83f803               | je                  0xa3
            //   7405                 | pop                 edi
            //   83f802               | pop                 esi
            //   7530                 | pop                 ebx

    condition:
        7 of them and filesize < 155648
}