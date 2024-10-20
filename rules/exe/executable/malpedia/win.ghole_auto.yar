rule win_ghole_auto {

    meta:
        atk_type = "win.ghole."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.ghole."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ghole"
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
        $sequence_0 = { 740d 8b55fc 48 8b45e8 89908c000000 48 8b55e0 }
            // n = 7, score = 100
            //   740d                 | je                  0xf
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   48                   | dec                 eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   89908c000000         | mov                 dword ptr [eax + 0x8c], edx
            //   48                   | dec                 eax
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]

        $sequence_1 = { 3b45ec 7591 48 8b05???????? 48 8b00 8b15???????? }
            // n = 7, score = 100
            //   3b45ec               | cmp                 eax, dword ptr [ebp - 0x14]
            //   7591                 | jne                 0xffffff93
            //   48                   | dec                 eax
            //   8b05????????         |                     
            //   48                   | dec                 eax
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b15????????         |                     

        $sequence_2 = { 89c7 e8???????? 85c0 0f85ac160000 8b850cfdffff 48 8d9518fdffff }
            // n = 7, score = 100
            //   89c7                 | mov                 edi, eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f85ac160000         | jne                 0x16b2
            //   8b850cfdffff         | mov                 eax, dword ptr [ebp - 0x2f4]
            //   48                   | dec                 eax
            //   8d9518fdffff         | lea                 edx, [ebp - 0x2e8]

        $sequence_3 = { 90 8b4dc8 8b55c4 48 8b5d98 48 8b4598 }
            // n = 7, score = 100
            //   90                   | nop                 
            //   8b4dc8               | mov                 ecx, dword ptr [ebp - 0x38]
            //   8b55c4               | mov                 edx, dword ptr [ebp - 0x3c]
            //   48                   | dec                 eax
            //   8b5d98               | mov                 ebx, dword ptr [ebp - 0x68]
            //   48                   | dec                 eax
            //   8b4598               | mov                 eax, dword ptr [ebp - 0x68]

        $sequence_4 = { 8910 48 8b45e8 48 83c018 48 8b55e8 }
            // n = 7, score = 100
            //   8910                 | mov                 dword ptr [eax], edx
            //   48                   | dec                 eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   48                   | dec                 eax
            //   83c018               | add                 eax, 0x18
            //   48                   | dec                 eax
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]

        $sequence_5 = { 85c0 7518 8b45e0 89c7 e8???????? 85c0 750a }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7518                 | jne                 0x1a
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   89c7                 | mov                 edi, eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc

        $sequence_6 = { 48 8b45e0 48 895010 48 8d55d4 48 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   48                   | dec                 eax
            //   895010               | mov                 dword ptr [eax + 0x10], edx
            //   48                   | dec                 eax
            //   8d55d4               | lea                 edx, [ebp - 0x2c]
            //   48                   | dec                 eax

        $sequence_7 = { 894c2408 48 83ec78 c744242050000000 c744242403000000 48 8d0540feffff }
            // n = 7, score = 100
            //   894c2408             | mov                 dword ptr [esp + 8], ecx
            //   48                   | dec                 eax
            //   83ec78               | sub                 esp, 0x78
            //   c744242050000000     | mov                 dword ptr [esp + 0x20], 0x50
            //   c744242403000000     | mov                 dword ptr [esp + 0x24], 3
            //   48                   | dec                 eax
            //   8d0540feffff         | lea                 eax, [0xfffffe40]

        $sequence_8 = { 4c 8945c0 c745ec00000000 8b05???????? 85c0 750a b800000000 }
            // n = 7, score = 100
            //   4c                   | dec                 esp
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax
            //   c745ec00000000       | mov                 dword ptr [ebp - 0x14], 0
            //   8b05????????         |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   b800000000           | mov                 eax, 0

        $sequence_9 = { 0f847d0f0000 48 8d95a0faffff 48 8d8520fdffff 48 89d6 }
            // n = 7, score = 100
            //   0f847d0f0000         | je                  0xf83
            //   48                   | dec                 eax
            //   8d95a0faffff         | lea                 edx, [ebp - 0x560]
            //   48                   | dec                 eax
            //   8d8520fdffff         | lea                 eax, [ebp - 0x2e0]
            //   48                   | dec                 eax
            //   89d6                 | mov                 esi, edx

    condition:
        7 of them and filesize < 622592
}