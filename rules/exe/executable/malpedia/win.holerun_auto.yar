rule win_holerun_auto {

    meta:
        atk_type = "win.holerun."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.holerun."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.holerun"
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
        $sequence_0 = { 85c0 740c c785ec00000000000000 eb63 488b05???????? }
            // n = 5, score = 100
            //   85c0                 | mov                 ecx, edx
            //   740c                 | call                eax
            //   c785ec00000000000000     | jmp    0x2b2
            //   eb63                 | dec                 eax
            //   488b05????????       |                     

        $sequence_1 = { e8???????? 8b45c4 83f840 7472 8b45c4 83f804 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b45c4               | mov                 eax, eax
            //   83f840               | dec                 eax
            //   7472                 | add                 eax, edx
            //   8b45c4               | dec                 eax
            //   83f804               | mov                 dword ptr [ebx + 8], eax

        $sequence_2 = { c744242000010000 41b901000000 41b800000000 ba03000000 4889c1 }
            // n = 5, score = 100
            //   c744242000010000     | inc                 ecx
            //   41b901000000         | mov                 eax, 8
            //   41b800000000         | dec                 eax
            //   ba03000000           | mov                 edx, dword ptr [ebp + 0x10]
            //   4889c1               | dec                 eax

        $sequence_3 = { 488b85e0000000 488b4020 4889c1 488b05???????? ffd0 }
            // n = 5, score = 100
            //   488b85e0000000       | dec                 eax
            //   488b4020             | mov                 eax, dword ptr [ebp - 0x10]
            //   4889c1               | mov                 eax, dword ptr [eax]
            //   488b05????????       |                     
            //   ffd0                 | cmp                 eax, 0x4550

        $sequence_4 = { ffd0 488b85e0000000 488b4020 4889c1 488b05???????? }
            // n = 5, score = 100
            //   ffd0                 | dec                 eax
            //   488b85e0000000       | mov                 eax, dword ptr [ebp - 0x10]
            //   488b4020             | dec                 eax
            //   4889c1               | mov                 ecx, eax
            //   488b05????????       |                     

        $sequence_5 = { ffd0 8b85cc030000 4881c458040000 5b 5d c3 }
            // n = 6, score = 100
            //   ffd0                 | dec                 eax
            //   8b85cc030000         | mov                 eax, dword ptr [ebp - 0x18]
            //   4881c458040000       | mov                 eax, dword ptr [eax + 0xd0]
            //   5b                   | test                eax, eax
            //   5d                   | setne               al
            //   c3                   | mov                 eax, 0

        $sequence_6 = { 4883c00f 48c1e804 48c1e004 e8???????? 4829c4 }
            // n = 5, score = 100
            //   4883c00f             | mov                 eax, dword ptr [ebp + 0x10]
            //   48c1e804             | dec                 esp
            //   48c1e004             | lea                 eax, [eax + 0x28]
            //   e8????????           |                     
            //   4829c4               | dec                 eax

        $sequence_7 = { eb1e 8345f401 488345f828 488b45e8 0fb74006 0fb7c0 }
            // n = 6, score = 100
            //   eb1e                 | dec                 eax
            //   8345f401             | lea                 ecx, [0x336d]
            //   488345f828           | nop                 
            //   488b45e8             | mov                 eax, dword ptr [eax + 8]
            //   0fb74006             | dec                 ecx
            //   0fb7c0               | mov                 eax, ecx

        $sequence_8 = { c705????????00000000 c705????????00000000 8b45fc 8905???????? }
            // n = 4, score = 100
            //   c705????????00000000     |     
            //   c705????????00000000     |     
            //   8b45fc               | lea                 eax, [ebp + 0x70]
            //   8905????????         |                     

        $sequence_9 = { 488b4d10 e8???????? 4885c0 7507 b8ffffffff eb05 }
            // n = 6, score = 100
            //   488b4d10             | add                 eax, ecx
            //   e8????????           |                     
            //   4885c0               | dec                 eax
            //   7507                 | mov                 ecx, dword ptr [eax + 8]
            //   b8ffffffff           | dec                 eax
            //   eb05                 | mov                 eax, edx

    condition:
        7 of them and filesize < 156672
}