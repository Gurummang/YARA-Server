rule win_havoc_auto {

    meta:
        atk_type = "win.havoc."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.havoc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.havoc"
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
        $sequence_0 = { 85c0 7856 488b842488000000 488bb42488000000 4531c9 }
            // n = 5, score = 800
            //   85c0                 | dec                 eax
            //   7856                 | mov                 dword ptr [esp + 0x28], eax
            //   488b842488000000     | mov                 eax, 0x10
            //   488bb42488000000     | dec                 eax
            //   4531c9               | mov                 dword ptr [esp + 0x20], edi

        $sequence_1 = { 48898424ae000000 4c8d442458 ba2a040000 8b842498000000 4889442448 }
            // n = 5, score = 800
            //   48898424ae000000     | call                dword ptr [eax + 0x15c]
            //   4c8d442458           | mov                 ecx, 0x40
            //   ba2a040000           | dec                 eax
            //   8b842498000000       | mov                 dword ptr [esp + 0x70], eax
            //   4889442448           | dec                 ecx

        $sequence_2 = { 4488440101 448a440202 4488440102 448a440203 4488440103 4883c004 4883f820 }
            // n = 7, score = 800
            //   4488440101           | mov                 dword ptr [esp + 0x38], ebx
            //   448a440202           | xor                 eax, eax
            //   4488440102           | mov                 dword ptr [esp + 0x40], esi
            //   448a440203           | xor                 edi, edi
            //   4488440103           | mov                 ecx, 0xadd31df0
            //   4883c004             | dec                 eax
            //   4883f820             | mov                 dword ptr [esp + 0x38], ebx

        $sequence_3 = { 4885c0 7504 31f6 eb08 488b4030 ffc3 }
            // n = 6, score = 800
            //   4885c0               | dec                 eax
            //   7504                 | mov                 edx, dword ptr [ebx]
            //   31f6                 | dec                 eax
            //   eb08                 | mov                 dword ptr [edx + 0x55c], eax
            //   488b4030             | dec                 eax
            //   ffc3                 | mov                 ecx, dword ptr [edx + 0x644]

        $sequence_4 = { 55 4c89c5 57 56 4889d6 53 }
            // n = 6, score = 800
            //   55                   | dec                 eax
            //   4c89c5               | mov                 edx, dword ptr [ebx]
            //   57                   | dec                 eax
            //   56                   | mov                 dword ptr [edx + 0x30c], eax
            //   4889d6               | dec                 eax
            //   53                   | mov                 eax, dword ptr [ebx]

        $sequence_5 = { 4883ec28 488b410c 488b4904 488d5008 488b05???????? }
            // n = 5, score = 800
            //   4883ec28             | je                  0x164a
            //   488b410c             | dec                 eax
            //   488b4904             | mov                 eax, dword ptr [esi]
            //   488d5008             | dec                 eax
            //   488b05????????       |                     

        $sequence_6 = { 488d4b10 4c8d4c2460 4889442460 8b442478 ba00000002 4c8d842490000000 }
            // n = 6, score = 800
            //   488d4b10             | mov                 eax, dword ptr [ebx]
            //   4c8d4c2460           | call                dword ptr [eax + 0x45c]
            //   4889442460           | dec                 eax
            //   8b442478             | mov                 ecx, esi
            //   ba00000002           | mov                 dword ptr [esp + 0x2c], eax
            //   4c8d842490000000     | dec                 eax

        $sequence_7 = { f3a5 488bbc2480000000 488b742460 b934010000 f3a5 }
            // n = 5, score = 800
            //   f3a5                 | dec                 esp
            //   488bbc2480000000     | mov                 ecx, ebp
            //   488b742460           | dec                 eax
            //   b934010000           | lea                 ecx, [esp + 0x98]
            //   f3a5                 | dec                 eax

        $sequence_8 = { baff010f00 c744244001000000 4889442444 31c0 85f6 }
            // n = 5, score = 800
            //   baff010f00           | inc                 ecx
            //   c744244001000000     | mov                 eax, 0x2ce5a244
            //   4889442444           | dec                 eax
            //   31c0                 | mov                 dword ptr [edx + 0x5cc], eax
            //   85f6                 | dec                 eax

        $sequence_9 = { 4155 4154 4531e4 55 57 56 53 }
            // n = 7, score = 800
            //   4155                 | mov                 dword ptr [edx + 0x484], eax
            //   4154                 | dec                 eax
            //   4531e4               | test                ecx, ecx
            //   55                   | je                  0x1746
            //   57                   | mov                 edx, 0xbb6970d6
            //   56                   | dec                 eax
            //   53                   | mov                 edx, dword ptr [ebx]

    condition:
        7 of them and filesize < 164864
}