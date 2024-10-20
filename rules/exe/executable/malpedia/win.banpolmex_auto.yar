rule win_banpolmex_auto {

    meta:
        atk_type = "win.banpolmex."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.banpolmex."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.banpolmex"
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
        $sequence_0 = { 7419 4c8b0f 8bd0 41b801000000 498bcc e8???????? 4883f801 }
            // n = 7, score = 100
            //   7419                 | add                 esp, edx
            //   4c8b0f               | dec                 ebx
            //   8bd0                 | mov                 eax, dword ptr [eax + edi*8 + 0xad080]
            //   41b801000000         | js                  0xec0
            //   498bcc               | jae                 0xeba
            //   e8????????           |                     
            //   4883f801             | dec                 eax

        $sequence_1 = { ff15???????? 488d1530980800 488bcb 488905???????? ff15???????? 488d1529980800 488bcb }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488d1530980800       | lea                 eax, [esi - 0x7d]
            //   488bcb               | dec                 eax
            //   488905????????       |                     
            //   ff15????????         |                     
            //   488d1529980800       | mov                 edx, dword ptr [ebx + 0x10]
            //   488bcb               | dec                 eax

        $sequence_2 = { c3 488d15ea560200 488bcf e8???????? b80a000000 488b5c2460 4883c420 }
            // n = 7, score = 100
            //   c3                   | inc                 ebp
            //   488d15ea560200       | xor                 ecx, dword ptr [edi + ecx*4 + 0x800]
            //   488bcf               | inc                 ecx
            //   e8????????           |                     
            //   b80a000000           | movzx               ecx, al
            //   488b5c2460           | inc                 ebp
            //   4883c420             | xor                 ecx, dword ptr [edi + eax*4 + 0xc00]

        $sequence_3 = { 0f97c0 890d???????? 4883c428 c3 8b0d???????? 44891d???????? 3bc1 }
            // n = 7, score = 100
            //   0f97c0               | cmovne              ecx, ebp
            //   890d????????         |                     
            //   4883c428             | dec                 eax
            //   c3                   | mov                 dword ptr [esp + 0x58], ecx
            //   8b0d????????         |                     
            //   44891d????????       |                     
            //   3bc1                 | dec                 eax

        $sequence_4 = { 448d4201 4d8bb4c5a8010000 488bcb e8???????? 85c0 7919 488d156ca70100 }
            // n = 7, score = 100
            //   448d4201             | lea                 eax, [esp + 0x250]
            //   4d8bb4c5a8010000     | mov                 edx, 0x2716
            //   488bcb               | dec                 eax
            //   e8????????           |                     
            //   85c0                 | mov                 ecx, ebx
            //   7919                 | inc                 esp
            //   488d156ca70100       | mov                 eax, esi

        $sequence_5 = { 4d016810 4d016018 49017020 49017828 49015830 4d015838 4d015040 }
            // n = 7, score = 100
            //   4d016810             | dec                 eax
            //   4d016018             | mov                 ecx, ebp
            //   49017020             | jmp                 0xf78
            //   49017828             | dec                 eax
            //   49015830             | lea                 edx, [0x321cb]
            //   4d015838             | jmp                 0xf78
            //   4d015040             | dec                 eax

        $sequence_6 = { 660f1f440000 483bd5 7733 488bca 4869c988000000 4903c9 428b44210c }
            // n = 7, score = 100
            //   660f1f440000         | jne                 0x1df8
            //   483bd5               | dec                 esp
            //   7733                 | lea                 ecx, [esp + 0x440]
            //   488bca               | dec                 esp
            //   4869c988000000       | lea                 eax, [0x838d7]
            //   4903c9               | mov                 edi, eax
            //   428b44210c           | dec                 eax

        $sequence_7 = { 4883ec28 488b0d???????? 4885c9 7409 83caff ff15???????? 33c0 }
            // n = 7, score = 100
            //   4883ec28             | je                  0x1c75
            //   488b0d????????       |                     
            //   4885c9               | dec                 esp
            //   7409                 | mov                 ecx, ecx
            //   83caff               | dec                 eax
            //   ff15????????         |                     
            //   33c0                 | mov                 dword ptr [esp + 0x58], ecx

        $sequence_8 = { 4c8b5c2420 488b442428 4c011b 480107 0fb7442438 66ffc0 6689442438 }
            // n = 7, score = 100
            //   4c8b5c2420           | test                eax, eax
            //   488b442428           | jne                 0x1f35
            //   4c011b               | inc                 ecx
            //   480107               | mov                 edi, edi
            //   0fb7442438           | jmp                 0x1f35
            //   66ffc0               | inc                 ecx
            //   6689442438           | cmp                 ebp, 0x24

        $sequence_9 = { 4c897c2458 3c02 0f85a4000000 41b803000000 4533ff 898c24a8000000 44898424b0000000 }
            // n = 7, score = 100
            //   4c897c2458           | js                  0x1597
            //   3c02                 | dec                 eax
            //   0f85a4000000         | lea                 ecx, [esi + 0x30]
            //   41b803000000         | inc                 esp
            //   4533ff               | mov                 ecx, ebp
            //   898c24a8000000       | dec                 esp
            //   44898424b0000000     | mov                 eax, ebx

    condition:
        7 of them and filesize < 1555456
}