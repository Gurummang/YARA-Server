rule win_firechili_auto {

    meta:
        atk_type = "win.firechili."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.firechili."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.firechili"
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
        $sequence_0 = { 7d11 48837c242000 7509 b201 33c9 e8???????? 33c0 }
            // n = 7, score = 100
            //   7d11                 | mov                 ecx, edi
            //   48837c242000         | test                al, al
            //   7509                 | je                  0x10f0
            //   b201                 | dec                 eax
            //   33c9                 | mov                 eax, dword ptr [edi + 0x10]
            //   e8????????           |                     
            //   33c0                 | mov                 word ptr [esi + 2], bp

        $sequence_1 = { 488b7c2458 488b6c2460 4885f6 744e }
            // n = 4, score = 100
            //   488b7c2458           | test                edx, edx
            //   488b6c2460           | jne                 0x2db
            //   4885f6               | mov                 eax, 0xc0000001
            //   744e                 | dec                 eax

        $sequence_2 = { 4533c0 4889742420 488d55f7 ff15???????? }
            // n = 4, score = 100
            //   4533c0               | inc                 ecx
            //   4889742420           | movzx               eax, word ptr [edx + 2]
            //   488d55f7             | dec                 eax
            //   ff15????????         |                     

        $sequence_3 = { c744242866730000 4533c0 33d2 48c744242008020000 ff15???????? c605????????01 488bd7 }
            // n = 7, score = 100
            //   c744242866730000     | cmp                 al, 2
            //   4533c0               | ja                  0x806
            //   33d2                 | je                  0x811
            //   48c744242008020000     | inc    esp
            //   ff15????????         |                     
            //   c605????????01       |                     
            //   488bd7               | mov                 edx, cr0

        $sequence_4 = { 488b7c2430 488b742438 4c8b6c2428 498b442408 }
            // n = 4, score = 100
            //   488b7c2430           | dec                 eax
            //   488b742438           | sub                 eax, 2
            //   4c8b6c2428           | inc                 ecx
            //   498b442408           | mov                 edx, 0x80000005

        $sequence_5 = { c3 4c8bdc 4d894318 49895310 53 56 4883ec68 }
            // n = 7, score = 100
            //   c3                   | js                  0x52e
            //   4c8bdc               | inc                 ebp
            //   4d894318             | xor                 ecx, ecx
            //   49895310             | dec                 eax
            //   53                   | lea                 edx, [esp + 0x40]
            //   56                   | inc                 ebp
            //   4883ec68             | movzx               eax, bh

        $sequence_6 = { 418bc6 81c200040000 4a393400 740c ffc1 48ffc0 483bc2 }
            // n = 7, score = 100
            //   418bc6               | pop                 ebx
            //   81c200040000         | ret                 
            //   4a393400             | dec                 esp
            //   740c                 | mov                 dword ptr [esp + 0x60], esi
            //   ffc1                 | dec                 eax
            //   48ffc0               | add                 esp, 0x30
            //   483bc2               | pop                 ebx

        $sequence_7 = { 4889742458 418d5020 48897c2460 ff15???????? 8bf8 85c0 784b }
            // n = 7, score = 100
            //   4889742458           | mov                 dword ptr [ebp - 0x29], edx
            //   418d5020             | dec                 eax
            //   48897c2460           | mov                 dword ptr [ebp - 0x21], ecx
            //   ff15????????         |                     
            //   8bf8                 | dec                 eax
            //   85c0                 | mov                 dword ptr [ebp - 9], edx
            //   784b                 | dec                 eax

        $sequence_8 = { 4c8bc1 488bc1 6690 66833800 }
            // n = 4, score = 100
            //   4c8bc1               | inc                 esp
            //   488bc1               | mov                 eax, dword ptr [eax + 0x14]
            //   6690                 | inc                 ecx
            //   66833800             | cmp                 eax, 0x840766b7

        $sequence_9 = { 488d05ff500000 c605????????01 488905???????? 488905???????? 4883c420 }
            // n = 5, score = 100
            //   488d05ff500000       | xor                 edi, edi
            //   c605????????01       |                     
            //   488905????????       |                     
            //   488905????????       |                     
            //   4883c420             | je                  0x679

    condition:
        7 of them and filesize < 91136
}