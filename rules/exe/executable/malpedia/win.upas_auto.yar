rule win_upas_auto {

    meta:
        atk_type = "win.upas."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.upas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.upas"
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
        $sequence_0 = { 6a00 8d45f8 50 8d45f0 50 ff15???????? }
            // n = 6, score = 400
            //   6a00                 | push                0
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_1 = { ffd6 33c0 eb18 6a00 57 }
            // n = 5, score = 400
            //   ffd6                 | call                esi
            //   33c0                 | xor                 eax, eax
            //   eb18                 | jmp                 0x1a
            //   6a00                 | push                0
            //   57                   | push                edi

        $sequence_2 = { ff751c e8???????? ff7620 ff763c e8???????? 8b4d10 8bd8 }
            // n = 7, score = 400
            //   ff751c               | push                dword ptr [ebp + 0x1c]
            //   e8????????           |                     
            //   ff7620               | push                dword ptr [esi + 0x20]
            //   ff763c               | push                dword ptr [esi + 0x3c]
            //   e8????????           |                     
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8bd8                 | mov                 ebx, eax

        $sequence_3 = { ff15???????? 8945fc 3bc7 7504 33c0 eb64 56 }
            // n = 7, score = 400
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   3bc7                 | cmp                 eax, edi
            //   7504                 | jne                 6
            //   33c0                 | xor                 eax, eax
            //   eb64                 | jmp                 0x66
            //   56                   | push                esi

        $sequence_4 = { 50 53 ff15???????? 8945f4 3bc3 7504 }
            // n = 6, score = 400
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   3bc3                 | cmp                 eax, ebx
            //   7504                 | jne                 6

        $sequence_5 = { 83c420 53 6880000000 6a02 53 53 68000000c0 }
            // n = 7, score = 400
            //   83c420               | add                 esp, 0x20
            //   53                   | push                ebx
            //   6880000000           | push                0x80
            //   6a02                 | push                2
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   68000000c0           | push                0xc0000000

        $sequence_6 = { 8944b5dc 837cb5dc00 59 59 7406 46 83fe07 }
            // n = 7, score = 400
            //   8944b5dc             | mov                 dword ptr [ebp + esi*4 - 0x24], eax
            //   837cb5dc00           | cmp                 dword ptr [ebp + esi*4 - 0x24], 0
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   7406                 | je                  8
            //   46                   | inc                 esi
            //   83fe07               | cmp                 esi, 7

        $sequence_7 = { ff15???????? ff75e8 8d4598 6a22 50 e8???????? }
            // n = 6, score = 400
            //   ff15????????         |                     
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   8d4598               | lea                 eax, [ebp - 0x68]
            //   6a22                 | push                0x22
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_8 = { 72d1 5e c3 8b442410 8b08 3b0d???????? }
            // n = 6, score = 400
            //   72d1                 | jb                  0xffffffd3
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   3b0d????????         |                     

        $sequence_9 = { ff15???????? 85c0 742d 8d8500fdffff 50 }
            // n = 5, score = 400
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   742d                 | je                  0x2f
            //   8d8500fdffff         | lea                 eax, [ebp - 0x300]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 114688
}