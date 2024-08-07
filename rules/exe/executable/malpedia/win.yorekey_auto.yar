rule win_yorekey_auto {

    meta:
        atk_type = "win.yorekey."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.yorekey."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yorekey"
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
        $sequence_0 = { 750a 85c0 7506 ff15???????? }
            // n = 4, score = 200
            //   750a                 | jne                 0xc
            //   85c0                 | test                eax, eax
            //   7506                 | jne                 8
            //   ff15????????         |                     

        $sequence_1 = { 4883ec20 33ff 488d1dc9fa0000 488b0b ff15???????? }
            // n = 5, score = 100
            //   4883ec20             | lea                 ecx, [edi + 4]
            //   33ff                 | dec                 eax
            //   488d1dc9fa0000       | mov                 dword ptr [esp + 0x28], eax
            //   488b0b               | dec                 esp
            //   ff15????????         |                     

        $sequence_2 = { 33c9 ff15???????? 488bd8 ff15???????? 3db7000000 7509 }
            // n = 6, score = 100
            //   33c9                 | test                eax, eax
            //   ff15????????         |                     
            //   488bd8               | jae                 0xf
            //   ff15????????         |                     
            //   3db7000000           | dec                 eax
            //   7509                 | mov                 edx, ebx

        $sequence_3 = { 8bc6 83f801 7521 a1???????? 50 ff15???????? 68???????? }
            // n = 7, score = 100
            //   8bc6                 | test                edi, edi
            //   83f801               | dec                 eax
            //   7521                 | sub                 esp, 0x20
            //   a1????????           |                     
            //   50                   | xor                 edi, edi
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_4 = { 03048de0404100 eb02 8bc2 f6402480 0f8571ffffff 33f6 3bfe }
            // n = 7, score = 100
            //   03048de0404100       | lea                 ecx, [esp + 0x30]
            //   eb02                 | dec                 eax
            //   8bc2                 | lea                 edx, [esp + 0x38]
            //   f6402480             | inc                 esp
            //   0f8571ffffff         | mov                 eax, ebx
            //   33f6                 | dec                 eax
            //   3bfe                 | mov                 dword ptr [esp + 0x20], 0

        $sequence_5 = { 4803d1 488d0d02090100 442bc6 488b0cc1 498b0c0c ff15???????? 85c0 }
            // n = 7, score = 100
            //   4803d1               | dec                 eax
            //   488d0d02090100       | add                 edx, ecx
            //   442bc6               | dec                 eax
            //   488b0cc1             | lea                 ecx, [0x10902]
            //   498b0c0c             | inc                 esp
            //   ff15????????         |                     
            //   85c0                 | sub                 eax, esi

        $sequence_6 = { 7530 a1???????? ba???????? 50 e9???????? a1???????? }
            // n = 6, score = 100
            //   7530                 | dec                 eax
            //   a1????????           |                     
            //   ba????????           |                     
            //   50                   | lea                 ebx, [0xfac9]
            //   e9????????           |                     
            //   a1????????           |                     

        $sequence_7 = { 488bce e8???????? 488d154c040100 4c63c8 418d4902 }
            // n = 5, score = 100
            //   488bce               | lea                 eax, [0xfffffacb]
            //   e8????????           |                     
            //   488d154c040100       | je                  7
            //   4c63c8               | inc                 cx
            //   418d4902             | mov                 dword ptr [ebp], ecx

        $sequence_8 = { 730d 488bd3 488bcf e8???????? eb1c }
            // n = 5, score = 100
            //   730d                 | dec                 eax
            //   488bd3               | mov                 ecx, dword ptr [ecx + eax*8]
            //   488bcf               | dec                 ecx
            //   e8????????           |                     
            //   eb1c                 | mov                 ecx, dword ptr [esp + ecx]

        $sequence_9 = { 751b 6a02 33c9 51 }
            // n = 4, score = 100
            //   751b                 | mov                 dword ptr [ebp - 0x90], eax
            //   6a02                 | mov                 dword ptr [ebp - 0x94], eax
            //   33c9                 | lea                 eax, [ebp - 0x68]
            //   51                   | mov                 ecx, 0x19

        $sequence_10 = { 7405 6641894d00 4885f6 7457 483bf7 7252 4d85ff }
            // n = 7, score = 100
            //   7405                 | dec                 eax
            //   6641894d00           | mov                 ebx, eax
            //   4885f6               | cmp                 eax, 0xb7
            //   7457                 | jne                 0xb
            //   483bf7               | dec                 eax
            //   7252                 | lea                 eax, [esp + 0x3c]
            //   4d85ff               | inc                 esp

        $sequence_11 = { 898570ffffff 89856cffffff 8d4598 b919000000 }
            // n = 4, score = 100
            //   898570ffffff         | dec                 eax
            //   89856cffffff         | mov                 ecx, dword ptr [ebx]
            //   8d4598               | dec                 eax
            //   b919000000           | mov                 ecx, esi

        $sequence_12 = { ff15???????? 488d44243c 448d4f04 4889442428 4c8d05cbfaffff }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   488d44243c           | dec                 eax
            //   448d4f04             | mov                 ecx, edi
            //   4889442428           | jmp                 0x26
            //   4c8d05cbfaffff       | xor                 ecx, ecx

        $sequence_13 = { 5a 8985c4fbffff 3bc2 0f8451ffffff 83f807 0f87110a0000 ff2485b19b4000 }
            // n = 7, score = 100
            //   5a                   | jne                 0xc
            //   8985c4fbffff         | test                eax, eax
            //   3bc2                 | jne                 0xa
            //   0f8451ffffff         | mov                 eax, esi
            //   83f807               | cmp                 eax, 1
            //   0f87110a0000         | jne                 0x26
            //   ff2485b19b4000       | push                eax

        $sequence_14 = { 55 8bec 51 8bc2 56 8d7002 8d9b00000000 }
            // n = 7, score = 100
            //   55                   | dec                 eax
            //   8bec                 | lea                 edx, [0x1044c]
            //   51                   | dec                 esp
            //   8bc2                 | arpl                ax, cx
            //   56                   | inc                 ecx
            //   8d7002               | lea                 ecx, [ecx + 2]
            //   8d9b00000000         | dec                 esp

    condition:
        7 of them and filesize < 274432
}