rule win_unidentified_070_auto {

    meta:
        atk_type = "win.unidentified_070."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_070."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_070"
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
        $sequence_0 = { 6a04 50 ff15???????? 8945fc 85c0 }
            // n = 5, score = 300
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   85c0                 | test                eax, eax

        $sequence_1 = { 6a00 6a00 6a04 50 ff15???????? 8945fc 85c0 }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   85c0                 | test                eax, eax

        $sequence_2 = { 33c0 c20400 3b0d???????? 7502 }
            // n = 4, score = 300
            //   33c0                 | xor                 eax, eax
            //   c20400               | ret                 4
            //   3b0d????????         |                     
            //   7502                 | jne                 4

        $sequence_3 = { 6a00 6a04 50 ff15???????? 8945fc }
            // n = 5, score = 300
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_4 = { 6a00 6a04 50 ff15???????? 8945fc 85c0 }
            // n = 6, score = 300
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   85c0                 | test                eax, eax

        $sequence_5 = { 6a00 6a00 6a00 6a04 50 ff15???????? 8945fc }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_6 = { 6a00 6a00 6a04 50 ff15???????? 8945fc }
            // n = 6, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_7 = { 6a00 8d45f4 50 ff75fc 57 56 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_8 = { 8bf9 c78424cc00000000000000 66c78424d00000000010 e8???????? 83c40c 8d442424 50 }
            // n = 7, score = 200
            //   8bf9                 | mov                 edi, ecx
            //   c78424cc00000000000000     | mov    dword ptr [esp + 0xcc], 0
            //   66c78424d00000000010     | mov    word ptr [esp + 0xd0], 0x1000
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   50                   | push                eax

        $sequence_9 = { 6a00 56 ff15???????? 8945f8 85c0 0f8493000000 6a00 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   85c0                 | test                eax, eax
            //   0f8493000000         | je                  0x99
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 90112
}