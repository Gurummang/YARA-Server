rule win_suppobox_auto {

    meta:
        atk_type = "win.suppobox."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.suppobox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.suppobox"
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
        $sequence_0 = { 7d10 a1???????? 0b05???????? a3???????? }
            // n = 4, score = 200
            //   7d10                 | jge                 0x12
            //   a1????????           |                     
            //   0b05????????         |                     
            //   a3????????           |                     

        $sequence_1 = { 7f10 a1???????? 2305???????? a3???????? }
            // n = 4, score = 200
            //   7f10                 | jg                  0x12
            //   a1????????           |                     
            //   2305????????         |                     
            //   a3????????           |                     

        $sequence_2 = { 8945f0 a1???????? 83e801 a3???????? }
            // n = 4, score = 200
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   a1????????           |                     
            //   83e801               | sub                 eax, 1
            //   a3????????           |                     

        $sequence_3 = { 7e10 a1???????? 0305???????? a3???????? }
            // n = 4, score = 200
            //   7e10                 | jle                 0x12
            //   a1????????           |                     
            //   0305????????         |                     
            //   a3????????           |                     

        $sequence_4 = { 890d???????? e8???????? 8bf0 e8???????? 03f0 }
            // n = 5, score = 200
            //   890d????????         |                     
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   03f0                 | add                 esi, eax

        $sequence_5 = { 7d10 a1???????? 3305???????? a3???????? }
            // n = 4, score = 200
            //   7d10                 | jge                 0x12
            //   a1????????           |                     
            //   3305????????         |                     
            //   a3????????           |                     

        $sequence_6 = { 3bc8 7d10 a1???????? 2b05???????? a3???????? }
            // n = 5, score = 200
            //   3bc8                 | cmp                 ecx, eax
            //   7d10                 | jge                 0x12
            //   a1????????           |                     
            //   2b05????????         |                     
            //   a3????????           |                     

        $sequence_7 = { 01bdacf7ffff 83c40c 83bdc8f7ffff00 8b95c8f7ffff }
            // n = 4, score = 100
            //   01bdacf7ffff         | add                 dword ptr [ebp - 0x854], edi
            //   83c40c               | add                 esp, 0xc
            //   83bdc8f7ffff00       | cmp                 dword ptr [ebp - 0x838], 0
            //   8b95c8f7ffff         | mov                 edx, dword ptr [ebp - 0x838]

        $sequence_8 = { 8d45f3 83ec04 890424 e8???????? }
            // n = 4, score = 100
            //   8d45f3               | lea                 eax, [ebp - 0xd]
            //   83ec04               | sub                 esp, 4
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     

        $sequence_9 = { 8d45f3 890424 e8???????? 52 ebc5 }
            // n = 5, score = 100
            //   8d45f3               | lea                 eax, [ebp - 0xd]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   52                   | push                edx
            //   ebc5                 | jmp                 0xffffffc7

        $sequence_10 = { 8d45f4 89442408 e9???????? 8b4508 }
            // n = 4, score = 100
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   e9????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_11 = { 01c6 39fe 0f8d7e010000 80bc2ef4f7ffff0a }
            // n = 4, score = 100
            //   01c6                 | add                 esi, eax
            //   39fe                 | cmp                 esi, edi
            //   0f8d7e010000         | jge                 0x184
            //   80bc2ef4f7ffff0a     | cmp                 byte ptr [esi + ebp - 0x80c], 0xa

        $sequence_12 = { 8d45f2 89f1 89442404 c70424???????? }
            // n = 4, score = 100
            //   8d45f2               | lea                 eax, [ebp - 0xe]
            //   89f1                 | mov                 ecx, esi
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   c70424????????       |                     

        $sequence_13 = { 01d8 3b85b0f7ffff 7e2f 8b95c8f7ffff }
            // n = 4, score = 100
            //   01d8                 | add                 eax, ebx
            //   3b85b0f7ffff         | cmp                 eax, dword ptr [ebp - 0x850]
            //   7e2f                 | jle                 0x31
            //   8b95c8f7ffff         | mov                 edx, dword ptr [ebp - 0x838]

        $sequence_14 = { 8d45f2 89442404 8b4508 890424 e8???????? 83ec08 }
            // n = 6, score = 100
            //   8d45f2               | lea                 eax, [ebp - 0xe]
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   83ec08               | sub                 esp, 8

        $sequence_15 = { 8d45ef 89d9 890424 e8???????? 51 }
            // n = 5, score = 100
            //   8d45ef               | lea                 eax, [ebp - 0x11]
            //   89d9                 | mov                 ecx, ebx
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   51                   | push                ecx

        $sequence_16 = { 01d7 68???????? 57 e8???????? }
            // n = 4, score = 100
            //   01d7                 | add                 edi, edx
            //   68????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_17 = { 01c6 ebdb ff7510 57 }
            // n = 4, score = 100
            //   01c6                 | add                 esi, eax
            //   ebdb                 | jmp                 0xffffffdd
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   57                   | push                edi

        $sequence_18 = { 01c9 4a 79f2 833b54 }
            // n = 4, score = 100
            //   01c9                 | add                 ecx, ecx
            //   4a                   | dec                 edx
            //   79f2                 | jns                 0xfffffff4
            //   833b54               | cmp                 dword ptr [ebx], 0x54

        $sequence_19 = { 8d45f4 89442408 c744240401000000 893424 }
            // n = 4, score = 100
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   c744240401000000     | mov                 dword ptr [esp + 4], 1
            //   893424               | mov                 dword ptr [esp], esi

        $sequence_20 = { 01c6 39fe 0f8d2f020000 80bc2ef4f7ffff0a }
            // n = 4, score = 100
            //   01c6                 | add                 esi, eax
            //   39fe                 | cmp                 esi, edi
            //   0f8d2f020000         | jge                 0x235
            //   80bc2ef4f7ffff0a     | cmp                 byte ptr [esi + ebp - 0x80c], 0xa

        $sequence_21 = { 019dacf7ffff 83c40c 299dc4f7ffff e9???????? }
            // n = 4, score = 100
            //   019dacf7ffff         | add                 dword ptr [ebp - 0x854], ebx
            //   83c40c               | add                 esp, 0xc
            //   299dc4f7ffff         | sub                 dword ptr [ebp - 0x83c], ebx
            //   e9????????           |                     

    condition:
        7 of them and filesize < 1875968
}