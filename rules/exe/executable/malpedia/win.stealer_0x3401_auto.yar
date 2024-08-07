rule win_stealer_0x3401_auto {

    meta:
        atk_type = "win.stealer_0x3401."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.stealer_0x3401."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealer_0x3401"
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
        $sequence_0 = { 03f2 8bd6 85f6 7e37 8d8d5cfeffff e8???????? }
            // n = 6, score = 100
            //   03f2                 | add                 esi, edx
            //   8bd6                 | mov                 edx, esi
            //   85f6                 | test                esi, esi
            //   7e37                 | jle                 0x39
            //   8d8d5cfeffff         | lea                 ecx, [ebp - 0x1a4]
            //   e8????????           |                     

        $sequence_1 = { 53 e8???????? 83c41c c74424280f000000 c744242400000000 c644241400 803b00 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   c74424280f000000     | mov                 dword ptr [esp + 0x28], 0xf
            //   c744242400000000     | mov                 dword ptr [esp + 0x24], 0
            //   c644241400           | mov                 byte ptr [esp + 0x14], 0
            //   803b00               | cmp                 byte ptr [ebx], 0

        $sequence_2 = { 5f 894df0 8b34cd50fa0110 8b4d08 6a5a 2bce }
            // n = 6, score = 100
            //   5f                   | pop                 edi
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   8b34cd50fa0110       | mov                 esi, dword ptr [ecx*8 + 0x1001fa50]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   6a5a                 | push                0x5a
            //   2bce                 | sub                 ecx, esi

        $sequence_3 = { 83781410 7202 8b00 ffb57cfdffff }
            // n = 4, score = 100
            //   83781410             | cmp                 dword ptr [eax + 0x14], 0x10
            //   7202                 | jb                  4
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ffb57cfdffff         | push                dword ptr [ebp - 0x284]

        $sequence_4 = { c745fc05000000 8d8d5cffffff e8???????? c645fc06 83781410 7202 }
            // n = 6, score = 100
            //   c745fc05000000       | mov                 dword ptr [ebp - 4], 5
            //   8d8d5cffffff         | lea                 ecx, [ebp - 0xa4]
            //   e8????????           |                     
            //   c645fc06             | mov                 byte ptr [ebp - 4], 6
            //   83781410             | cmp                 dword ptr [eax + 0x14], 0x10
            //   7202                 | jb                  4

        $sequence_5 = { 8b8db87dffff 40 3d00100000 722a f6c11f }
            // n = 5, score = 100
            //   8b8db87dffff         | mov                 ecx, dword ptr [ebp - 0x8248]
            //   40                   | inc                 eax
            //   3d00100000           | cmp                 eax, 0x1000
            //   722a                 | jb                  0x2c
            //   f6c11f               | test                cl, 0x1f

        $sequence_6 = { 64a300000000 8b35???????? 8d8574ffffff 50 6a00 }
            // n = 5, score = 100
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b35????????         |                     
            //   8d8574ffffff         | lea                 eax, [ebp - 0x8c]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_7 = { 8d8598feffff 3bc3 7435 8bc8 e8???????? }
            // n = 5, score = 100
            //   8d8598feffff         | lea                 eax, [ebp - 0x168]
            //   3bc3                 | cmp                 eax, ebx
            //   7435                 | je                  0x37
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     

        $sequence_8 = { 8d4c2434 e8???????? 53 e8???????? 83c404 8d44242c 8bcf }
            // n = 7, score = 100
            //   8d4c2434             | lea                 ecx, [esp + 0x34]
            //   e8????????           |                     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d44242c             | lea                 eax, [esp + 0x2c]
            //   8bcf                 | mov                 ecx, edi

        $sequence_9 = { ffb5843fffff ffd7 83bd803fffff00 0f84ec000000 6a12 68???????? b9???????? }
            // n = 7, score = 100
            //   ffb5843fffff         | push                dword ptr [ebp - 0xc07c]
            //   ffd7                 | call                edi
            //   83bd803fffff00       | cmp                 dword ptr [ebp - 0xc080], 0
            //   0f84ec000000         | je                  0xf2
            //   6a12                 | push                0x12
            //   68????????           |                     
            //   b9????????           |                     

    condition:
        7 of them and filesize < 357376
}