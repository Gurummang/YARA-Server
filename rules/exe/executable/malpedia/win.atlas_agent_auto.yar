rule win_atlas_agent_auto {

    meta:
        atk_type = "win.atlas_agent."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.atlas_agent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atlas_agent"
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
        $sequence_0 = { 0fb60c0a 83e13c c1f902 03c1 }
            // n = 4, score = 200
            //   0fb60c0a             | movzx               ecx, byte ptr [edx + ecx]
            //   83e13c               | and                 ecx, 0x3c
            //   c1f902               | sar                 ecx, 2
            //   03c1                 | add                 eax, ecx

        $sequence_1 = { 8bc1 99 b903000000 f7f9 c1e002 }
            // n = 5, score = 200
            //   8bc1                 | mov                 eax, ecx
            //   99                   | cdq                 
            //   b903000000           | mov                 ecx, 3
            //   f7f9                 | idiv                ecx
            //   c1e002               | shl                 eax, 2

        $sequence_2 = { 4c8b8424c8000000 488b9424c0000000 488b8c2480000000 e8???????? 89442460 }
            // n = 5, score = 100
            //   4c8b8424c8000000     | dec                 esp
            //   488b9424c0000000     | mov                 eax, dword ptr [esp + 0xc8]
            //   488b8c2480000000     | dec                 eax
            //   e8????????           |                     
            //   89442460             | mov                 edx, dword ptr [esp + 0xc0]

        $sequence_3 = { 4c8b8424e0000000 488b9424d8000000 488b4c2468 e8???????? }
            // n = 4, score = 100
            //   4c8b8424e0000000     | dec                 esp
            //   488b9424d8000000     | mov                 eax, dword ptr [esp + 0xc8]
            //   488b4c2468           | dec                 eax
            //   e8????????           |                     

        $sequence_4 = { 89857cffffff c645fc06 83bd7cffffff00 7417 }
            // n = 4, score = 100
            //   89857cffffff         | mov                 dword ptr [ebp - 0x84], eax
            //   c645fc06             | mov                 byte ptr [ebp - 4], 6
            //   83bd7cffffff00       | cmp                 dword ptr [ebp - 0x84], 0
            //   7417                 | je                  0x19

        $sequence_5 = { 898584feffff 8b8584feffff 50 8d8dd4feffff }
            // n = 4, score = 100
            //   898584feffff         | mov                 dword ptr [ebp - 0x17c], eax
            //   8b8584feffff         | mov                 eax, dword ptr [ebp - 0x17c]
            //   50                   | push                eax
            //   8d8dd4feffff         | lea                 ecx, [ebp - 0x12c]

        $sequence_6 = { 898588f8ffff 8b9588f8ffff 899584f8ffff c645fc07 }
            // n = 4, score = 100
            //   898588f8ffff         | mov                 dword ptr [ebp - 0x778], eax
            //   8b9588f8ffff         | mov                 edx, dword ptr [ebp - 0x778]
            //   899584f8ffff         | mov                 dword ptr [ebp - 0x77c], edx
            //   c645fc07             | mov                 byte ptr [ebp - 4], 7

        $sequence_7 = { 4c8b8424f0000000 488b942488000000 488b8c24e0000000 e8???????? }
            // n = 4, score = 100
            //   4c8b8424f0000000     | mov                 edx, dword ptr [esp + 0xd8]
            //   488b942488000000     | dec                 eax
            //   488b8c24e0000000     | mov                 ecx, dword ptr [esp + 0x68]
            //   e8????????           |                     

        $sequence_8 = { 89857cffffff 83bd7cffffff1e 7302 eb05 }
            // n = 4, score = 100
            //   89857cffffff         | mov                 dword ptr [ebp - 0x84], eax
            //   83bd7cffffff1e       | cmp                 dword ptr [ebp - 0x84], 0x1e
            //   7302                 | jae                 4
            //   eb05                 | jmp                 7

        $sequence_9 = { 4c8b8424f8000000 488b942400010000 488d8c24f0030000 e8???????? }
            // n = 4, score = 100
            //   4c8b8424f8000000     | mov                 edx, dword ptr [esp + 0x88]
            //   488b942400010000     | dec                 eax
            //   488d8c24f0030000     | mov                 ecx, dword ptr [esp + 0xe0]
            //   e8????????           |                     

        $sequence_10 = { 89857cffffff 8b8d18ffffff 894d80 83bd7cffffff00 }
            // n = 4, score = 100
            //   89857cffffff         | mov                 dword ptr [ebp - 0x84], eax
            //   8b8d18ffffff         | mov                 ecx, dword ptr [ebp - 0xe8]
            //   894d80               | mov                 dword ptr [ebp - 0x80], ecx
            //   83bd7cffffff00       | cmp                 dword ptr [ebp - 0x84], 0

        $sequence_11 = { 4c8b8c2408010000 4c8d05c2930400 ba40000000 488d4c2470 }
            // n = 4, score = 100
            //   4c8b8c2408010000     | movzx               eax, al
            //   4c8d05c2930400       | test                eax, eax
            //   ba40000000           | je                  0x4b
            //   488d4c2470           | dec                 esp

        $sequence_12 = { 89857cffffff 895580 8b4580 3b45dc }
            // n = 4, score = 100
            //   89857cffffff         | mov                 dword ptr [ebp - 0x84], eax
            //   895580               | mov                 dword ptr [ebp - 0x80], edx
            //   8b4580               | mov                 eax, dword ptr [ebp - 0x80]
            //   3b45dc               | cmp                 eax, dword ptr [ebp - 0x24]

        $sequence_13 = { 4c8b8c2408010000 4c8d442460 488b9424f8000000 488b8c24f0000000 }
            // n = 4, score = 100
            //   4c8b8c2408010000     | dec                 eax
            //   4c8d442460           | lea                 edx, [esp + 0x78]
            //   488b9424f8000000     | dec                 eax
            //   488b8c24f0000000     | mov                 ecx, dword ptr [esp + 0xe0]

    condition:
        7 of them and filesize < 857088
}