rule win_heyoka_auto {

    meta:
        atk_type = "win.heyoka."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.heyoka."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.heyoka"
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
        $sequence_0 = { 8b4d0c 8b510c 83c204 52 8b45fc 50 }
            // n = 6, score = 100
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b510c               | mov                 edx, dword ptr [ecx + 0xc]
            //   83c204               | add                 edx, 4
            //   52                   | push                edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax

        $sequence_1 = { c745f800000000 c745f000000000 c745f400000000 c745ec00000000 8b4514 6bc005 c1e803 }
            // n = 7, score = 100
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745ec00000000       | mov                 dword ptr [ebp - 0x14], 0
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   6bc005               | imul                eax, eax, 5
            //   c1e803               | shr                 eax, 3

        $sequence_2 = { 8b45dc 50 e8???????? 83c410 8945d8 837dd800 750c }
            // n = 7, score = 100
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   837dd800             | cmp                 dword ptr [ebp - 0x28], 0
            //   750c                 | jne                 0xe

        $sequence_3 = { 83ec08 894df8 8b45f8 c700???????? 8b4df8 c7810c09000000000000 8b55f8 }
            // n = 7, score = 100
            //   83ec08               | sub                 esp, 8
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   c700????????         |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   c7810c09000000000000     | mov    dword ptr [ecx + 0x90c], 0
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]

        $sequence_4 = { e8???????? 83c408 8b5518 52 8b45dc 83c004 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]
            //   52                   | push                edx
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   83c004               | add                 eax, 4

        $sequence_5 = { e8???????? 83c408 eb17 837d0803 7511 68???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   eb17                 | jmp                 0x19
            //   837d0803             | cmp                 dword ptr [ebp + 8], 3
            //   7511                 | jne                 0x13
            //   68????????           |                     

        $sequence_6 = { 8bec 83ec08 8b4508 50 6a01 e8???????? 83c408 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec08               | sub                 esp, 8
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   6a01                 | push                1
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_7 = { 7423 8bce 8bc6 c1f905 83e01f 8b0c8da0d80110 }
            // n = 6, score = 100
            //   7423                 | je                  0x25
            //   8bce                 | mov                 ecx, esi
            //   8bc6                 | mov                 eax, esi
            //   c1f905               | sar                 ecx, 5
            //   83e01f               | and                 eax, 0x1f
            //   8b0c8da0d80110       | mov                 ecx, dword ptr [ecx*4 + 0x1001d8a0]

        $sequence_8 = { 51 e8???????? 83c404 8b45e0 83c00c 8be5 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   83c00c               | add                 eax, 0xc
            //   8be5                 | mov                 esp, ebp

        $sequence_9 = { 8955f8 8b45fc 8b4df4 8b55f8 0faf948134e30000 8b4df4 8bc2 }
            // n = 7, score = 100
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   0faf948134e30000     | imul                edx, dword ptr [ecx + eax*4 + 0xe334]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8bc2                 | mov                 eax, edx

    condition:
        7 of them and filesize < 270336
}