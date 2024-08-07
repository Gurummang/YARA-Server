rule win_megumin_auto {

    meta:
        atk_type = "win.megumin."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.megumin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.megumin"
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
        $sequence_0 = { 8b348510164600 037520 6b45243c 034528 6bc03c 03452c }
            // n = 6, score = 200
            //   8b348510164600       | mov                 esi, dword ptr [eax*4 + 0x461610]
            //   037520               | add                 esi, dword ptr [ebp + 0x20]
            //   6b45243c             | imul                eax, dword ptr [ebp + 0x24], 0x3c
            //   034528               | add                 eax, dword ptr [ebp + 0x28]
            //   6bc03c               | imul                eax, eax, 0x3c
            //   03452c               | add                 eax, dword ptr [ebp + 0x2c]

        $sequence_1 = { 8945e8 57 8d4dd8 c745fc00000000 e8???????? 8b45e8 85c0 }
            // n = 7, score = 200
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   57                   | push                edi
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   e8????????           |                     
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   85c0                 | test                eax, eax

        $sequence_2 = { 8d45f4 64a300000000 6841010000 8d8528faffff c745fc00000000 6a00 50 }
            // n = 7, score = 200
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   6841010000           | push                0x141
            //   8d8528faffff         | lea                 eax, [ebp - 0x5d8]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_3 = { 8d4dd8 8d45c0 50 e8???????? ff37 8d55d7 8d4db0 }
            // n = 7, score = 200
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   8d45c0               | lea                 eax, [ebp - 0x40]
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff37                 | push                dword ptr [edi]
            //   8d55d7               | lea                 edx, [ebp - 0x29]
            //   8d4db0               | lea                 ecx, [ebp - 0x50]

        $sequence_4 = { c60100 e8???????? 8d4c2430 e8???????? 8bc8 83c418 83791410 }
            // n = 7, score = 200
            //   c60100               | mov                 byte ptr [ecx], 0
            //   e8????????           |                     
            //   8d4c2430             | lea                 ecx, [esp + 0x30]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   83c418               | add                 esp, 0x18
            //   83791410             | cmp                 dword ptr [ecx + 0x14], 0x10

        $sequence_5 = { 833d????????00 0f8549870000 8d0d90e74500 ba1d000000 e9???????? 833d????????00 0f852c870000 }
            // n = 7, score = 200
            //   833d????????00       |                     
            //   0f8549870000         | jne                 0x874f
            //   8d0d90e74500         | lea                 ecx, [0x45e790]
            //   ba1d000000           | mov                 edx, 0x1d
            //   e9????????           |                     
            //   833d????????00       |                     
            //   0f852c870000         | jne                 0x8732

        $sequence_6 = { 83c404 8d8d14fdffff c645fc1a 51 8bd0 8d8d04fbffff }
            // n = 6, score = 200
            //   83c404               | add                 esp, 4
            //   8d8d14fdffff         | lea                 ecx, [ebp - 0x2ec]
            //   c645fc1a             | mov                 byte ptr [ebp - 4], 0x1a
            //   51                   | push                ecx
            //   8bd0                 | mov                 edx, eax
            //   8d8d04fbffff         | lea                 ecx, [ebp - 0x4fc]

        $sequence_7 = { 0f1f440000 8845eb 8b410c 897da8 8945b0 c645fc02 }
            // n = 6, score = 200
            //   0f1f440000           | nop                 dword ptr [eax + eax]
            //   8845eb               | mov                 byte ptr [ebp - 0x15], al
            //   8b410c               | mov                 eax, dword ptr [ecx + 0xc]
            //   897da8               | mov                 dword ptr [ebp - 0x58], edi
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2

        $sequence_8 = { 8d4101 8945d8 3dffffff7f 0f8700010000 6a00 6a00 50 }
            // n = 7, score = 200
            //   8d4101               | lea                 eax, [ecx + 1]
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   3dffffff7f           | cmp                 eax, 0x7fffffff
            //   0f8700010000         | ja                  0x106
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_9 = { 3bca 763b 8bd1 a81f 7535 8b48fc }
            // n = 6, score = 200
            //   3bca                 | cmp                 ecx, edx
            //   763b                 | jbe                 0x3d
            //   8bd1                 | mov                 edx, ecx
            //   a81f                 | test                al, 0x1f
            //   7535                 | jne                 0x37
            //   8b48fc               | mov                 ecx, dword ptr [eax - 4]

    condition:
        7 of them and filesize < 1007616
}