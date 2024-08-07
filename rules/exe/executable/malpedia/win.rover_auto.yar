rule win_rover_auto {

    meta:
        atk_type = "win.rover."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rover."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rover"
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
        $sequence_0 = { 6800120000 885c247b ff15???????? 85c0 0f8422010000 8b35???????? 8d542460 }
            // n = 7, score = 100
            //   6800120000           | push                0x1200
            //   885c247b             | mov                 byte ptr [esp + 0x7b], bl
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8422010000         | je                  0x128
            //   8b35????????         |                     
            //   8d542460             | lea                 edx, [esp + 0x60]

        $sequence_1 = { ff15???????? 8d4c2404 c684249c00000000 ff15???????? 8d8c24a4000000 c784249c000000ffffffff }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   c684249c00000000     | mov                 byte ptr [esp + 0x9c], 0
            //   ff15????????         |                     
            //   8d8c24a4000000       | lea                 ecx, [esp + 0xa4]
            //   c784249c000000ffffffff     | mov    dword ptr [esp + 0x9c], 0xffffffff

        $sequence_2 = { 83ed01 0f8464010000 83ed04 0f845b010000 83bba402000000 8b6a28 896c240c }
            // n = 7, score = 100
            //   83ed01               | sub                 ebp, 1
            //   0f8464010000         | je                  0x16a
            //   83ed04               | sub                 ebp, 4
            //   0f845b010000         | je                  0x161
            //   83bba402000000       | cmp                 dword ptr [ebx + 0x2a4], 0
            //   8b6a28               | mov                 ebp, dword ptr [edx + 0x28]
            //   896c240c             | mov                 dword ptr [esp + 0xc], ebp

        $sequence_3 = { 85db 0f856f030000 8b471c 85c0 7421 50 8d442414 }
            // n = 7, score = 100
            //   85db                 | test                ebx, ebx
            //   0f856f030000         | jne                 0x375
            //   8b471c               | mov                 eax, dword ptr [edi + 0x1c]
            //   85c0                 | test                eax, eax
            //   7421                 | je                  0x23
            //   50                   | push                eax
            //   8d442414             | lea                 eax, [esp + 0x14]

        $sequence_4 = { 8bf0 83c404 3bf3 7537 a1???????? 8b4824 8d542438 }
            // n = 7, score = 100
            //   8bf0                 | mov                 esi, eax
            //   83c404               | add                 esp, 4
            //   3bf3                 | cmp                 esi, ebx
            //   7537                 | jne                 0x39
            //   a1????????           |                     
            //   8b4824               | mov                 ecx, dword ptr [eax + 0x24]
            //   8d542438             | lea                 edx, [esp + 0x38]

        $sequence_5 = { 50 8b442458 68???????? 50 e8???????? 83c410 85c0 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b442458             | mov                 eax, dword ptr [esp + 0x58]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax

        $sequence_6 = { 8b8fb0050000 8d6b50 89442410 8987b0050000 8b85a8000000 8bd0 80e215 }
            // n = 7, score = 100
            //   8b8fb0050000         | mov                 ecx, dword ptr [edi + 0x5b0]
            //   8d6b50               | lea                 ebp, [ebx + 0x50]
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   8987b0050000         | mov                 dword ptr [edi + 0x5b0], eax
            //   8b85a8000000         | mov                 eax, dword ptr [ebp + 0xa8]
            //   8bd0                 | mov                 edx, eax
            //   80e215               | and                 dl, 0x15

        $sequence_7 = { 83e802 7426 83e815 740f 683f270000 ff15???????? 83c8ff }
            // n = 7, score = 100
            //   83e802               | sub                 eax, 2
            //   7426                 | je                  0x28
            //   83e815               | sub                 eax, 0x15
            //   740f                 | je                  0x11
            //   683f270000           | push                0x273f
            //   ff15????????         |                     
            //   83c8ff               | or                  eax, 0xffffffff

        $sequence_8 = { 83c40c c3 6a2f 57 ffd6 83c408 85c0 }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   c3                   | ret                 
            //   6a2f                 | push                0x2f
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax

        $sequence_9 = { 57 e8???????? 56 e8???????? 83c40c c744242c04000000 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c744242c04000000     | mov                 dword ptr [esp + 0x2c], 4

    condition:
        7 of them and filesize < 704512
}