rule win_hyperbro_auto {

    meta:
        atk_type = "win.hyperbro."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.hyperbro."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hyperbro"
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
        $sequence_0 = { 33c0 6a40 66890479 e8???????? 6a40 }
            // n = 5, score = 400
            //   33c0                 | xor                 eax, eax
            //   6a40                 | push                0x40
            //   66890479             | mov                 word ptr [ecx + edi*2], ax
            //   e8????????           |                     
            //   6a40                 | push                0x40

        $sequence_1 = { 8b4604 83c004 50 6a00 57 }
            // n = 5, score = 400
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   83c004               | add                 eax, 4
            //   50                   | push                eax
            //   6a00                 | push                0
            //   57                   | push                edi

        $sequence_2 = { 46 47 83e801 75f5 }
            // n = 4, score = 400
            //   46                   | inc                 esi
            //   47                   | inc                 edi
            //   83e801               | sub                 eax, 1
            //   75f5                 | jne                 0xfffffff7

        $sequence_3 = { 8d542428 68???????? c74424200c000000 c744242801000000 89542424 ff15???????? }
            // n = 6, score = 400
            //   8d542428             | lea                 edx, [esp + 0x28]
            //   68????????           |                     
            //   c74424200c000000     | mov                 dword ptr [esp + 0x20], 0xc
            //   c744242801000000     | mov                 dword ptr [esp + 0x28], 1
            //   89542424             | mov                 dword ptr [esp + 0x24], edx
            //   ff15????????         |                     

        $sequence_4 = { 05ff000000 41 3d01feffff 0f871c010000 8bd5 2bd1 83fa01 }
            // n = 7, score = 400
            //   05ff000000           | add                 eax, 0xff
            //   41                   | inc                 ecx
            //   3d01feffff           | cmp                 eax, 0xfffffe01
            //   0f871c010000         | ja                  0x122
            //   8bd5                 | mov                 edx, ebp
            //   2bd1                 | sub                 edx, ecx
            //   83fa01               | cmp                 edx, 1

        $sequence_5 = { 50 8d4c2472 51 6689442474 }
            // n = 4, score = 400
            //   50                   | push                eax
            //   8d4c2472             | lea                 ecx, [esp + 0x72]
            //   51                   | push                ecx
            //   6689442474           | mov                 word ptr [esp + 0x74], ax

        $sequence_6 = { 6882000000 c706???????? e8???????? 6882000000 6a00 50 }
            // n = 6, score = 400
            //   6882000000           | push                0x82
            //   c706????????         |                     
            //   e8????????           |                     
            //   6882000000           | push                0x82
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_7 = { e8???????? 83c404 83eb01 79ec 8b4f2c 51 e8???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83eb01               | sub                 ebx, 1
            //   79ec                 | jns                 0xffffffee
            //   8b4f2c               | mov                 ecx, dword ptr [edi + 0x2c]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_8 = { 83c410 85ed 750e 8b7c2410 }
            // n = 4, score = 400
            //   83c410               | add                 esp, 0x10
            //   85ed                 | test                ebp, ebp
            //   750e                 | jne                 0x10
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]

        $sequence_9 = { 8b44242c 3bc3 7415 50 e8???????? 83c404 }
            // n = 6, score = 400
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   3bc3                 | cmp                 eax, ebx
            //   7415                 | je                  0x17
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

    condition:
        7 of them and filesize < 352256
}