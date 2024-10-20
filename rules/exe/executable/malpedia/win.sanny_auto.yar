rule win_sanny_auto {

    meta:
        atk_type = "win.sanny."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sanny."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sanny"
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
        $sequence_0 = { 51 8bcb e8???????? 8b5310 68???????? 8d442a08 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   8b5310               | mov                 edx, dword ptr [ebx + 0x10]
            //   68????????           |                     
            //   8d442a08             | lea                 eax, [edx + ebp + 8]

        $sequence_1 = { 8b842430060000 8d742410 8d5901 b987000000 53 81ec1c020000 8bfc }
            // n = 7, score = 100
            //   8b842430060000       | mov                 eax, dword ptr [esp + 0x630]
            //   8d742410             | lea                 esi, [esp + 0x10]
            //   8d5901               | lea                 ebx, [ecx + 1]
            //   b987000000           | mov                 ecx, 0x87
            //   53                   | push                ebx
            //   81ec1c020000         | sub                 esp, 0x21c
            //   8bfc                 | mov                 edi, esp

        $sequence_2 = { ebd3 53 55 56 57 }
            // n = 5, score = 100
            //   ebd3                 | jmp                 0xffffffd5
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_3 = { 52 68???????? 56 e8???????? 8b44244c }
            // n = 5, score = 100
            //   52                   | push                edx
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b44244c             | mov                 eax, dword ptr [esp + 0x4c]

        $sequence_4 = { 8bc2 c1c60a 03f1 f7d0 0bc6 33c1 }
            // n = 6, score = 100
            //   8bc2                 | mov                 eax, edx
            //   c1c60a               | rol                 esi, 0xa
            //   03f1                 | add                 esi, ecx
            //   f7d0                 | not                 eax
            //   0bc6                 | or                  eax, esi
            //   33c1                 | xor                 eax, ecx

        $sequence_5 = { ae 40 00bcae4000e0ae 40 0023 d18a0688078a }
            // n = 6, score = 100
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   40                   | inc                 eax
            //   00bcae4000e0ae       | add                 byte ptr [esi + ebp*4 - 0x511fffc0], bh
            //   40                   | inc                 eax
            //   0023                 | add                 byte ptr [ebx], ah
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1

        $sequence_6 = { 55 68???????? 55 e8???????? 8b4c2424 83c410 55 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   68????????           |                     
            //   55                   | push                ebp
            //   e8????????           |                     
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   83c410               | add                 esp, 0x10
            //   55                   | push                ebp

        $sequence_7 = { 663918 747f 668b11 6683fa41 720c }
            // n = 5, score = 100
            //   663918               | cmp                 word ptr [eax], bx
            //   747f                 | je                  0x81
            //   668b11               | mov                 dx, word ptr [ecx]
            //   6683fa41             | cmp                 dx, 0x41
            //   720c                 | jb                  0xe

        $sequence_8 = { f3ab 8b0d???????? aa 898c2408010000 b906000000 33c0 8dbc240d010000 }
            // n = 7, score = 100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8b0d????????         |                     
            //   aa                   | stosb               byte ptr es:[edi], al
            //   898c2408010000       | mov                 dword ptr [esp + 0x108], ecx
            //   b906000000           | mov                 ecx, 6
            //   33c0                 | xor                 eax, eax
            //   8dbc240d010000       | lea                 edi, [esp + 0x10d]

        $sequence_9 = { 8b44241c 8d9424dc000000 52 50 ffd5 b925000000 33c0 }
            // n = 7, score = 100
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   8d9424dc000000       | lea                 edx, [esp + 0xdc]
            //   52                   | push                edx
            //   50                   | push                eax
            //   ffd5                 | call                ebp
            //   b925000000           | mov                 ecx, 0x25
            //   33c0                 | xor                 eax, eax

    condition:
        7 of them and filesize < 253952
}