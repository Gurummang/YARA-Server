rule win_concealment_troy_auto {

    meta:
        atk_type = "win.concealment_troy."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.concealment_troy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.concealment_troy"
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
        $sequence_0 = { 6a00 6a04 6a00 6aff ff15???????? e8???????? 50 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   6aff                 | push                -1
            //   ff15????????         |                     
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_1 = { 56 57 b900000000 8b7508 0fb68600010000 0fb69e01010000 33d2 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   b900000000           | mov                 ecx, 0
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   0fb68600010000       | movzx               eax, byte ptr [esi + 0x100]
            //   0fb69e01010000       | movzx               ebx, byte ptr [esi + 0x101]
            //   33d2                 | xor                 edx, edx

        $sequence_2 = { 894d80 c7458410000000 33c0 88440590 40 3d00010000 }
            // n = 6, score = 100
            //   894d80               | mov                 dword ptr [ebp - 0x80], ecx
            //   c7458410000000       | mov                 dword ptr [ebp - 0x7c], 0x10
            //   33c0                 | xor                 eax, eax
            //   88440590             | mov                 byte ptr [ebp + eax - 0x70], al
            //   40                   | inc                 eax
            //   3d00010000           | cmp                 eax, 0x100

        $sequence_3 = { 50 8d8c2438050000 51 e8???????? 8d942434030000 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8d8c2438050000       | lea                 ecx, [esp + 0x538]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8d942434030000       | lea                 edx, [esp + 0x334]

        $sequence_4 = { 75f6 80bc242001000022 0f854e040000 6808020000 8d942434090000 }
            // n = 5, score = 100
            //   75f6                 | jne                 0xfffffff8
            //   80bc242001000022     | cmp                 byte ptr [esp + 0x120], 0x22
            //   0f854e040000         | jne                 0x454
            //   6808020000           | push                0x208
            //   8d942434090000       | lea                 edx, [esp + 0x934]

        $sequence_5 = { 51 e8???????? 8bf0 83c408 85f6 7523 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c408               | add                 esp, 8
            //   85f6                 | test                esi, esi
            //   7523                 | jne                 0x25

        $sequence_6 = { e8???????? 8d8c243c030000 68???????? 51 e8???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8d8c243c030000       | lea                 ecx, [esp + 0x33c]
            //   68????????           |                     
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_7 = { 50 ffd5 bb???????? 8bf8 e8???????? 8b35???????? 50 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ffd5                 | call                ebp
            //   bb????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   e8????????           |                     
            //   8b35????????         |                     
            //   50                   | push                eax

        $sequence_8 = { 55 8bec 83e4f8 b834130000 e8???????? a1???????? 33c4 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83e4f8               | and                 esp, 0xfffffff8
            //   b834130000           | mov                 eax, 0x1334
            //   e8????????           |                     
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp

        $sequence_9 = { 8b1495a0774100 c1e006 8d440224 802080 884dfd 8065fd48 884dff }
            // n = 7, score = 100
            //   8b1495a0774100       | mov                 edx, dword ptr [edx*4 + 0x4177a0]
            //   c1e006               | shl                 eax, 6
            //   8d440224             | lea                 eax, [edx + eax + 0x24]
            //   802080               | and                 byte ptr [eax], 0x80
            //   884dfd               | mov                 byte ptr [ebp - 3], cl
            //   8065fd48             | and                 byte ptr [ebp - 3], 0x48
            //   884dff               | mov                 byte ptr [ebp - 1], cl

    condition:
        7 of them and filesize < 229376
}