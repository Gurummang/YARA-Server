rule win_new_ct_auto {

    meta:
        atk_type = "win.new_ct."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.new_ct."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.new_ct"
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
        $sequence_0 = { 894304 7532 8bfe 83c9ff 33c0 f2ae f7d1 }
            // n = 7, score = 200
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   7532                 | jne                 0x34
            //   8bfe                 | mov                 edi, esi
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

        $sequence_1 = { 7472 3c42 746e 33c0 }
            // n = 4, score = 200
            //   7472                 | je                  0x74
            //   3c42                 | cmp                 al, 0x42
            //   746e                 | je                  0x70
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 81ec00040000 53 56 6888030000 33db }
            // n = 5, score = 200
            //   81ec00040000         | sub                 esp, 0x400
            //   53                   | push                ebx
            //   56                   | push                esi
            //   6888030000           | push                0x388
            //   33db                 | xor                 ebx, ebx

        $sequence_3 = { 7605 b800000100 8b742418 03c7 8d8c24bc070000 8d44301c }
            // n = 6, score = 200
            //   7605                 | jbe                 7
            //   b800000100           | mov                 eax, 0x10000
            //   8b742418             | mov                 esi, dword ptr [esp + 0x18]
            //   03c7                 | add                 eax, edi
            //   8d8c24bc070000       | lea                 ecx, [esp + 0x7bc]
            //   8d44301c             | lea                 eax, [eax + esi + 0x1c]

        $sequence_4 = { c644240537 c644240679 c6442407b9 7627 }
            // n = 4, score = 200
            //   c644240537           | mov                 byte ptr [esp + 5], 0x37
            //   c644240679           | mov                 byte ptr [esp + 6], 0x79
            //   c6442407b9           | mov                 byte ptr [esp + 7], 0xb9
            //   7627                 | jbe                 0x29

        $sequence_5 = { 8bcd 8933 2bce c6043e00 49 33c0 }
            // n = 6, score = 200
            //   8bcd                 | mov                 ecx, ebp
            //   8933                 | mov                 dword ptr [ebx], esi
            //   2bce                 | sub                 ecx, esi
            //   c6043e00             | mov                 byte ptr [esi + edi], 0
            //   49                   | dec                 ecx
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { 50 6a00 6a00 68???????? 6a00 68???????? ff15???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   6a00                 | push                0
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_7 = { 33c0 8dbc24bd070000 c68424bc07000000 c68424bc0f000000 f3ab 66ab aa }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   8dbc24bd070000       | lea                 edi, [esp + 0x7bd]
            //   c68424bc07000000     | mov                 byte ptr [esp + 0x7bc], 0
            //   c68424bc0f000000     | mov                 byte ptr [esp + 0xfbc], 0
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_8 = { 740d 8d942414020000 52 ffd0 83c404 5f 5e }
            // n = 7, score = 200
            //   740d                 | je                  0xf
            //   8d942414020000       | lea                 edx, [esp + 0x214]
            //   52                   | push                edx
            //   ffd0                 | call                eax
            //   83c404               | add                 esp, 4
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_9 = { 8bbc245c040000 c1e902 f3a5 8bc8 83e103 f3a4 }
            // n = 6, score = 200
            //   8bbc245c040000       | mov                 edi, dword ptr [esp + 0x45c]
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]

    condition:
        7 of them and filesize < 122880
}