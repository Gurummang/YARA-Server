rule win_alma_locker_auto {

    meta:
        atk_type = "win.alma_locker."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.alma_locker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alma_locker"
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
        $sequence_0 = { 8d8d6cfeffff e8???????? 83c404 8d4d8c c645fc07 51 8bd0 }
            // n = 7, score = 100
            //   8d8d6cfeffff         | lea                 ecx, [ebp - 0x194]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d4d8c               | lea                 ecx, [ebp - 0x74]
            //   c645fc07             | mov                 byte ptr [ebp - 4], 7
            //   51                   | push                ecx
            //   8bd0                 | mov                 edx, eax

        $sequence_1 = { 720e ffb5ccfeffff e8???????? 83c404 837da008 720b ff758c }
            // n = 7, score = 100
            //   720e                 | jb                  0x10
            //   ffb5ccfeffff         | push                dword ptr [ebp - 0x134]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   837da008             | cmp                 dword ptr [ebp - 0x60], 8
            //   720b                 | jb                  0xd
            //   ff758c               | push                dword ptr [ebp - 0x74]

        $sequence_2 = { 0304b5e86a0210 59 eb02 8bc3 8a4024 247f 3c01 }
            // n = 7, score = 100
            //   0304b5e86a0210       | add                 eax, dword ptr [esi*4 + 0x10026ae8]
            //   59                   | pop                 ecx
            //   eb02                 | jmp                 4
            //   8bc3                 | mov                 eax, ebx
            //   8a4024               | mov                 al, byte ptr [eax + 0x24]
            //   247f                 | and                 al, 0x7f
            //   3c01                 | cmp                 al, 1

        $sequence_3 = { 50 ff15???????? 8bf0 89b52cfaffff }
            // n = 4, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   89b52cfaffff         | mov                 dword ptr [ebp - 0x5d4], esi

        $sequence_4 = { 83e11f c1f805 c1e106 8b0485e86a0210 f644080401 7405 }
            // n = 6, score = 100
            //   83e11f               | and                 ecx, 0x1f
            //   c1f805               | sar                 eax, 5
            //   c1e106               | shl                 ecx, 6
            //   8b0485e86a0210       | mov                 eax, dword ptr [eax*4 + 0x10026ae8]
            //   f644080401           | test                byte ptr [eax + ecx + 4], 1
            //   7405                 | je                  7

        $sequence_5 = { 8d8dd0fbffff e8???????? c645fc03 8d85d0fbffff 83bde4fbffff10 0f4385d0fbffff }
            // n = 6, score = 100
            //   8d8dd0fbffff         | lea                 ecx, [ebp - 0x430]
            //   e8????????           |                     
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   8d85d0fbffff         | lea                 eax, [ebp - 0x430]
            //   83bde4fbffff10       | cmp                 dword ptr [ebp - 0x41c], 0x10
            //   0f4385d0fbffff       | cmovae              eax, dword ptr [ebp - 0x430]

        $sequence_6 = { b9???????? e8???????? 33c0 c645fc1f 33c9 66a3???????? 66390d???????? }
            // n = 7, score = 100
            //   b9????????           |                     
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   c645fc1f             | mov                 byte ptr [ebp - 4], 0x1f
            //   33c9                 | xor                 ecx, ecx
            //   66a3????????         |                     
            //   66390d????????       |                     

        $sequence_7 = { 81fbfeffff7f 0f87ab000000 8b4614 3bc3 7325 ff7610 53 }
            // n = 7, score = 100
            //   81fbfeffff7f         | cmp                 ebx, 0x7ffffffe
            //   0f87ab000000         | ja                  0xb1
            //   8b4614               | mov                 eax, dword ptr [esi + 0x14]
            //   3bc3                 | cmp                 eax, ebx
            //   7325                 | jae                 0x27
            //   ff7610               | push                dword ptr [esi + 0x10]
            //   53                   | push                ebx

        $sequence_8 = { b9???????? c705????????07000000 0f44f8 c705????????00000000 57 68???????? }
            // n = 6, score = 100
            //   b9????????           |                     
            //   c705????????07000000     |     
            //   0f44f8               | cmove               edi, eax
            //   c705????????00000000     |     
            //   57                   | push                edi
            //   68????????           |                     

        $sequence_9 = { 83c404 c78584fbffff0f000000 c78580fbffff00000000 c68570fbffff00 83bd9cfbffff10 720e }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   c78584fbffff0f000000     | mov    dword ptr [ebp - 0x47c], 0xf
            //   c78580fbffff00000000     | mov    dword ptr [ebp - 0x480], 0
            //   c68570fbffff00       | mov                 byte ptr [ebp - 0x490], 0
            //   83bd9cfbffff10       | cmp                 dword ptr [ebp - 0x464], 0x10
            //   720e                 | jb                  0x10

    condition:
        7 of them and filesize < 335872
}