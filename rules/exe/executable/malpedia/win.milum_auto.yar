rule win_milum_auto {

    meta:
        atk_type = "win.milum."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.milum."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.milum"
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
        $sequence_0 = { 8db53cffffff e8???????? 83c41c c645fc20 50 8d4d90 e8???????? }
            // n = 7, score = 400
            //   8db53cffffff         | lea                 esi, [ebp - 0xc4]
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   c645fc20             | mov                 byte ptr [ebp - 4], 0x20
            //   50                   | push                eax
            //   8d4d90               | lea                 ecx, [ebp - 0x70]
            //   e8????????           |                     

        $sequence_1 = { 837b1800 0f8507010000 8b45f0 50 8d75dc e8???????? 837b1800 }
            // n = 7, score = 400
            //   837b1800             | cmp                 dword ptr [ebx + 0x18], 0
            //   0f8507010000         | jne                 0x10d
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   50                   | push                eax
            //   8d75dc               | lea                 esi, [ebp - 0x24]
            //   e8????????           |                     
            //   837b1800             | cmp                 dword ptr [ebx + 0x18], 0

        $sequence_2 = { 50 e8???????? 8bc6 eb0f 885dfc 8d8d34ffffff }
            // n = 6, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   eb0f                 | jmp                 0x11
            //   885dfc               | mov                 byte ptr [ebp - 4], bl
            //   8d8d34ffffff         | lea                 ecx, [ebp - 0xcc]

        $sequence_3 = { 8b4dcc 8b55c8 83c40c c78574ffffff44000000 8945ac 894db4 814da001010000 }
            // n = 7, score = 400
            //   8b4dcc               | mov                 ecx, dword ptr [ebp - 0x34]
            //   8b55c8               | mov                 edx, dword ptr [ebp - 0x38]
            //   83c40c               | add                 esp, 0xc
            //   c78574ffffff44000000     | mov    dword ptr [ebp - 0x8c], 0x44
            //   8945ac               | mov                 dword ptr [ebp - 0x54], eax
            //   894db4               | mov                 dword ptr [ebp - 0x4c], ecx
            //   814da001010000       | or                  dword ptr [ebp - 0x60], 0x101

        $sequence_4 = { 8d8d10feffff e8???????? c645fc1e 8d8df4fdffff e8???????? c645fc1d }
            // n = 6, score = 400
            //   8d8d10feffff         | lea                 ecx, [ebp - 0x1f0]
            //   e8????????           |                     
            //   c645fc1e             | mov                 byte ptr [ebp - 4], 0x1e
            //   8d8df4fdffff         | lea                 ecx, [ebp - 0x20c]
            //   e8????????           |                     
            //   c645fc1d             | mov                 byte ptr [ebp - 4], 0x1d

        $sequence_5 = { 2bc6 c7421803000000 89421c 395a18 0f849cfeffff ddd8 ddd8 }
            // n = 7, score = 400
            //   2bc6                 | sub                 eax, esi
            //   c7421803000000       | mov                 dword ptr [edx + 0x18], 3
            //   89421c               | mov                 dword ptr [edx + 0x1c], eax
            //   395a18               | cmp                 dword ptr [edx + 0x18], ebx
            //   0f849cfeffff         | je                  0xfffffea2
            //   ddd8                 | fstp                st(0)
            //   ddd8                 | fstp                st(0)

        $sequence_6 = { 6bc064 2bc8 8d045590a64600 0fb610 8816 0fb64001 884601 }
            // n = 7, score = 400
            //   6bc064               | imul                eax, eax, 0x64
            //   2bc8                 | sub                 ecx, eax
            //   8d045590a64600       | lea                 eax, [edx*2 + 0x46a690]
            //   0fb610               | movzx               edx, byte ptr [eax]
            //   8816                 | mov                 byte ptr [esi], dl
            //   0fb64001             | movzx               eax, byte ptr [eax + 1]
            //   884601               | mov                 byte ptr [esi + 1], al

        $sequence_7 = { 385f45 7503 895704 8b7a04 897e04 8b7804 3b5704 }
            // n = 7, score = 400
            //   385f45               | cmp                 byte ptr [edi + 0x45], bl
            //   7503                 | jne                 5
            //   895704               | mov                 dword ptr [edi + 4], edx
            //   8b7a04               | mov                 edi, dword ptr [edx + 4]
            //   897e04               | mov                 dword ptr [esi + 4], edi
            //   8b7804               | mov                 edi, dword ptr [eax + 4]
            //   3b5704               | cmp                 edx, dword ptr [edi + 4]

        $sequence_8 = { 8bca eb0e 8b55e8 2bd1 8b4e44 8955d4 894ddc }
            // n = 7, score = 400
            //   8bca                 | mov                 ecx, edx
            //   eb0e                 | jmp                 0x10
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   2bd1                 | sub                 edx, ecx
            //   8b4e44               | mov                 ecx, dword ptr [esi + 0x44]
            //   8955d4               | mov                 dword ptr [ebp - 0x2c], edx
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx

        $sequence_9 = { 8d7508 83ec1c 8bcc 8bc6 c741140f000000 895910 896598 }
            // n = 7, score = 400
            //   8d7508               | lea                 esi, [ebp + 8]
            //   83ec1c               | sub                 esp, 0x1c
            //   8bcc                 | mov                 ecx, esp
            //   8bc6                 | mov                 eax, esi
            //   c741140f000000       | mov                 dword ptr [ecx + 0x14], 0xf
            //   895910               | mov                 dword ptr [ecx + 0x10], ebx
            //   896598               | mov                 dword ptr [ebp - 0x68], esp

    condition:
        7 of them and filesize < 1076224
}