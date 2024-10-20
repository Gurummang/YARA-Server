rule win_newposthings_auto {

    meta:
        atk_type = "win.newposthings."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.newposthings."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newposthings"
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
        $sequence_0 = { 8a4601 3c30 7c04 3c39 7e0a 3c3d 7406 }
            // n = 7, score = 100
            //   8a4601               | mov                 al, byte ptr [esi + 1]
            //   3c30                 | cmp                 al, 0x30
            //   7c04                 | jl                  6
            //   3c39                 | cmp                 al, 0x39
            //   7e0a                 | jle                 0xc
            //   3c3d                 | cmp                 al, 0x3d
            //   7406                 | je                  8

        $sequence_1 = { 7423 3d00000400 7550 80c980 884c3704 8b0c9d481d0210 8a443124 }
            // n = 7, score = 100
            //   7423                 | je                  0x25
            //   3d00000400           | cmp                 eax, 0x40000
            //   7550                 | jne                 0x52
            //   80c980               | or                  cl, 0x80
            //   884c3704             | mov                 byte ptr [edi + esi + 4], cl
            //   8b0c9d481d0210       | mov                 ecx, dword ptr [ebx*4 + 0x10021d48]
            //   8a443124             | mov                 al, byte ptr [ecx + esi + 0x24]

        $sequence_2 = { 83e61f 8b0485481d0210 c1e606 80643004fd 8b45f8 8b55fc 5f }
            // n = 7, score = 100
            //   83e61f               | and                 esi, 0x1f
            //   8b0485481d0210       | mov                 eax, dword ptr [eax*4 + 0x10021d48]
            //   c1e606               | shl                 esi, 6
            //   80643004fd           | and                 byte ptr [eax + esi + 4], 0xfd
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   5f                   | pop                 edi

        $sequence_3 = { ff7510 ff750c 56 6843120110 e8???????? 83c418 85c0 }
            // n = 7, score = 100
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   6843120110           | push                0x10011243
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   85c0                 | test                eax, eax

        $sequence_4 = { 83c602 663906 74f8 6a03 56 68548e0110 e8???????? }
            // n = 7, score = 100
            //   83c602               | add                 esi, 2
            //   663906               | cmp                 word ptr [esi], ax
            //   74f8                 | je                  0xfffffffa
            //   6a03                 | push                3
            //   56                   | push                esi
            //   68548e0110           | push                0x10018e54
            //   e8????????           |                     

        $sequence_5 = { 50 c644245c00 8bce e8???????? 8bf0 eb02 33f6 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   c644245c00           | mov                 byte ptr [esp + 0x5c], 0
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   eb02                 | jmp                 4
            //   33f6                 | xor                 esi, esi

        $sequence_6 = { e8???????? 50 8bcb e8???????? c745fc00000000 c745f001000000 8bc3 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1
            //   8bc3                 | mov                 eax, ebx

        $sequence_7 = { 8b049538f34500 47 ff3418 ff15???????? 85c0 750a ff15???????? }
            // n = 7, score = 100
            //   8b049538f34500       | mov                 eax, dword ptr [edx*4 + 0x45f338]
            //   47                   | inc                 edi
            //   ff3418               | push                dword ptr [eax + ebx]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   ff15????????         |                     

        $sequence_8 = { 83c204 8955e0 eb86 890cb538f34500 }
            // n = 4, score = 100
            //   83c204               | add                 edx, 4
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   eb86                 | jmp                 0xffffff88
            //   890cb538f34500       | mov                 dword ptr [esi*4 + 0x45f338], ecx

        $sequence_9 = { e8???????? c745fc00000000 83ec18 8bcc 896588 6aff }
            // n = 6, score = 100
            //   e8????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   83ec18               | sub                 esp, 0x18
            //   8bcc                 | mov                 ecx, esp
            //   896588               | mov                 dword ptr [ebp - 0x78], esp
            //   6aff                 | push                -1

    condition:
        7 of them and filesize < 827392
}