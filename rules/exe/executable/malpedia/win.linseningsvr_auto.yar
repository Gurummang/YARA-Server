rule win_linseningsvr_auto {

    meta:
        atk_type = "win.linseningsvr."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.linseningsvr."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.linseningsvr"
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
        $sequence_0 = { 81c4cc0d0000 c3 68ffffff7f 56 ff15???????? 83f8ff }
            // n = 6, score = 100
            //   81c4cc0d0000         | add                 esp, 0xdcc
            //   c3                   | ret                 
            //   68ffffff7f           | push                0x7fffffff
            //   56                   | push                esi
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1

        $sequence_1 = { 5d b801000000 5b 81c4cc0d0000 }
            // n = 4, score = 100
            //   5d                   | pop                 ebp
            //   b801000000           | mov                 eax, 1
            //   5b                   | pop                 ebx
            //   81c4cc0d0000         | add                 esp, 0xdcc

        $sequence_2 = { 8b4c2428 6a24 8d542464 6a01 52 89442464 }
            // n = 6, score = 100
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   6a24                 | push                0x24
            //   8d542464             | lea                 edx, [esp + 0x64]
            //   6a01                 | push                1
            //   52                   | push                edx
            //   89442464             | mov                 dword ptr [esp + 0x64], eax

        $sequence_3 = { 7e16 8b742414 8bd1 8d7c1f18 c1e902 f3a5 8bca }
            // n = 7, score = 100
            //   7e16                 | jle                 0x18
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]
            //   8bd1                 | mov                 edx, ecx
            //   8d7c1f18             | lea                 edi, [edi + ebx + 0x18]
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bca                 | mov                 ecx, edx

        $sequence_4 = { f6c202 7410 8088????????20 8a9405ecfcffff ebe3 80a0808b400000 40 }
            // n = 7, score = 100
            //   f6c202               | test                dl, 2
            //   7410                 | je                  0x12
            //   8088????????20       |                     
            //   8a9405ecfcffff       | mov                 dl, byte ptr [ebp + eax - 0x314]
            //   ebe3                 | jmp                 0xffffffe5
            //   80a0808b400000       | and                 byte ptr [eax + 0x408b80], 0
            //   40                   | inc                 eax

        $sequence_5 = { 0f858b030000 33c9 8acc 3ac8 }
            // n = 4, score = 100
            //   0f858b030000         | jne                 0x391
            //   33c9                 | xor                 ecx, ecx
            //   8acc                 | mov                 cl, ah
            //   3ac8                 | cmp                 cl, al

        $sequence_6 = { 55 6800010000 8d942464040000 6a01 52 e8???????? }
            // n = 6, score = 100
            //   55                   | push                ebp
            //   6800010000           | push                0x100
            //   8d942464040000       | lea                 edx, [esp + 0x464]
            //   6a01                 | push                1
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_7 = { 8acc 3ac8 0f857f030000 33d2 55 89542432 }
            // n = 6, score = 100
            //   8acc                 | mov                 cl, ah
            //   3ac8                 | cmp                 cl, al
            //   0f857f030000         | jne                 0x385
            //   33d2                 | xor                 edx, edx
            //   55                   | push                ebp
            //   89542432             | mov                 dword ptr [esp + 0x32], edx

        $sequence_8 = { 66895c2411 89442419 885c2418 8944241d 89442421 6689442425 88442427 }
            // n = 7, score = 100
            //   66895c2411           | mov                 word ptr [esp + 0x11], bx
            //   89442419             | mov                 dword ptr [esp + 0x19], eax
            //   885c2418             | mov                 byte ptr [esp + 0x18], bl
            //   8944241d             | mov                 dword ptr [esp + 0x1d], eax
            //   89442421             | mov                 dword ptr [esp + 0x21], eax
            //   6689442425           | mov                 word ptr [esp + 0x25], ax
            //   88442427             | mov                 byte ptr [esp + 0x27], al

        $sequence_9 = { 7514 ff15???????? 50 68???????? e8???????? 83c408 55 }
            // n = 7, score = 100
            //   7514                 | jne                 0x16
            //   ff15????????         |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   55                   | push                ebp

    condition:
        7 of them and filesize < 81360
}