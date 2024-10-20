rule win_tokyox_auto {

    meta:
        atk_type = "win.tokyox."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.tokyox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tokyox"
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
        $sequence_0 = { 6685c0 75e8 8d8570ffffff 8bf0 }
            // n = 4, score = 200
            //   6685c0               | test                ax, ax
            //   75e8                 | jne                 0xffffffea
            //   8d8570ffffff         | lea                 eax, [ebp - 0x90]
            //   8bf0                 | mov                 esi, eax

        $sequence_1 = { bb0f000000 8975d8 8975e8 51 68ffff0000 50 }
            // n = 6, score = 200
            //   bb0f000000           | mov                 ebx, 0xf
            //   8975d8               | mov                 dword ptr [ebp - 0x28], esi
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi
            //   51                   | push                ecx
            //   68ffff0000           | push                0xffff
            //   50                   | push                eax

        $sequence_2 = { ff15???????? 85c0 0f8456010000 837d1000 751b 68c8000000 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8456010000         | je                  0x15c
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0
            //   751b                 | jne                 0x1d
            //   68c8000000           | push                0xc8

        $sequence_3 = { 8d4598 8bcb 50 6888130000 8d45dc 50 e8???????? }
            // n = 7, score = 200
            //   8d4598               | lea                 eax, [ebp - 0x68]
            //   8bcb                 | mov                 ecx, ebx
            //   50                   | push                eax
            //   6888130000           | push                0x1388
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 8d854cf5ffff 50 68???????? ff15???????? }
            // n = 4, score = 200
            //   8d854cf5ffff         | lea                 eax, [ebp - 0xab4]
            //   50                   | push                eax
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_5 = { 0f114590 0f104010 0f1145c0 0f1145a0 }
            // n = 4, score = 200
            //   0f114590             | movups              xmmword ptr [ebp - 0x70], xmm0
            //   0f104010             | movups              xmm0, xmmword ptr [eax + 0x10]
            //   0f1145c0             | movups              xmmword ptr [ebp - 0x40], xmm0
            //   0f1145a0             | movups              xmmword ptr [ebp - 0x60], xmm0

        $sequence_6 = { ff730c ffd7 e9???????? 8d8550ffffff 0f57c0 50 0f114310 }
            // n = 7, score = 200
            //   ff730c               | push                dword ptr [ebx + 0xc]
            //   ffd7                 | call                edi
            //   e9????????           |                     
            //   8d8550ffffff         | lea                 eax, [ebp - 0xb0]
            //   0f57c0               | xorps               xmm0, xmm0
            //   50                   | push                eax
            //   0f114310             | movups              xmmword ptr [ebx + 0x10], xmm0

        $sequence_7 = { 8d85f0faffff c645a000 50 ff75a0 8d4de8 }
            // n = 5, score = 200
            //   8d85f0faffff         | lea                 eax, [ebp - 0x510]
            //   c645a000             | mov                 byte ptr [ebp - 0x60], 0
            //   50                   | push                eax
            //   ff75a0               | push                dword ptr [ebp - 0x60]
            //   8d4de8               | lea                 ecx, [ebp - 0x18]

        $sequence_8 = { 8bf8 56 53 57 e8???????? 0f1045d0 }
            // n = 6, score = 200
            //   8bf8                 | mov                 edi, eax
            //   56                   | push                esi
            //   53                   | push                ebx
            //   57                   | push                edi
            //   e8????????           |                     
            //   0f1045d0             | movups              xmm0, xmmword ptr [ebp - 0x30]

        $sequence_9 = { 668903 8d5101 8a01 41 84c0 75f9 ff75f8 }
            // n = 7, score = 200
            //   668903               | mov                 word ptr [ebx], ax
            //   8d5101               | lea                 edx, [ecx + 1]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   ff75f8               | push                dword ptr [ebp - 8]

    condition:
        7 of them and filesize < 237568
}