rule win_pay2key_auto {

    meta:
        atk_type = "win.pay2key."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.pay2key."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pay2key"
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
        $sequence_0 = { f7d1 33d2 3b4dfc 8bcb 0f43d0 3bd7 0f43fa }
            // n = 7, score = 300
            //   f7d1                 | not                 ecx
            //   33d2                 | xor                 edx, edx
            //   3b4dfc               | cmp                 ecx, dword ptr [ebp - 4]
            //   8bcb                 | mov                 ecx, ebx
            //   0f43d0               | cmovae              edx, eax
            //   3bd7                 | cmp                 edx, edi
            //   0f43fa               | cmovae              edi, edx

        $sequence_1 = { e8???????? 8d4e2c e8???????? 8d4e14 e8???????? c74604???????? 8b7e10 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8d4e2c               | lea                 ecx, [esi + 0x2c]
            //   e8????????           |                     
            //   8d4e14               | lea                 ecx, [esi + 0x14]
            //   e8????????           |                     
            //   c74604????????       |                     
            //   8b7e10               | mov                 edi, dword ptr [esi + 0x10]

        $sequence_2 = { ffd7 837d1c08 8d5508 8d7508 0f435508 0f437508 }
            // n = 6, score = 300
            //   ffd7                 | call                edi
            //   837d1c08             | cmp                 dword ptr [ebp + 0x1c], 8
            //   8d5508               | lea                 edx, [ebp + 8]
            //   8d7508               | lea                 esi, [ebp + 8]
            //   0f435508             | cmovae              edx, dword ptr [ebp + 8]
            //   0f437508             | cmovae              esi, dword ptr [ebp + 8]

        $sequence_3 = { c745fc00000000 833e00 7517 68de020000 68???????? 68???????? }
            // n = 6, score = 300
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7517                 | jne                 0x19
            //   68de020000           | push                0x2de
            //   68????????           |                     
            //   68????????           |                     

        $sequence_4 = { 50 e8???????? 83ec18 c645fc05 8bcc 896584 c7411000000000 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   83ec18               | sub                 esp, 0x18
            //   c645fc05             | mov                 byte ptr [ebp - 4], 5
            //   8bcc                 | mov                 ecx, esp
            //   896584               | mov                 dword ptr [ebp - 0x7c], esp
            //   c7411000000000       | mov                 dword ptr [ecx + 0x10], 0

        $sequence_5 = { 3bf7 0f8595f7ffff 83cfff c745fc07000000 8b750c 85f6 7429 }
            // n = 7, score = 300
            //   3bf7                 | cmp                 esi, edi
            //   0f8595f7ffff         | jne                 0xfffff79b
            //   83cfff               | or                  edi, 0xffffffff
            //   c745fc07000000       | mov                 dword ptr [ebp - 4], 7
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   85f6                 | test                esi, esi
            //   7429                 | je                  0x2b

        $sequence_6 = { eb05 6880000000 8bce e8???????? 8b4e20 8bc3 8b09 }
            // n = 7, score = 300
            //   eb05                 | jmp                 7
            //   6880000000           | push                0x80
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8b4e20               | mov                 ecx, dword ptr [esi + 0x20]
            //   8bc3                 | mov                 eax, ebx
            //   8b09                 | mov                 ecx, dword ptr [ecx]

        $sequence_7 = { c7461000000000 7202 8b36 33c0 668906 8db758030000 8b4614 }
            // n = 7, score = 300
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   7202                 | jb                  4
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   33c0                 | xor                 eax, eax
            //   668906               | mov                 word ptr [esi], ax
            //   8db758030000         | lea                 esi, [edi + 0x358]
            //   8b4614               | mov                 eax, dword ptr [esi + 0x14]

        $sequence_8 = { 3bf7 758c 8b5dec ff7314 8b35???????? ffd6 }
            // n = 6, score = 300
            //   3bf7                 | cmp                 esi, edi
            //   758c                 | jne                 0xffffff8e
            //   8b5dec               | mov                 ebx, dword ptr [ebp - 0x14]
            //   ff7314               | push                dword ptr [ebx + 0x14]
            //   8b35????????         |                     
            //   ffd6                 | call                esi

        $sequence_9 = { eb02 33c0 894758 8d5758 8a4304 88475c e8???????? }
            // n = 7, score = 300
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   894758               | mov                 dword ptr [edi + 0x58], eax
            //   8d5758               | lea                 edx, [edi + 0x58]
            //   8a4304               | mov                 al, byte ptr [ebx + 4]
            //   88475c               | mov                 byte ptr [edi + 0x5c], al
            //   e8????????           |                     

    condition:
        7 of them and filesize < 2252800
}