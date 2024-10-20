rule win_snifula_auto {

    meta:
        atk_type = "win.snifula."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.snifula."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snifula"
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
        $sequence_0 = { 53 ff35???????? ffd7 6800040000 53 ff35???????? }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   ff35????????         |                     
            //   ffd7                 | call                edi
            //   6800040000           | push                0x400
            //   53                   | push                ebx
            //   ff35????????         |                     

        $sequence_1 = { 53 6a00 ff35???????? ff15???????? b8???????? 83c9ff }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   b8????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_2 = { 6a00 ff35???????? 8945fc ff15???????? 8bf8 85ff }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi

        $sequence_3 = { a1???????? 85c0 75ef 53 57 bb???????? }
            // n = 6, score = 200
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   75ef                 | jne                 0xfffffff1
            //   53                   | push                ebx
            //   57                   | push                edi
            //   bb????????           |                     

        $sequence_4 = { ff15???????? 8bf8 83ffff 747f 53 8d450c 50 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   83ffff               | cmp                 edi, -1
            //   747f                 | je                  0x81
            //   53                   | push                ebx
            //   8d450c               | lea                 eax, [ebp + 0xc]
            //   50                   | push                eax

        $sequence_5 = { e8???????? 85c0 740c 81386368756e 7504 834e1002 8bc6 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   740c                 | je                  0xe
            //   81386368756e         | cmp                 dword ptr [eax], 0x6e756863
            //   7504                 | jne                 6
            //   834e1002             | or                  dword ptr [esi + 0x10], 2
            //   8bc6                 | mov                 eax, esi

        $sequence_6 = { c1e802 25ff000000 8d44c72c 8b18 3bd8 7432 }
            // n = 6, score = 200
            //   c1e802               | shr                 eax, 2
            //   25ff000000           | and                 eax, 0xff
            //   8d44c72c             | lea                 eax, [edi + eax*8 + 0x2c]
            //   8b18                 | mov                 ebx, dword ptr [eax]
            //   3bd8                 | cmp                 ebx, eax
            //   7432                 | je                  0x34

        $sequence_7 = { 83f803 7533 ff7304 8bc7 ff750c e8???????? 8b4724 }
            // n = 7, score = 200
            //   83f803               | cmp                 eax, 3
            //   7533                 | jne                 0x35
            //   ff7304               | push                dword ptr [ebx + 4]
            //   8bc7                 | mov                 eax, edi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   8b4724               | mov                 eax, dword ptr [edi + 0x24]

        $sequence_8 = { 68???????? 56 ff15???????? 83c414 68???????? 56 }
            // n = 6, score = 200
            //   68????????           |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   68????????           |                     
            //   56                   | push                esi

        $sequence_9 = { 53 50 889c243c010000 e8???????? a1???????? 83c43c 895c2430 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   50                   | push                eax
            //   889c243c010000       | mov                 byte ptr [esp + 0x13c], bl
            //   e8????????           |                     
            //   a1????????           |                     
            //   83c43c               | add                 esp, 0x3c
            //   895c2430             | mov                 dword ptr [esp + 0x30], ebx

    condition:
        7 of them and filesize < 188416
}