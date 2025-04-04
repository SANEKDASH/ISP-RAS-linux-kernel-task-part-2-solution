# Анализ варнинга в linux-kernel полученного syzkaller'ом

## Введение
Мне выдали несколько сообщений от syzkaller'а о варнинге в функции get_pat_info() ядра линукс.

Выглядят они следующим образом:
1-й репорт (был получен на версии ядра 5.10.234):
```
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
------------[ cut here ]------------
Call Trace:
 __dump_stack lib/dump_stack.c:77 [inline]
 dump_stack+0x107/0x167 lib/dump_stack.c:118
 fail_dump lib/fault-inject.c:52 [inline]
 should_fail.cold+0x5/0xa lib/fault-inject.c:146
WARNING: CPU: 1 PID: 1418 at arch/x86/mm/pat/memtype.c:1019 get_pat_info+0x216/0x270 arch/x86/mm/pat/memtype.c:1019
 should_failslab+0x5/0x20 mm/slab_common.c:1200
 slab_pre_alloc_hook mm/slab.h:515 [inline]
 slab_alloc_node mm/slub.c:2821 [inline]
 slab_alloc mm/slub.c:2904 [inline]
 kmem_cache_alloc_trace+0x55/0x2f0 mm/slub.c:2921
 io_uring_alloc_task_context+0x99Socket connected tcp:127.0.0.1:49381,server=on <-> 127.0.0.1:49460
Modules linked in:
 __io_uring_add_tctx_node+0x2c6/0x520 io_uring/io_uring.c:9590

 io_uring_add_tctx_node io_uring/io_uring.c:9635 [inline]
 io_uring_install_fd io_uring/io_uring.c:10159 [inline]
 io_uring_create io_uring/io_uring.c:10292 [inline]
 io_uring_setup+0x1fab/0x2980 io_uring/io_uring.c:10329
CPU: 1 PID: 1418 Comm: syz-executor.3 Not tainted 5.10.234-syzkaller #0
 do_syscall_64+0x33/0x40 arch/x86/entry/common.c:46
 entry_SYSCALL_64_after_hwframe+0x67/0xd1
RIP: 0033:0x46a269
Code: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48

Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
RSP: 002b:00007fcf6bbb6b88 EFLAGS: 00000206 ORIG_RAX: 00000000000001a9
RAX: ffffffffffffffda RBX: 0000000020000080 RCX: 000000000046a269
RDX: 0000000020c00000 RSI: 0000000020000080 RDI: 00000000000039f4
RBP: 00007fcf6bbb6c60 R08: 0000000020000300 R09: 0000000020000300
R10: 00000000200002c0 R11: 0000000000000206 R12: 0000000020c00000
R13: 0000000020ffb000 R14: 0000000020000300 R15: 00000000200002c0
RIP: 0010:get_pat_info+0x216/0x270 arch/x86/mm/pat/memtype.c:1019
Code: c1 ea 03 80 3c 02 00 75 71 49 89 1e eb 8e e8 51 c0 3e 00 0f 0b e9 97 fe ff ff 41 bc ea ff ff ff e9 77 ff ff ff e8 3a c0 3e 00 <0f> 0b 41 bc ea ff ff ff e9 65 ff ff ff 4c 89 ff e8 85 fd 7d 00 e9
RSP: 0018:ffffc9001499f760 EFLAGS: 00010246
RAX: 0000000000040000 RBX: ffff88811cf619c8 RCX: ffffc9000f273000
RDX: 0000000000040000 RSI: ffffffff81318a06 RDI: 0000000000000007
RBP: ffffc9001499f818 R08: 0000000000000000 R09: ffffc9001499f6e8
R10: 0000000000000028 R11: 0000000000000001 R12: 0000000000000028
R13: 1ffff92002933eec R14: 0000000000000000 R15: ffff88811cf61a18
FS:  00007f309921c700(0000) GS:ffff8882bac00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000000000 CR3: 000000010cb22000 CR4: 0000000000350ee0
Call Trace:
 untrack_pfn+0xdc/0x240 arch/x86/mm/pat/memtype.c:1121
 unmap_single_vma+0x17b/0x2b0 mm/memory.c:1500
 zap_page_range_single+0x2bd/0x430 mm/memory.c:1604
 remap_pfn_range_notrack+0x9af/0xc60 mm/memory.c:2364
 remap_pfn_range+0xc6/0x140 mm/memory.c:2389
 io_uring_mmap+0x37e/0x480 io_uring/io_uring.c:9805
 call_mmap include/linux/fs.h:2044 [inline]
 mmap_file+0x5e/0xe0 mm/util.c:1080
 __mmap_region mm/mmap.c:1805 [inline]
 mmap_region+0xc28/0x1420 mm/mmap.c:2945
 do_mmap+0xc9d/0x1150 mm/mmap.c:1582
 vm_mmap_pgoff+0x199/0x200 mm/util.c:539
 ksys_mmap_pgoff+0x418/0x580 mm/mmap.c:1633
 do_syscall_64+0x33/0x40 arch/x86/entry/common.c:46
 entry_SYSCALL_64_after_hwframe+0x67/0xd1
RIP: 0033:0x46a2d3
Code: 54 41 89 d4 55 48 89 fd 53 4c 89 cb 48 85 ff 74 56 49 89 d9 45 89 f8 45 89 f2 44 89 e2 4c 89 ee 48 89 ef b8 09 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 75 5b 5d 41 5c 41 5d 41 5e 41 5f c3 66 2e 0f
RSP: 002b:00007f309921bb58 EFLAGS: 00000206 ORIG_RAX: 0000000000000009
RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 000000000046a2d3
RDX: 0000000000000003 RSI: 0000000000090140 RDI: 0000000020ffb000
RBP: 0000000020ffb000 R08: 0000000000000004 R09: 0000000000000000
R10: 0000000000008011 R11: 0000000000000206 R12: 0000000000000003
R13: 0000000000090140 R14: 0000000000008011 R15: 0000000000000004
```

2-й репорт (был получен на версии ядра 6.1.118):
```
erofs: (device loop4): mounted with root inode @ nid 36.
------------[ cut here ]------------
erofs: (device loop6): mounted with root inode @ nid 36.
erofs: (device loop7): mounted with root inode @ nid 36.
WARNING: CPU: 0 PID: 21675 at arch/x86/mm/pat/memtype.c:1028 get_pat_info+0x210/0x270 arch/x86/mm/pat/memtype.c:1028
Modules linked in:
PU: 0 PID: 21675 Comm: syz-executor.5 Not tainted 6.1.118-syzkaller-00108-gdd21049e63b4 #0
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
RIP: 0010:get_pat_info+0x210/0x270 arch/x86/mm/pat/memtype.c:1028
Code: c1 ea 03 80 3c 02 00 75 71 49 89 1e eb 8e e8 17 3d 43 00 0f 0b e9 9d fe ff ff 41 bc ea ff ff ff e9 77 ff ff ff e8 00 3d 43 00 <0f> 0b 41 bc ea ff ff ff e9 65 ff ff ff 4c 89 ff e8 9b db 8c 00 e9
RSP: 0018:ffff88811629f6b8 EFLAGS: 00010246
RAX: 0000000000040000 RBX: ffff888110f5ee58 RCX: ffffc900139d2000
RDX: 0000000000040000 RSI: ffffffff81370070 RDI: 0000000000000007
RBP: ffff88811629f770 R08: ffff88811629f770 R09: 0000000000000000
R10: 0000000000000000 R11: 3e4b5341542f3c20 R12: 0000000000000000
R13: 1ffff11022c53ed7 R14: 0000000000000000 R15: ffff888110f5ee78
FS:  00007f3a05524700(0000) GS:ffff888128e00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 000000000053c1b8 CR3: 000000011f07e000 CR4: 0000000000350ef0
Call Trace:
 <TASK>
 untrack_pfn+0xdc/0x240 arch/x86/mm/pat/memtype.c:1130
 unmap_single_vma+0x17b/0x250 mm/memory.c:1669
 zap_page_range_single+0x305/0x4c0 mm/memory.c:1794
 remap_pfn_range_notrack+0x9af/0xc60 mm/memory.c:2553
 remap_pfn_range+0xc6/0x140 mm/memory.c:2578
 usbdev_mmap+0x40b/0x870 drivers/usb/core/devio.c:276
 call_mmap include/linux/fs.h:2270 [inline]
 mmap_region+0x631/0x19c0 mm/mmap.c:2763
 do_mmap+0x84b/0xf20 mm/mmap.c:1425
 vm_mmap_pgoff+0x1af/0x280 mm/util.c:520
 ksys_mmap_pgoff+0x41f/0x5a0 mm/mmap.c:1471
 do_syscall_x64 arch/x86/entry/common.c:51 [inline]
 do_syscall_64+0x35/0x80 arch/x86/entry/common.c:81
 entry_SYSCALL_64_after_hwframe+0x6e/0xd8
RIP: 0033:0x46a269
Code: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007f3a05523c08 EFLAGS: 00000246 ORIG_RAX: 0000000000000009
RAX: ffffffffffffffda RBX: 000000000056bf80 RCX: 000000000046a269
RDX: 0000000000000000 RSI: 0000000000003000 RDI: 0000000020ffd000
RBP: 00007f3a05523c60 R08: 0000000000000003 R09: 0000000000000000
R10: 0000000000004011 R11: 0000000000000246 R12: 000000000000000b
R13: 00007ffc40179e8f R14: 00007f3a05524700 R15: 0000000000000000
 </TASK>
```

3-й репорт (был получен на версии ядра 5.10.233):
```
RBP: 0000000020ffc000 R08: 0000000000000004 R09: 0000000000000000
R10: 0000000000008011 R11: 0000000000000206 R12: 0000000000000003
R13: 0000000000120140 R14: 0000000000008011 R15: 0000000000000004
------------[ cut here ]------------
WARNING: CPU: 2 PID: 7729 at arch/x86/mm/pat/memtype.c:1019 get_pat_info+0x216/0x270 arch/x86/mm/pat/memtype.c:1019
Modules linked in:
CPU: 2 PID: 7729 Comm: syz-executor.6 Not tainted 5.10.233-syzkaller #0
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
RIP: 0010:get_pat_info+0x216/0x270 arch/x86/mm/pat/memtype.c:1019
Code: c1 ea 03 80 3c 02 00 75 71 49 89 1e eb 8e e8 a1 ff 3e 00 0f 0b e9 97 fe ff ff 41 bc ea ff ff ff e9 77 ff ff ff e8 8a ff 3e 00 <0f> 0b 41 bc ea ff ff ff e9 65 ff ff ff 4c 89 ff e8 a5 95 7e 00 e9
RSP: 0018:ffffc900148df860 EFLAGS: 00010212
RAX: 00000000000119d4 RBX: ffff888104ddfad0 RCX: ffffc9000e85f000
RDX: 0000000000040000 RSI: ffffffff8131dac6 RDI: 0000000000000007
RBP: ffffc900148df918 R08: 0000000000000000 R09: ffffc900148df7e8
R10: 0000000000000028 R11: 0000000000000001 R12: 0000000000000028
R13: 1ffff9200291bf0c R14: 0000000000000000 R15: ffff888104ddfb20
FS:  00007f25f58a2700(0000) GS:ffff888129100000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 000000000056d0b0 CR3: 0000000112ac6000 CR4: 0000000000350ee0
Call Trace:
 untrack_pfn+0xdc/0x240 arch/x86/mm/pat/memtype.c:1121
 unmap_single_vma+0x17b/0x2b0 mm/memory.c:1500
 zap_page_range_single+0x2c6/0x440 mm/memory.c:1604
 remap_pfn_range_notrack mm/memory.c:2364 [inline]
 remap_pfn_range+0x139/0x160 mm/memory.c:2389
 io_uring_mmap+0x37b/0x480 io_uring/io_uring.c:9805
 call_mmap include/linux/fs.h:2044 [inline]
 mmap_file+0x5e/0xe0 mm/util.c:1080
 __mmap_region mm/mmap.c:1805 [inline]
 mmap_region+0xdbd/0x15f0 mm/mmap.c:2945
 do_mmap+0xcec/0x11c0 mm/mmap.c:1582
 vm_mmap_pgoff+0x199/0x200 mm/util.c:539
 ksys_mmap_pgoff+0x418/0x580 mm/mmap.c:1633
 __do_sys_mmap arch/x86/kernel/sys_x86_64.c:95 [inline]
 __se_sys_mmap arch/x86/kernel/sys_x86_64.c:86 [inline]
 __x64_sys_mmap+0xe9/0x1b0 arch/x86/kernel/sys_x86_64.c:86
 do_syscall_64+0x33/0x50 arch/x86/entry/common.c:46
 entry_SYSCALL_64_after_hwframe+0x67/0xd1
RIP: 0033:0x46a2d3
Code: 54 41 89 d4 55 48 89 fd 53 4c 89 cb 48 85 ff 74 56 49 89 d9 45 89 f8 45 89 f2 44 89 e2 4c 89 ee 48 89 ef b8 09 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 75 5b 5d 41 5c 41 5d 41 5e 41 5f c3 66 2e 0f
RSP: 002b:00007f25f58a1b58 EFLAGS: 00000206 ORIG_RAX: 0000000000000009
RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 000000000046a2d3
RDX: 0000000000000003 RSI: 0000000000120140 RDI: 0000000020ffc000
RBP: 0000000020ffc000 R08: 0000000000000004 R09: 0000000000000000
R10: 0000000000008011 R11: 0000000000000206 R12: 0000000000000003
R13: 0000000000120140 R14: 0000000000008011 R15: 0000000000000004
```

Код функции get_pat_info(), в которой происходит варнинг:
```C
static int get_pat_info(struct vm_area_struct *vma, resource_size_t *paddr,
		        pgprot_t *pgprot)
{
	unsigned long prot;

	VM_WARN_ON_ONCE(!(vma->vm_flags & VM_PAT));

	/*
	 * We need the starting PFN and cachemode used for track_pfn_remap()
	 * that covered the whole VMA. For most mappings, we can obtain that
	 * information from the page tables. For COW mappings, we might now
	 * suddenly have anon folios mapped and follow_phys() will fail.
	 *
	 * Fallback to using vma->vm_pgoff, see remap_pfn_range_notrack(), to
	 * detect the PFN. If we need the cachemode as well, we're out of luck
	 * for now and have to fail fork().
	 */
	if (!follow_phys(vma, vma->vm_start, 0, &prot, paddr)) {
		if (pgprot)
			*pgprot = __pgprot(prot);
		return 0;
	}
	if (is_cow_mapping(vma->vm_flags)) {
		if (pgprot)
			return -EINVAL;
		*paddr = (resource_size_t)vma->vm_pgoff << PAGE_SHIFT;
		return 0;
	}
	WARN_ON_ONCE(1); // Интересующий нас варнинг.
	return -EINVAL;
}
```

Код этой функции один и тот же во всех вышеперечисленных версиях ядра, так что это облегчает поиск ошибки. 

Моя задача:
 - Найти причину срабатывания этого варнинга.
 - Предложить решение этой проблемы.