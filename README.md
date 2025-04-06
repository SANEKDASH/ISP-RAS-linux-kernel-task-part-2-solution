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

Так же syzkaller'ом были сгенерированы репродьюсеры этого варнинга, то есть программы, при выполнении которых __может__ произойти наша проблема.
На код репродьюсеров можно посмотреть [здесь](https://github.com/SANEKDASH/ISP-RAS-linux-kernel-task-part-2-solution/tree/main/reproducers).

Моя задача на данный момент - найти причину, по которой срабатывает этот варнинг.

## Анализ варнинга

Код, который объединяет их всех:
```C
int main(void)
{
  ...

  syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);

  ...

  return 0;
}
```

На основании этого мы можем сделать вывод, что имеем дело с системным вызовом __mmap__.

```
void *mmap(void *addr, size_t length, int prot, int flags,
           int fd, off_t offset);

```

Зная, на каких версиях происходит варнинг и при выполнении каких программ он может произойти,
мне пришла в голову идея запустить ядро на виртуальной машине и попытаться самому отловить баг.

Я выбрал версию 5.10.233.

Сначала я скачал запакованный исходный код ядра, находящийся по [этой ссылке](https://git.linuxtesting.ru/pub/scm/linux/kernel/git/lvc/linux-stable.git/tag/?h=v5.10.233-lvc41)

Далее, заменив дефолтный конфигурационный файл ядра, на [тот, что шел в комплекте с даннымы от syzkaller'а](https://github.com/SANEKDASH/ISP-RAS-linux-kernel-task-part-2-solution/blob/main/reproducers/5.10.233/kernel-config.0),
я скомпилировал ядро.

Затем в соответствии с [документацией syzkaller](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md)
я получил образ системы и ssh ключ для доступа к ssh серверу, который будет запущен qemu.

На этом этапе запустил ядро на виртуальной машине qemu с помощью команды:
```bash
 qemu-system-x86_64 \
        -s \ # запускает gdb-сервер на порту 1234               
        -S \ #  останавливает исполнение виртуальной машины на этапе загрузки, до момента подключения к ней через gdb 
        -append “nokaslr” \
        -m 2G \
        -smp 2 \
        -kernel linux-kernel/arch/x86/boot/bzImage \
        -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
        -drive file=syzkaller/bullseye.img,format=raw \
        -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
        -net nic,model=e1000 \
        -enable-kvm \
        -nographic \
        -pidfile vm.pid \
        2>&1 | tee vm.log
```
Наконец подключился с помощью gdb к виртуальной машине с помощью следующих команд:
```bash
$ gdb vmlinux
target remote:1234
```
## Отладка в gdb
Закинув несколько репродьюсеров на виртуальную машину я начал пытаться отлавливать этот варнинг.

Чтобы это сделать, я поставил breakpoint на место варнинга в функции `get_pat_info()` и начал запускать репродьюсеров.

Посидев так некоторое время, я ни разу не увидел, что этот варнинг срабатывает, но, в то же время,
по информации от syzkaller'a мы знаем, что он происходит.

Возможно, если бы я запустил репродьюсера, который в цикле делает __fault injection__ и несколько системных вызовов,
и прождал бы так несколько часов, что-нибудь и словил бы.

Но, внезапно мне пришла идея погуглить эту ошибку.
В syzbot'е о ней уже были [сообщения](https://syzkaller.appspot.com/bug?extid=16b1da89309a06cd0e3a).
Я решил попытать удачу с [этим](https://syzkaller.appspot.com/text?tag=ReproC&x=1704ae30580000) репродьюсером и у меня получилось:
```
[   68.907788] FAULT_INJECTION: forcing a failure.                                                                   
[   68.907788] name fail_page_alloc, interval 1, probability 0, space 0, times 1                                      
[   68.909441] CPU: 0 PID: 897 Comm: a.out Tainted: G        W         5.10.233 #6                                   
[   68.909994] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014                        
[   68.910637] Call Trace:                                                                                            
[   68.910844]  dump_stack+0x107/0x167  
[   68.911116]  should_fail.cold+0x5/0xa                                                                             
[   68.911408]  __alloc_pages_nodemask+0x189/0x670                                                                   
[   68.911755]  ? __alloc_pages_slowpath.constprop.0+0x22e0/0x22e0                                                   
[   68.912222]  ? walk_system_ram_range+0x15d/0x1c0                                                                   
[   68.912599]  alloc_pages_current+0x191/0x2a0                                                                       
[   68.912939]  pte_alloc_one+0x16/0x1a0                                                                             
[   68.913250]  __pte_alloc+0x1d/0x2a0                                                                                
[   68.913530]  remap_pfn_range_notrack+0x78b/0xc60                                                                   
[   68.913895]  ? apply_to_existing_page_range+0x40/0x40                                                              
[   68.914285]  ? kmem_cache_alloc_trace+0x15b/0x2f0                                                                
[   68.914707]  remap_pfn_range+0xc6/0x140                                                                        
[   68.915000]  ? remap_pfn_range_notrack+0xc60/0xc60                                                                
[   68.915383]  usbdev_mmap+0x417/0x800                                                                            
[   68.915673]  ? usbdev_vm_close+0x40/0x40                                                                       
[   68.916005]  ? kmem_cache_alloc+0x2b0/0x2f0                                                                      
[   68.916341]  mmap_file+0x5e/0xe0                                                                                   
[   68.916614]  mmap_region+0xc28/0x1420                                                                             
[   68.916912]  do_mmap+0xc9d/0x1150                                                                                
[   68.917180]  vm_mmap_pgoff+0x199/0x200                                                                            
[   68.917485]  ? randomize_page+0xb0/0xb0                                                                          
[   68.917797]  ksys_mmap_pgoff+0x418/0x580                                                                          
[   68.918111]  ? find_mergeable_anon_vma+0x240/0x240                                                                 
[   68.918495]  ? lockdep_hardirqs_on_prepare+0x277/0x3e0                                                             
[   68.918924]  ? syscall_enter_from_user_mode+0x1d/0x50                                                             
[   68.919346]  do_syscall_64+0x33/0x40                                                                               
[   68.919640]  entry_SYSCALL_64_after_hwframe+0x67/0xd1                                                              
[   68.920049] RIP: 0033:0x7f19916b8fc9                                                                               
[   68.920348] Code: 00 c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 44 00 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 8
[   68.921841] RSP: 002b:00007ffca141ab38 EFLAGS: 00000216 ORIG_RAX: 0000000000000009                                
[   68.922466] RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f19916b8fc9                                     
[   68.923038] RDX: 0000000000000000 RSI: 0000000000003000 RDI: 0000000020ff6000                                     
[   68.923608] RBP: 00007ffca141ab60 R08: 0000000000000003 R09: 0000000000000000                                     
[   68.924170] R10: 0000000000000013 R11: 0000000000000216 R12: 00005558ade3d300                                      
[   68.924740] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000                                      
[   68.928244] ------------[ cut here ]------------                                                                   
[   68.930101] WARNING: CPU: 0 PID: 897 at arch/x86/mm/pat/memtype.c:1019 get_pat_info+0x216/0x270                    
[   68.932698] Modules linked in:                                                                                     
[   68.933657] CPU: 0 PID: 897 Comm: a.out Tainted: G        W         5.10.233 #6                                    
[   68.935741] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014                        
[   68.938179] RIP: 0010:get_pat_info+0x216/0x270                                                                    
[   68.939347] Code: c1 ea 03 80 3c 02 00 75 71 49 89 1e eb 8e e8 b1 b2 3e 00 0f 0b e9 97 fe ff ff 41 bc ea ff ff ff 9
[   68.944537] RSP: 0018:ffffc900035ff6e0 EFLAGS: 00010293                                                            
[   68.946076] RAX: 0000000000000000 RBX: ffff8880570d6a50 RCX: ffffffff8131704c                                      
[   68.948085] RDX: ffff8880592f8000 RSI: ffffffff81317146 RDI: 0000000000000007                                     
[   68.950047] RBP: ffffc900035ff798 R08: 0000000000000000 R09: ffffc900035ff668                                     
[   68.952036] R10: 0000000000000020 R11: 0000000000000001 R12: 0000000000000000                                      
[   68.953942] R13: 1ffff920006bfedc R14: 0000000000000000 R15: ffff8880570d6aa0                                      
[   68.955844] FS:  00007f1991799640(0000) GS:ffff88802d000000(0000) knlGS:0000000000000000                           
[   68.957973] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033                                                     
[   68.959581] CR2: 0000000020000000 CR3: 000000004c86a000 CR4: 00000000000006f0                                      
[   68.961504] Call Trace:                                                                                           
[   68.962226]  ? __warn+0xe2/0x1f0                                                                                
[   68.963152]  ? get_pat_info+0x216/0x270                                                                         
[   68.964232]  ? report_bug+0x1c5/0x210                                                                          
[   68.965252]  ? handle_bug+0x3c/0x70  
[   68.967310]  ? asm_exc_invalid_op+0x12/0x20                                                      
[   68.968447]  ? get_pat_info+0x11c/0x270                                                                           
[   68.969471]  ? get_pat_info+0x216/0x270                                                                          
[   68.970546]  ? get_pat_info+0x216/0x270                                                                         
[   68.971614]  ? pgprot_writethrough+0xc0/0xc0                                                                   
[   68.972838]  ? untrack_pfn+0xc3/0x240                                                                            
[   68.973893]  untrack_pfn+0xdc/0x240                                                                               
[   68.974837]  ? track_pfn_insert+0x150/0x150                                                                       
[   68.976856]  ? zap_page_range_single+0x28d/0x430                                                                   
[   68.977947]  ? lock_downgrade+0x6d0/0x6d0                                                                       
[   68.978930]  ? dump_stack+0x15a/0x167                                                                          
[   68.979771]  unmap_single_vma+0x172/0x2a0                                                                       
[   68.980709]  zap_page_range_single+0x2bd/0x430                                                                 
[   68.981719]  ? unmap_single_vma+0x2a0/0x2a0                                                                    
[   68.982671]  ? __alloc_pages_slowpath.constprop.0+0x22e0/0x22e0                                                  
[   68.983939]  ? walk_system_ram_range+0x15d/0x1c0                                                                
[   68.984949]  ? alloc_pages_current+0x199/0x2a0                                                                  
[   68.985893]  ? pte_alloc_one+0x8e/0x1a0                                                                           
[   68.986774]  remap_pfn_range_notrack+0x9af/0xc60                                                                 
[   68.987974]  ? apply_to_existing_page_range+0x40/0x40                                                             
[   68.989018]  ? kmem_cache_alloc_trace+0x15b/0x2f0                                                                
[   68.989973]  remap_pfn_range+0xc6/0x140                                                                            
[   68.990709]  ? remap_pfn_range_notrack+0xc60/0xc60                                                                
[   68.991669]  usbdev_mmap+0x417/0x800                                                                              
[   68.992353]  ? usbdev_vm_close+0x40/0x40                                                                          
[   68.992975]  ? kmem_cache_alloc+0x2b0/0x2f0                                                                        
[   68.993574]  mmap_file+0x5e/0xe0                                                                                   
[   68.994066]  mmap_region+0xc28/0x1420                                                                           
[   68.994627]  do_mmap+0xc9d/0x1150                                                                                 
[   68.995174]  vm_mmap_pgoff+0x199/0x200                                                                           
[   68.995746]  ? randomize_page+0xb0/0xb0                                                                        
[   68.996313]  ksys_mmap_pgoff+0x418/0x580                                                                          
[   68.996870]  ? find_mergeable_anon_vma+0x240/0x240                                                                
[   68.997539]  ? lockdep_hardirqs_on_prepare+0x277/0x3e0                                                             
[   68.998247]  ? syscall_enter_from_user_mode+0x1d/0x50                                                              
[   68.998947]  do_syscall_64+0x33/0x40                                                                              
[   68.999430]  entry_SYSCALL_64_after_hwframe+0x67/0xd1                                                             
[   69.000139] RIP: 0033:0x7f19916b8fc9                                                                               
[   69.000642] Code: 00 c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 44 00 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 8
[   69.004502] RSP: 002b:00007ffca141ab38 EFLAGS: 00000216 ORIG_RAX: 0000000000000009                                
[   69.005677] RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f19916b8fc9                                     
[   69.006614] RDX: 0000000000000000 RSI: 0000000000003000 RDI: 0000000020ff6000                                     
[   69.007556] RBP: 00007ffca141ab60 R08: 0000000000000003 R09: 0000000000000000                                     
[   69.008197] R10: 0000000000000013 R11: 0000000000000216 R12: 00005558ade3d300                                     
[   69.008752] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000                                     
[   69.009287] irq event stamp: 40017                                                                                 
[   69.009543] hardirqs last  enabled at (40025): [<ffffffff8157c250>] console_unlock+0x940/0xb50                    
[   69.010219] hardirqs last disabled at (40034): [<ffffffff8157c13e>] console_unlock+0x82e/0xb50                    
[   69.010964] softirqs last  enabled at (39976): [<ffffffff87e010d2>] asm_call_irq_on_stack+0x12/0x20                
[   69.011736] softirqs last disabled at (39967): [<ffffffff87e010d2>] asm_call_irq_on_stack+0x12/0x20               
[   69.012517] ---[ end trace 89869ab599b58388 ]---    
```

Как мне кажется, эта трасса имеет больше смысла, тем те, что были изначально.

Посидев в gdb какое-то время, я так и не понял, в чем заключается ошибка реализации.
Это натолкнуло меня на мысль, что здесь есть ошибка в идейном плане. 
И я начал разбираться в этой теме.

## Анализ обсуждения

В этой трассе есть проблема о которой я узнал из [обсуждения](https://lore.kernel.org/all/262aa19c-59fe-420a-aeae-0b1866a3e36b@redhat.com/T/#u).
Изобразим трассу следующим образом:
```
remap_pfn_range
  remap_pfn_range_notrack
    remap_pfn_range_internal
      remap_p4d_range	// fault injection happens here
    zap_page_range_single
      unmap_single_vma
        untrack_pfn
          get_pat_info
            WARN_ON_ONCE(1);
```
Из прочитанного я понял следующее: untrack_pfn() не должен вызываться в этой функции, так как
драйвера утройств должны начинать отслеживать pfn в mmap() и переставать в munmap().

По этому поводу был выпущен [коммит](https://lore.kernel.org/all/20240712144244.3090089-1-peterx@redhat.com/T/#u).

## Итог
Судя по всему мы имеем дело с устаревшей проблемой.