
| KCONFIG NAME | 默认值 | 起始版本 | 功能简介 | 适用平台 |
| :------| :------: | :------: | :------: | :------ |
| CONFIG_SHADOW_CALL_STACK | Y | Android R | Clang支持项，通过将栈上返回值另存到x18寄存器，来避免栈上返回值被修改问题 | ARM64  | https://clang.llvm.org/docs/ShadowCallStack.html |
| CONFIG_SHADOW_CALL_STACK_VMAP | Y | Android R | 同上 | ARM64  | https://clang.llvm.org/docs/ShadowCallStack.html |
| CONFIG_ARCH_SUPPORTS_SHADOW_CALL_STACK | Y | Android R | 同上 | ARM64  | https://clang.llvm.org/docs/ShadowCallStack.html |
| CONFIG_CFI_PERMISSIVE | Y | Android R | 在编译阶段设定函数能够跳转的目标范围，任何非法跳转的控制流都将被限制 | ALL | https://source.android.google.cn/devices/tech/debug/kcfi?hl=zh-cn |
| CONFIG_CFI_CLANG | Y | Android R | 同上 | ALL | https://source.android.google.cn/devices/tech/debug/kcfi?hl=zh-cn|
| CONFIG_CFI_CLANG_SHADOW | Y | Android R | 同上 | ALL | https://source.android.google.cn/devices/tech/debug/kcfi?hl=zh-cn |
| CONFIG_SECURITY_SELINUX | Y | Android L? | Selinux整体开关 | ALL | https://source.android.google.cn/security/selinux/implement?hl=zh-cn |
| CONFIG_SECURITY_NETWORK | Y | N/A | Security Hook for socket or Network | N/A |https://www.cnblogs.com/cslunatic/p/3709356.html |
| CONFIG_SECURITY_PERF_EVENTS_RESTRICT | N | N/A | 预防通过PERF_EVENTS进行攻击，在2020年1月，kernel.org社区认为selinux可以满足安全需求，此安全策略不再android上维护。详情：e92b6ef8fc963a068ff70188fb0458b1eeaa7175 | N/A | https://patchwork.kernel.org/project/linux-hardening/patch/1469630783-32413-1-git-send-email-jeffv@google.com/ |
| CONFIG_F2FS_FS_SECURITY | Y | N/A | F2FS模块的LSM hook框架接口 | N/A | https://github.com/raspberrypi/linux/issues/2778 |
| CONFIG_EXT4_FS_SECURITY | Y | N/A | EXT4模块的LSM hook框架接口 | N/A | https://boxmatrix.info/wiki/CONFIG_EXT4_FS_SECURITY |
| CONFIG_QCOM_SECURE_BUFFER | Y | N/A |通过TZ保护缓冲区的辅助函数 | Qcom | https://patchwork.kernel.org/project/linux-arm-msm/patch/1483974609-25522-2-git-send-email-akdwived@codeaurora.org/ |
| CONFIG_ARCH_MMAP_RND_BITS | Y | N/A |  选择从mmap分配产生的vma区域基地址的随机偏移量的位数 | N/A | https://cateee.net/lkddb/web-lkddb/ARCH_MMAP_RND_BITS.html |
| CONFIG_FTRACE | N | N/A | FTRACE用户外部调试的Hook feature | N/A | https://cateee.net/lkddb/web-lkddb/FTRACE.html |
| CONFIG_STACKPROTECTOR | Y | kernel 4.18 | 堆栈金丝雀，在返回值和ESP之间假如canary，通过对canary的检测来判断返回值是否被篡改 | ALL | 
| CONFIG_STACKPROTECTOR_STRONG | Y | Kernel 4.18 | GCC通用的栈金丝雀保护功能，通过金丝雀的检查以确认栈未被修改 | ALL | https://cateee.net/lkddb/web-lkddb/FTRACE.html |
| CONFIG_HAVE_STACKPROTECTOR | Y | Kernel 4.18 | GCC通用的栈金丝雀保护功能，通过金丝雀的检查以确认栈未被修改 | ALL | https://cateee.net/lkddb/web-lkddb/FTRACE.html |
| CONFIG_STRICT_KERNEL_RWX | Y | N/A | 设置内核text段的代码为RO | N/A | 
| CONFIG_STRICT_MODULE_RWX | Y | kernel 4.11 | 内核模块数据段的内存将变为只读，非text内存将变为不可执行 | N/A |
| CONFIG_ARM64_PAN | Y | ARM8.1 | 特权禁止访问，kernel和userspace禁止访问同一段内存 | ALL | 
| CONFIG_ARM64_PAX | Not Set | ARM8.1 | 特权禁止执行，禁止内核空间和用户空间执行同一份文件，PAN的前身 | ALL | 
| CONFIG_UNMAP_KERNEL_AT_EL0 | Y | 2018年 | 针对KPTI缺陷代码修复补丁之一 | ARM64 | 
| CONFIG_HARDEN_EL2_VECTORS | N/A | kernel 4.17 | 将向量映射到固定位置，独立于 EL2 代码映射，因此向攻击者泄露 VBAR_EL2 不会泄露任何额外信息。只在受影响的 CPU 上启用 | ARM64 | 
| CONFIG_RODATA_FULL_DEFAULT_ENABLED | Y | N/A | 将 VM 区域的 r/o 权限也应用于它们的线性别名 | N/A | 
| CONFIG_ARM64_PTR_AUTH | Y | ARMv8.3 | 针对密钥对指针进行签名和身份验证的说明，可用于缓解面向返回的编程 (ROP) 和其他攻击 | N/A | 
| CONFIG_VMAP_STACK | Y | kernel 4.14 | 线程内核堆栈采用vmalloc分配，否则直接分配连续的物理页面 | N/A | 
| CONFIG_RANDOMIZE_BASE | Y | N/A | 内核地址随机化 | ALL | 
| CONFIG_THREAD_INFO_IN_TASK | Y | N/A | 开启后thread_info结构体放在task_struct结构体第一位 | ALL | 
| CONFIG_HARDEN_BRANCH_PREDICTOR | Y | kernel 4.18 | 清除内部分支预测的状态并限制某些情况下的预测逻，可以部分缓解分支预测攻击 | ARM | 
| CONFIG_BUG_ON_DATA_CORRUPTION | Y | kernel 4.10 | 检查内核内存结构中的数据污染,有效防御缓冲区溢出类漏洞 | ALL | 
| CONFIG_DEBUG_WX | Y | kernel 5.8 | 在启动的时候对W+X执行权限的映射区域产生警告，有效的发现内核在应用NX之后遗留的W+X映射区域，而这些映射都是高风险的利用区域 | ALL | 
| CONFIG_SCHED_STACK_END_CHECK | Y | kernel 3.18 | 调用schedule()时的栈溢出情况,在栈末尾存放MAGIC，调用时检查 | ALL | 
| CONFIG_SLAB_FREELIST_HARDENED | Y | kernel 3.18 | 调整了每个free时数据不会直接释放，而是在freelist缓存中进行检查后释放，能够有效缓解堆喷和double free问题 | ALL | 
| CONFIG_SLAB_FREELIST_RANDOM | Y | kernel 5.9 | 随机化slab的freelist，随机化用于创建新页的freelist为了减少对内核slab分配器的可预测性 | ALL | 
| CONFIG_FORTIFY_SOURCE | N | Android L | 检查内存拷贝类函数的目的缓冲区是否存在溢出。检测的函数包括：memcpy, mempcpy, memmove, memset, strcpy,stpcpy, strncpy, strcat, strncat,sprintf,vsprintf,snprintf,vsnprintf,gets | ALL | 
| CONFIG_HARDENED_USERCOPY | Y | kernel 4.9 | 针对copy_from/to_user缓冲区进行长度的检查，当长度检查发现有溢出的可能时，对数据进行截断，防止非法拷贝覆盖内存，破坏栈帧或堆 | ALL | 
| CONFIG_HARDENED_USERCOPY_FALLBACK | Y | kernel 4.9 | 同上，扩展功能 | ALL | 
| CONFIG_MODULE_SIG | 早期默认开启，但Android S后Google默认关闭 | N/A | 内核模块挂载时进行ko的签名校验 | ALL | 
| CONFIG_MODULE_SIG_ALL | 同上 | N/A | 同上 | ALL | 
| CONFIG_MODULE_SIG_SHA512 | 同上 | N/A | 同上，签名算法选择 | ALL | 
| CONFIG_MODULE_SIG_FORCE | 同上 | N/A | 同上，校验不通过将阻止加载，未开启时仅打印警告 | ALL | 
| CONFIG_INIT_STACK_ALL | N/A | N/A | 对栈上创建的变量进行默认初始化 | ALL | 
| CONFIG_INIT_ON_FREE_DEFAULT_ON | N/A | N/A | 待补充 | ALL | 
| CONFIG_GCC_PLUGIN_STACKLEAK | N/A | N/A | 待补充 | ALL | 
| CONFIG_ARM64_SW_TTBR0_PAN | N/A | N/A | 阻止内核直接访问用户空间，类似PAN，区分在于此方案以纯软件实现 | ALL | 
| CONFIG_SECURITY_DMESG_RESTRICT | Y | N/A | KPTR，非root权限下，kallsyms打印地址隐藏为0 | ALL | 
| CONFIG_STATIC_USERMODEHELPER | Y | N/A | 选项会强制所有的usermodehelper通过单一的二进制程序调用,避免usermodehlper接口被滥用EOP | ALL | 
| CONFIG_SECURITY_YAMA | N | kernel 3.4 | 访问权限控制类，Selinux弱化版本 | ALL | 
| CONFIG_SECURITY_WRITABLE_HOOKS | N | N/A | 待补充 | ALL | 
| CONFIG_SECURITY_LOCKDOWN_LSM | N | N/A | 通过LSM hook的方法锁定内核，阻止一些高危操作。比如加载未签名的模块，访问特殊文件/dev/port等 | ALL | 
| CONFIG_SECURITY_LOCKDOWN_LSM_EARLY | N | N/A | 同上 | ALL | 
| CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY | N | N/A | 待补充 | ALL | 
| CONFIG_SECURITY_SAFESETID | N | N/A | 待补充 | ALL | 
| CONFIG_SECURITY_LOADPIN | N | 2016年 | 用来确保所有内核加载的文件都是没有被篡改，利用新的内核文件加载机制去中断所有尝试加载进内核的文件，包括加载内核模块，读取固件，加载镜像等等，然后会把需要加载的文件与启动之后第一次加载使用的文件作比较，如果没有匹配则被阻止 | ALL | 
| CONFIG_DEBUG_LIST | Y | kernel 2.6 | 用于调试链表操作，开启之后会在链表操作中执行额外检查 | ALL | 
| CONFIG_DEBUG_SG | N | N/A |调试SG表的操作，开启之后会检查scatter-gather表，这个能帮助发现那些不能正确初始化SG表的驱动 | ALL | 
| CONFIG_DEBUG_CREDENTIALS | N | N/A | 调试凭证管理，开启之后对凭证管理做调试检查，追踪task_struct到给定凭证结构的指针数量没有超过凭证结构的使用上限 | ALL | 
| CONFIG_DEBUG_NOTIFIERS | N | N/A | 检测通知调用链的合法性，能确保模块正确的从通知链中注销 | ALL | 
| CONFIG_DEBUG_VIRTUAL | N | N/A | 调试虚拟内存转换，开启之后在内存转换时会合法性检查 | ALL | 
| CONFIG_SHUFFLE_PAGE_ALLOCATOR | Y | kernel 5.2 | 页分配器随机分配内存，搭配SLAB_FREELIST_RANDOM让整个分配过程更加难以预测 | ALL | 
| CONFIG_DEFAULT_MMAP_MIN_ADDR | 4096 | kernel 5.2 | 指定mmap产生的最小虚拟地址，因为地址空间过小可能会配合其他漏洞做进一步的利用 | ALL | 
| CONFIG_INIT_STACK_ALL_ZERO | Y | kernel 5.15 |新分配的栈上的所有数据都初始化为0，消除了所有的未初始化栈变量的漏洞利用以及信息泄露 | ALL | 
| CONFIG_PAGE_POISONING | Y | kernel 4.6 |在释放的页上做内存数据擦除工作。在free_pages()之后填入特殊的数据，在分配页之前会验证这个数据，以达到防御use after free的效果 | ALL | 
| CONFIG_F2FS_CHECK_FS | Y | kernel 3.13 |在Kernel启动时以BUG_ON检查F2FS文件系统一致性的 BUG_ON | ALL | 
| CONFIG_ARCH_MMAP_RND_BITS_MIN | 18 | kernel 4.5 | 选择mmap 分配产生的 vma 区域基址的随机偏移量.此值将受体系结构的最小值的限制 | ALL | 
| CONFIG_ARCH_MMAP_RND_BITS_MAX | 24 | kernel 4.5 | 选择mmap 分配产生的 vma 区域基址的随机偏移量.此值将受体系结构的最大值的限制 | ALL | 
| CONFIG_ARCH_HAS_STRICT_KERNEL_RWX | Y | kernel 4.11 | 内核内存保护 | ALL | 
| CONFIG_PANIC_ON_DATA_CORRUPTION | Y | kernel 4.10 | 内核在检查有效性时遇到内核内存结构中的数据损坏时应该出现 PANIC.调试用 | ALL | 
| CONFIG_IP_NF_SECURITY | Y | kernel 2.6 | 增加一个安全的table到iptables，用于控制MAC（强制访问控制）策略 | ALL | 
| CONFIG_IP6_NF_SECURITY | Not Set | kernel 2.6 | 同上，仅是IP4/6的差别 | ALL | 
| CONFIG_EROFS_FS_SECURITY | Y | Android R | EROFS文件系统是华为研的一项提升手机随机读写性能的系统及应用编译和运行机制，全称为Extendable Read-Only File System，用作 erofs 安全标签的控制开关功能 | ALL | 
| CONFIG_SECURITY_PATH | Y | kernel 4.1 | 这为基于路径名的访问控制启用了security hook | ALL | 
| CONFIG_LSM_MMAP_MIN_ADDR | 32768 | kernel 2.6 | 防止用户空间分配的低虚拟内存部分。阻止用户写入低页面有助于减少内核 NULL 指针错误的影响 | ALL | 
| CONFIG_SECURITY_SELINUX_AVC_STATS | Y | kernel 2.6 | 将访问向量缓存统计信息收集到 /sys/fs/selinux/avc/cache_stats，可以通过 avcstat 等工具对其进行监控。 | ALL | 
| CONFIG_SECURITY_SELINUX_SIDTAB_HASH_BITS | 9 | kernel 5.6 | 将 sidtab 哈希表中使用的桶数设置为 2^SECURITY_SELINUX_SIDTAB_HASH_BITS，减少HASH冲突的风险 | ALL | 
| CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE | 0 | kernel 2.6 | 设置“checkreqprot”标志的默认值，该标志确定 SELinux 是检查应用程序请求的保护还是内核将应用的保护（包括 read-implies-exec 的任何隐含执行）用于 mmap 和 mprotect 调用 | ALL | 
| CONFIG_INTEGRITY | Y | kernel 3.18 | 项启用完整性子系统，该子系统由许多不同的组件组成，包括完整性测量架构 (IMA)、扩展验证模块 (EVM)、IMA 评估扩展、数字签名验证扩展和审计测量日志支持。 | ALL | 
| CONFIG_INTEGRITY_AUDIT | Y | kernel 3.11 | 同上子选项，除了启用完整性审计支持外，此选项还添加了一个内核参数“integrity_audit”，它控制完整性审计消息的级别。0 - 基本完整性审计消息（默认） 1 - 附加完整性审计消息 | ALL | 
| CONFIG_CC_HAS_AUTO_VAR_INIT_PATTERN | Y | kernel 5.15 | 使用特定的调试值初始化堆栈上的所有内容（包括填充）。这旨在消除所有类别的未初始化堆栈变量漏洞利用和信息暴露，甚至是被警告未初始化的变量。特定情况的；64 位上的 Clang 对所有类型和填充使用 0xAA 重复，除了使用 0xFF 重复 (-NaN) 的浮点和双精度。32 位 Clang 对所有类型和填充使用 0xFF 重复。 | ALL | 
| CONFIG_INIT_ON_ALLOC_DEFAULT_ON | Y | kernel 5.3 | 所有page allocator和slab allocator内存在分配时都会清零，消除了多种“未初始化的堆内存”缺陷，尤其是堆内容暴露 | ALL | 
| CONFIG_INIT_STACK_NONE | Not Set | kernel 5.15 | 禁用自动堆栈变量初始化。这使得内核容易受到未初始化堆栈变量攻击和信息暴露的标准类的攻击 | ALL | 
| 内核安全属性 | | | | |
| unprivileged_userfaultfd | 1 | N/A | 标志设置为1时，允许低权限用户使用，设置为0时禁止低权限用户使用，只有高权限用户能够调用。userfaultfd是Linux中处理内存页错误的机制，缺页发生的位置将会处于暂停状态，这会导致一些条件竞争漏洞的利用 | ALL |
| slab_nomerge | N/A | N/A | 选项开启之后会禁止相近大小的slab合并，这个能有效防御一部分堆溢出的攻击，如果slab开启合并，被堆溢出篡改的slab块合并之后通常可以扩大攻击范围，让整个攻击危害更大 | N/A |
| Manual usage of nospec barriers | N/A | N/A | 内核提供的通用API确保在分支预测的情况下边界检查是符合预期的。主要是两个API nospec_ptr(ptr, lo, hi)和nospec_array_ptr(arr, idx, sz)，第一个API会限制ptr在lo和hi的范围内，防止指针越界；第二个API会限制idx只有在[0,sz)的范围中才能获得arr[idx]的数据。 | N/A |
| init_on_free/init_on_alloc | N/A | N/A | 阻止信息泄露和依赖于未初始化值的控制流漏洞。开启两个选项之一能保证页分配器返回的内存和SL[A|U]B是会被初始化为0 | N/A |
| __ro_after_init | N/A | N/A | 在内核初始化完成之后把这些内存区域标记为只读，减小内核关键变量的攻击面 | N/A |
