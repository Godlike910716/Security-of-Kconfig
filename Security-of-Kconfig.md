
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
| CONFIG_SECURITY_PERF_EVENTS_RESTRICT | Y | N/A | 预防通过PERF_EVENTS进行攻击 | N/A | https://patchwork.kernel.org/project/linux-hardening/patch/1469630783-32413-1-git-send-email-jeffv@google.com/ |
| CONFIG_F2FS_FS_SECURITY | Y | N/A | F2FS模块的LSM hook框架接口 | N/A | https://github.com/raspberrypi/linux/issues/2778 |
| CONFIG_EXT4_FS_SECURITY | Y | N/A | EXT4模块的LSM hook框架接口 | N/A | https://boxmatrix.info/wiki/CONFIG_EXT4_FS_SECURITY |
| CONFIG_QCOM_SECURE_BUFFER | Y | N/A |通过TZ保护缓冲区的辅助函数 | Qcom | https://patchwork.kernel.org/project/linux-arm-msm/patch/1483974609-25522-2-git-send-email-akdwived@codeaurora.org/ |
| CONFIG_ARCH_MMAP_RND_BITS | Y | N/A |  选择从mmap分配产生的vma区域基地址的随机偏移量的位数 | N/A | https://cateee.net/lkddb/web-lkddb/ARCH_MMAP_RND_BITS.html |
| CONFIG_FTRACE | N | N/A | FTRACE用户外部调试的Hook feature | N/A | https://cateee.net/lkddb/web-lkddb/FTRACE.html |
| CONFIG_STACKPROTECTOR_STRONG | Y | Kernel 4.+ | GCC通用的栈金丝雀保护功能，通过金丝雀的检查以确认栈未被修改 | ALL | https://cateee.net/lkddb/web-lkddb/FTRACE.html |
| CONFIG_STRICT_KERNEL_RWX | Y | N/A | 设置内核text段的代码为RO | N/A | 
| CONFIG_STRICT_MODULE_RWX | Y | kernel 4.11 | text模块和rodata的内存将变为只读，非text内存将变为不可执行 | N/A |
| CONFIG_ARM64_PAN | Y | ARM8.1 | 特权禁止访问，kernel和userspace禁止访问同一段内存 | ALL | 
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
| CONFIG_SECURITY_LOCKDOWN_LSM | N | N/A | 待补充 | ALL | 
| CONFIG_SECURITY_LOCKDOWN_LSM_EARLY | N | N/A | 待补充 | ALL | 
| CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY | N | N/A | 待补充 | ALL | 
| CONFIG_SECURITY_SAFESETID | N | N/A | 待补充 | ALL | 
| CONFIG_SECURITY_LOADPIN | N | 2016年 | 用来确保所有内核加载的文件都是没有被篡改，利用新的内核文件加载机制去中断所有尝试加载进内核的文件，包括加载内核模块，读取固件，加载镜像等等，然后会把需要加载的文件与启动之后第一次加载使用的文件作比较，如果没有匹配则被阻止 | ALL | 
| CONFIG_SECURITY_LOADPIN_ENFORCE | N | N/A |同上 | ALL | 
