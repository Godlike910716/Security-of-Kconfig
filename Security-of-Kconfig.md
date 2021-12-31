
| KCONFIG NAME | DesiredVal | VERSION(Android) | EFFECT | PLATFROM | LINK |
| :------| :------: | :------: | :------: | :------ | :------ |
| CONFIG_SHADOW_CALL_STACK | Y | Android R | TEST | ARM64 Only | https://clang.llvm.org/docs/ShadowCallStack.html |
| CONFIG_SHADOW_CALL_STACK_VMAP | Y | Android R | TEST | ARM64 Only | https://clang.llvm.org/docs/ShadowCallStack.html |
| CONFIG_ARCH_SUPPORTS_SHADOW_CALL_STACK | Y | Android R | TEST | ARM64 Only | https://clang.llvm.org/docs/ShadowCallStack.html |
| CONFIG_CFI_PERMISSIVE | Y | Android R | TEST | N/A | https://source.android.google.cn/devices/tech/debug/kcfi?hl=zh-cn |
| CONFIG_CFI_CLANG | Y | Android R | TEST | N/A | https://source.android.google.cn/devices/tech/debug/kcfi?hl=zh-cn|
| CONFIG_CFI_CLANG_SHADOW | Y | Android R | TEST | N/A | https://source.android.google.cn/devices/tech/debug/kcfi?hl=zh-cn |
| CONFIG_SECURITY_SELINUX | Y | N/A | TEST | N/A | https://source.android.google.cn/security/selinux/implement?hl=zh-cn |
| CONFIG_SECURITY_NETWORK | Y | N/A | Security Hook for socket or Network | N/A |https://www.cnblogs.com/cslunatic/p/3709356.html |
| CONFIG_SECURITY_PERF_EVENTS_RESTRICT | Y | N/A | Reduce the attack surface of PERF_EVENTS | N/A | https://patchwork.kernel.org/project/linux-hardening/patch/1469630783-32413-1-git-send-email-jeffv@google.com/ |
| CONFIG_F2FS_FS_SECURITY | Y | N/A | LSM safety interface for F2FS module | N/A | https://github.com/raspberrypi/linux/issues/2778 |
| CONFIG_EXT4_FS_SECURITY | Y | N/A | LSM safety interface for EXT4 module | N/A | https://boxmatrix.info/wiki/CONFIG_EXT4_FS_SECURITY |
| CONFIG_QCOM_SECURE_BUFFER | Y | N/A |Helper functions for securing buffers through TZ | Qcom | https://patchwork.kernel.org/project/linux-arm-msm/patch/1483974609-25522-2-git-send-email-akdwived@codeaurora.org/ |
| CONFIG_ARCH_MMAP_RND_BITS | Y | N/A |  select the number of bits to use to determine the random offset to the base address of vma regions resulting from mmap allocations | N/A | https://cateee.net/lkddb/web-lkddb/ARCH_MMAP_RND_BITS.html |
| CONFIG_FTRACE | N | N/A | ftrace provides external interfaces for hook debugging through debugfs | N/A | https://cateee.net/lkddb/web-lkddb/FTRACE.html |
CONFIG_STACKPROTECTOR_STRONG
CONFIG_STRICT_KERNEL_RWX
CONFIG_STRICT_MODULE_RWX
CONFIG_ARM64_PAN
CONFIG_UNMAP_KERNEL_AT_EL0
CONFIG_HARDEN_EL2_VECTORS
CONFIG_RODATA_FULL_DEFAULT_ENABLED
CONFIG_ARM64_PTR_AUTH
CONFIG_VMAP_STACK
CONFIG_RANDOMIZE_BASE
CONFIG_THREAD_INFO_IN_TASK
CONFIG_HARDEN_BRANCH_PREDICTOR
CONFIG_BUG_ON_DATA_CORRUPTION
CONFIG_DEBUG_WX
CONFIG_SCHED_STACK_END_CHECK
CONFIG_SLAB_FREELIST_HARDENED
CONFIG_SLAB_FREELIST_RANDOM
CONFIG_FORTIFY_SOURCE
CONFIG_HARDENED_USERCOPY
CONFIG_HARDENED_USERCOPY_FALLBACK
CONFIG_MODULE_SIG
CONFIG_MODULE_SIG_ALL
CONFIG_MODULE_SIG_SHA512
CONFIG_MODULE_SIG_FORCE
CONFIG_INIT_STACK_ALL
CONFIG_INIT_ON_FREE_DEFAULT_ON
CONFIG_GCC_PLUGIN_STACKLEAK
CONFIG_ARM64_SW_TTBR0_PAN
CONFIG_SECURITY_DMESG_RESTRICT
CONFIG_STATIC_USERMODEHELPER
CONFIG_SECURITY_YAMA
CONFIG_SECURITY_WRITABLE_HOOKS
CONFIG_SECURITY_LOCKDOWN_LSM
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY
CONFIG_SECURITY_SAFESETID
CONFIG_SECURITY_LOADPIN
CONFIG_SECURITY_LOADPIN_ENFORCE




| CONFIG_F2FS_FS_SECURITY | Y | N/A | LSM safety interface for F2FS module | N/A | https://github.com/raspberrypi/linux/issues/2778 |
