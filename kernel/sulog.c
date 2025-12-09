#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/timekeeping.h>  // 新增兼容 sys_tz
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/crc32.h>
#include <linux/fcntl.h>        // 新增filp_open 所需
#include <linux/file.h>         // 新增文件操作所需

// 兼容宏定义（根据内核版本适配）
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#define timespec64 timespec
#define ktime_get_real_ts64(ts) getnstimeofday(ts)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#define strscpy(dst, src, len) strlcpy(dst, src, len)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#define WQ_HIGHPRI 0  // 4.4 以下无 WQ_HIGHPRI，置空
#endif

// 自定义兼容宏
#ifndef SULOG_PATH
#define SULOG_PATH "/data/ksu/sulog.log"
#endif

#ifndef SULOG_COMM_LEN
#define SULOG_COMM_LEN 256
#endif

#ifndef SULOG_ENTRY_MAX_LEN
#define SULOG_ENTRY_MAX_LEN 1024
#endif

#ifndef SULOG_MAX_SIZE
#define SULOG_MAX_SIZE (1024 * 1024 * 10)  // 10MB
#endif

#ifndef DEDUP_SECS
#define DEDUP_SECS 5
#endif

#define DEDUP_SU_GRANT 1
#define DEDUP_SU_ATTEMPT 2
#define DEDUP_PERM_CHECK 3
#define DEDUP_MANAGER_OP 4
#define DEDUP_SYSCALL 5

// 结构体定义（补充缺失的定义）
struct dedup_key {
    u32 crc;
    uid_t uid;
    u8 type;
};

struct dedup_entry {
    struct dedup_key key;
    u64 ts_ns;
};

struct sulog_entry {
    struct list_head list;
    char content[SULOG_ENTRY_MAX_LEN];
};

// 兼容层替换未定义的 ksu_*_compat 函数
static struct file *ksu_filp_open_compat(const char *path, int flags, umode_t mode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    return filp_open(path, flags, mode);
#else
    // 4.4/4.9 内核 filp_open 接口
    return filp_open(path, flags, mode);
#endif
}

static ssize_t ksu_kernel_write_compat(struct file *file, const void *buf, size_t count, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    return kernel_write(file, buf, count, pos);
#else
    // 4.4/4.9 内核手动实现 write
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);
    ssize_t ret = vfs_write(file, (const char __user *)buf, count, pos);
    set_fs(old_fs);
    return ret;
#endif
}

// 兼容 get_cmdline 函数
static int get_cmdline_compat(struct task_struct *task, char *buf, size_t buf_len)
{
    if (!task || !buf || buf_len == 0)
        return -EINVAL;

    // 4.4/4.9 内核读取 cmdline
    unsigned int len = 0;
    char *page = (char *)__get_free_page(GFP_KERNEL);
    if (!page)
        return -ENOMEM;

    if (task->mm) {
        len = access_process_vm(task, task->mm->arg_start, page, min(buf_len - 1, PAGE_SIZE), 0);
        if (len > 0) {
            // 替换空字符为空格
            for (unsigned int i = 0; i < len; i++) {
                if (page[i] == '\0')
                    page[i] = ' ';
            }
            strlcpy(buf, page, min(len + 1, buf_len));
        }
    }

    free_page((unsigned long)page);
    return len > 0 ? len : -EINVAL;
}

// 计算去重哈希
static u32 dedup_calc_hash(const char *content, size_t len)
{
    return crc32_le(0, content, len);
}

#include "klog.h"
#include "kernel_compat.h"
#include "sulog.h"
#include "ksu.h"

#if __SULOG_GATE
struct dedup_entry dedup_tbl[SULOG_COMM_LEN];
DEFINE_SPINLOCK(dedup_lock);
static LIST_HEAD(sulog_queue);
static DEFINE_MUTEX(sulog_mutex);
static struct workqueue_struct *sulog_workqueue;
static struct work_struct sulog_work;
static bool sulog_enabled = true;

static void get_timestamp(char *buf, size_t len)
{
    struct timespec64 ts;
    struct tm tm;

    // 兼容老内核的时间获取
    ktime_get_real_ts64(&ts);

    // 处理时区（sys_tz 需引入 linux/timekeeping.h）
    time64_to_tm(ts.tv_sec - sys_tz.tz_minuteswest * 60, 0, &tm);

    snprintf(buf, len,
         "%04ld-%02d-%02d %02d:%02d:%02d",
         tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
         tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void ksu_get_cmdline(char *full_comm, const char *comm, size_t buf_len)
{
    char *kbuf;

    if (!full_comm || buf_len <= 0)
        return;

    if (comm && strlen(comm) > 0) {
        strscpy(full_comm, comm, buf_len);
    } else {
        kbuf = kmalloc(buf_len, GFP_ATOMIC);
        if (!kbuf) {
            pr_err("sulog: failed to allocate memory for kbuf\n");
            return;
        }

        // 替换为兼容的 get_cmdline_compat
        int n = get_cmdline_compat(current, kbuf, buf_len);

        if (n <= 0) {
            strscpy(full_comm, current->comm, buf_len);
        } else {
            for (int i = 0; i < n; i++) {
                if (kbuf[i] == '\0') kbuf[i] = ' ';
            }
            kbuf[n < buf_len ? n : buf_len - 1] = '\0';
            strscpy(full_comm, kbuf, buf_len);
        }

        kfree(kbuf);
    }
}

static bool dedup_should_print(uid_t uid, u8 type,
                               const char *content, size_t len)
{
    struct dedup_key key = {
        .crc  = dedup_calc_hash(content, len),
        .uid  = uid,
        .type = type,
    };
    u64 now = ktime_get_ns();
    u64 delta_ns = DEDUP_SECS * NSEC_PER_SEC;

    u32 idx = key.crc & (SULOG_COMM_LEN - 1);
    spin_lock(&dedup_lock);

    struct dedup_entry *e = &dedup_tbl[idx];
    if (e->key.crc == key.crc &&
        e->key.uid == key.uid &&
        e->key.type == key.type &&
        (now - e->ts_ns) < delta_ns) {
        spin_unlock(&dedup_lock);
        return false;
    }

    e->key = key;
    e->ts_ns = now;
    spin_unlock(&dedup_lock);
    return true;
}

static void sulog_work_handler(struct work_struct *work)
{
    struct file *fp;
    struct sulog_entry *entry, *tmp;
    LIST_HEAD(local_queue);
    loff_t pos = 0;
    
    mutex_lock(&sulog_mutex);
    list_splice_init(&sulog_queue, &local_queue);
    mutex_unlock(&sulog_mutex);
    
    if (list_empty(&local_queue))
        return;
    
    fp = ksu_filp_open_compat(SULOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0640);
    if (IS_ERR(fp)) {
        pr_err("sulog: failed to open log file: %ld\n", PTR_ERR(fp));
        goto cleanup;
    }
    
    if (fp->f_inode->i_size > SULOG_MAX_SIZE) {
        pr_info("sulog: log file exceeds maximum size, clearing...\n");
        if (vfs_truncate(&fp->f_path, 0)) {
            pr_err("sulog: failed to truncate log file\n");
        }
        pos = 0;
    } else {
        pos = fp->f_inode->i_size;
    }
    
    list_for_each_entry(entry, &local_queue, list) {
        ksu_kernel_write_compat(fp, entry->content, strlen(entry->content), &pos);
    }
    
    vfs_fsync(fp, 0);
    filp_close(fp, NULL);  // 4.4 内核 filp_close 第二个参数为 NULL
    
cleanup:
    list_for_each_entry_safe(entry, tmp, &local_queue, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

static void sulog_add_entry(const char *content)
{
    struct sulog_entry *entry;
    
    if (!sulog_enabled || !content)
        return;
    
    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        pr_err("sulog: failed to allocate memory for log entry\n");
        return;
    }
    
    strscpy(entry->content, content, SULOG_ENTRY_MAX_LEN - 1);
    
    mutex_lock(&sulog_mutex);
    list_add_tail(&entry->list, &sulog_queue);
    mutex_unlock(&sulog_mutex);
    
    if (sulog_workqueue)
        queue_work(sulog_workqueue, &sulog_work);
}

void ksu_sulog_report_su_grant(uid_t uid, const char *comm, const char *method)
{
    char *timestamp, *full_comm, *log_buf;
    
    if (!sulog_enabled)
        return;
    
    timestamp = kmalloc(32, GFP_ATOMIC);
    full_comm = kmalloc(SULOG_COMM_LEN, GFP_ATOMIC);
    log_buf = kmalloc(SULOG_ENTRY_MAX_LEN, GFP_ATOMIC);
    
    if (!timestamp || !full_comm || !log_buf) {
        pr_err("sulog: failed to allocate memory for su_grant log\n");
        goto cleanup;
    }
    
    get_timestamp(timestamp, 32);
    
    ksu_get_cmdline(full_comm, comm, SULOG_COMM_LEN);
    
    snprintf(log_buf, SULOG_ENTRY_MAX_LEN,
        "[%s] SU_GRANT: UID=%d COMM=%s METHOD=%s PID=%d\n",
        timestamp, uid, full_comm, 
        method ? method : "unknown", current->pid);

    if (!dedup_should_print(uid, DEDUP_SU_GRANT, log_buf, strlen(log_buf)))
        goto cleanup;
    
    sulog_add_entry(log_buf);
    
cleanup:
    kfree(timestamp);
    kfree(full_comm);
    kfree(log_buf);
}

void ksu_sulog_report_su_attempt(uid_t uid, const char *comm, const char *target_path, bool success)
{
    char *timestamp, *full_comm, *log_buf;
    
    if (!sulog_enabled)
        return;
    
    timestamp = kmalloc(32, GFP_ATOMIC);
    full_comm = kmalloc(SULOG_COMM_LEN, GFP_ATOMIC);
    log_buf = kmalloc(SULOG_ENTRY_MAX_LEN, GFP_ATOMIC);
    
    if (!timestamp || !full_comm || !log_buf) {
        pr_err("sulog: failed to allocate memory for su_attempt log\n");
        goto cleanup;
    }
    
    get_timestamp(timestamp, 32);
    
    ksu_get_cmdline(full_comm, comm, SULOG_COMM_LEN);
    
    snprintf(log_buf, SULOG_ENTRY_MAX_LEN,
        "[%s] SU_EXEC: UID=%d COMM=%s TARGET=%s RESULT=%s PID=%d\n",
        timestamp, uid, full_comm,
        target_path ? target_path : "unknown",
        success ? "SUCCESS" : "DENIED", current->pid);

    if (!dedup_should_print(uid, DEDUP_SU_ATTEMPT, log_buf, strlen(log_buf)))
        goto cleanup;
    
    sulog_add_entry(log_buf);
    
cleanup:
    kfree(timestamp);
    kfree(full_comm);
    kfree(log_buf);
}

void ksu_sulog_report_permission_check(uid_t uid, const char *comm, bool allowed)
{
    char *timestamp, *full_comm, *log_buf;
    
    if (!sulog_enabled)
        return;
    
    timestamp = kmalloc(32, GFP_ATOMIC);
    full_comm = kmalloc(SULOG_COMM_LEN, GFP_ATOMIC);
    log_buf = kmalloc(SULOG_ENTRY_MAX_LEN, GFP_ATOMIC);
    
    if (!timestamp || !full_comm || !log_buf) {
        pr_err("sulog: failed to allocate memory for permission_check log\n");
        goto cleanup;
    }
    
    get_timestamp(timestamp, 32);
    
    ksu_get_cmdline(full_comm, comm, SULOG_COMM_LEN);
    
    snprintf(log_buf, SULOG_ENTRY_MAX_LEN,
        "[%s] PERM_CHECK: UID=%d COMM=%s RESULT=%s PID=%d\n",
        timestamp, uid, full_comm,
        allowed ? "ALLOWED" : "DENIED", current->pid);

    if (!dedup_should_print(uid, DEDUP_PERM_CHECK, log_buf, strlen(log_buf)))
        goto cleanup;
    
    sulog_add_entry(log_buf);
    
cleanup:
    kfree(timestamp);
    kfree(full_comm);
    kfree(log_buf);
}

void ksu_sulog_report_manager_operation(const char *operation, uid_t manager_uid, uid_t target_uid)
{
    char *timestamp, *full_comm, *log_buf;
    
    if (!sulog_enabled)
        return;
    
    timestamp = kmalloc(32, GFP_ATOMIC);
    full_comm = kmalloc(SULOG_COMM_LEN, GFP_ATOMIC);
    log_buf = kmalloc(SULOG_ENTRY_MAX_LEN, GFP_ATOMIC);
    
    if (!timestamp || !full_comm || !log_buf) {
        pr_err("sulog: failed to allocate memory for manager_operation log\n");
        goto cleanup;
    }
    
    get_timestamp(timestamp, 32);

    ksu_get_cmdline(full_comm, NULL, SULOG_COMM_LEN);
    
    snprintf(log_buf, SULOG_ENTRY_MAX_LEN,
        "[%s] MANAGER_OP: OP=%s MANAGER_UID=%d TARGET_UID=%d COMM=%s PID=%d\n",
        timestamp, operation ? operation : "unknown",
        manager_uid, target_uid, full_comm, current->pid);

    if (!dedup_should_print(manager_uid, DEDUP_MANAGER_OP, log_buf, strlen(log_buf)))
        goto cleanup;
    
    sulog_add_entry(log_buf);
    
cleanup:
    kfree(timestamp);
    kfree(full_comm);
    kfree(log_buf);
}

void ksu_sulog_report_syscall(uid_t uid, const char *comm,
                  const char *syscall, const char *args)
{
    char *timestamp, *full_comm, *log_buf;

    if (!sulog_enabled)
        return;

    timestamp = kmalloc(32, GFP_ATOMIC);
    full_comm = kmalloc(SULOG_COMM_LEN, GFP_ATOMIC);
    log_buf   = kmalloc(SULOG_ENTRY_MAX_LEN, GFP_ATOMIC);

    if (!timestamp || !full_comm || !log_buf) {
        pr_err("sulog: failed to allocate memory for syscall log\n");
        goto cleanup;
    }

    get_timestamp(timestamp, 32);
    
    ksu_get_cmdline(full_comm, comm, SULOG_COMM_LEN);

    snprintf(log_buf, SULOG_ENTRY_MAX_LEN,
         "[%s] SYSCALL: UID=%d COMM=%s SYSCALL=%s ARGS=%s PID=%d\n",
         timestamp, uid, full_comm,
         syscall  ? syscall  : "unknown",
         args     ? args     : "none",
         current->pid);

    if (!dedup_should_print(uid, DEDUP_SYSCALL, log_buf, strlen(log_buf)))
        goto cleanup;

    sulog_add_entry(log_buf);

cleanup:
    kfree(timestamp);
    kfree(full_comm);
    kfree(log_buf);
}

int ksu_sulog_init(void)
{
    // 兼容老内核的 workqueue 创建（移除 WQ_HIGHPRI）
    sulog_workqueue = alloc_workqueue("ksu_sulog", WQ_UNBOUND, 1);
    if (!sulog_workqueue) {
        pr_err("sulog: failed to create workqueue\n");
        return -ENOMEM;
    }
    
    INIT_WORK(&sulog_work, sulog_work_handler);
    
    pr_info("sulog: initialized successfully\n");
    return 0;
}

void ksu_sulog_exit(void)
{
    struct sulog_entry *entry, *tmp;
    
    sulog_enabled = false;
    
    if (sulog_workqueue) {
        flush_workqueue(sulog_workqueue);
        destroy_workqueue(sulog_workqueue);
        sulog_workqueue = NULL;
    }
    
    mutex_lock(&sulog_mutex);
    list_for_each_entry_safe(entry, tmp, &sulog_queue, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    mutex_unlock(&sulog_mutex);
    
    pr_info("sulog: cleaned up successfully\n");
}
#endif // __SULOG_GATE
