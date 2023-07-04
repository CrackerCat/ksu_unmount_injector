#include <stdio.h>
#include <unistd.h>
#include <string>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <libgen.h>
#include <sys/prctl.h>

#include "procfp.hpp"
#include "logging.hpp"
#include "utils.hpp"
#include "magiskhide_util.hpp"

#include "debug.hpp"

const char *MAGISKTMP = nullptr;
bool new_magic_mount = false;
bool trace_log = false;
int SDK_INT = 0;
dev_t worker_dev = 0;

int log_fd = -1;

static int myself;

void kill_other(struct stat me){
    crawl_procfs([=](int pid) -> bool {
        struct stat st;
        char path[128];
        char cmdline[1024];
        snprintf(path, 127, "/proc/%d/exe", pid);
        if (stat(path,&st)!=0)
            return true;
        snprintf(path, 127, "/proc/%d/cmdline", pid);
        FILE *fp = fopen(path, "re");
        if (fp == nullptr)
            return true;
        fgets(cmdline, sizeof(cmdline), fp);
        fclose(fp);
        if (pid == myself)
            return true;
        if ((st.st_dev == me.st_dev && st.st_ino == me.st_ino) ||
            (st.st_size == me.st_size &&  strcmp(cmdline, "ksuhide_daemon") == 0)) {
#ifdef DEBUG
            fprintf(stderr, "Killed: %d\n", pid);
#endif
            kill(pid, SIGKILL);
        }
        return true;
    });
}

static bool check_ksu_version() {
    if (getuid() != 0) {
        printf("Root access is required for this action!\n");
        return false;
    }
    int ksu_version = -1;
    prctl(0xdeadbeef, 2, &ksu_version, 0, 0);
    if (ksu_version < 0) {
        printf("KernelSU is not installed (%d)\n", ksu_version);
        return false;
    }
    if (ksu_version < 10940) {
        printf("KernelSU version (%d) is lower than 10940\n", ksu_version);
        return false;
    }
    // TODO: Check capabilities, permissive context, ...
    return true;
}

int main(int argc, char **argv) {
    const char *binname = basename(argv[0]);

    if (strcmp(binname, "ksuhide") != 0) {
        int32_t result = -1;
        prctl(0xdeadbeef, 0, 0, 0, &result);
        if (result != -1) {
            if (!check_ksu_version()) return 1;
            char *argv_exec[argc+1];
            argv_exec[0] = (char*)binname;
            for (int i = 1; i < argc; i++)
                argv_exec[i] = argv[i];
            argv_exec[argc] = nullptr;
#define KSUD_PATH "/data/adb/ksud"
#ifdef DEBUG
            for (int i = 0; argv_exec[i]; i++) {
            	fprintf(stderr, "argv[%d] = [%s]\n", i, argv_exec[i]);
            }
#endif
            execve(KSUD_PATH, argv_exec, environ);
        }
        return 1;
    }

    if (!check_ksu_version()) return 1;

    if (argc >= 2 && strcmp(argv[1], "check") == 0)
        return 0;

    if (argc >= 2 && strcmp(argv[1], "exec") == 0) {
        if (argc >= 3 && unshare(CLONE_NEWNS) == 0) {
            mount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr);
            hide_unmount();
            execvp(argv[2], argv + 2);
        }
        return 1;
    }

#ifdef DEBUG
    if (argc >= 2 && strcmp(argv[1], "--test") == 0) {
        proc_monitor();
        return 0;
    }
#endif

    if (argc < 2 || strcmp(argv[1], "daemon") != 0) {
        fprintf(stderr, "usage: %s [OPTION]\n\n"
                        "OPTION:\n"
                        "check         Check compatible\n"
                        "daemon        Launch new daemon\n"
                        "exec CMD      Execute command in isolated mount namespace\n"
                        "              and do all unmounts\n"
                        "\n", binname);
        return 1;
    }

    if (switch_mnt_ns(1))
        return -1;

    struct stat me;
    myself = getpid();

    if (stat("/proc/self/exe", &me) != 0)
        return 1;

    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) {
        fprintf(stderr, "Broken pipe\n");
        return -1;
    }

    kill_other(me);
    set_nice_name("ksuhide_daemon");

    if (fork_dont_care() == 0) {
        int pid = getpid();
        write(pipe_fd[1], &pid, sizeof(pid));

        log_fd = open("/cache/ksu_umount.log", O_RDWR | O_CREAT | O_APPEND, 0666);

        LOGI("** Hide daemon started\n");
        struct stat modules_st{}, data_st{};
        stat("/data", &data_st);
        stat("/data/adb/modules", &modules_st);
        if (data_st.st_dev != modules_st.st_dev)
            worker_dev = modules_st.st_dev;

        signal(SIGTERM, SIG_IGN);
        signal(SIGUSR1, SIG_IGN);
        signal(SIGUSR2, SIG_IGN);

        char buf[1024] = { '\0' };

        setsid();

        // escape from cgroup
        switch_cgroup("/acct", pid);
        switch_cgroup("/dev/cg2_bpf", pid);
        switch_cgroup("/sys/fs/cgroup", pid);
        __system_property_get("ro.config.per_app_memcg", buf);
        if (strcmp(buf, "false") != 0) {
            switch_cgroup("/dev/memcg/apps", pid);
        }
        buf[0] = '\0';
        __system_property_get("ro.build.version.sdk", buf);
        SDK_INT = parse_int(buf);

        // run daemon
        proc_monitor();
        _exit(0);
    }
    int daemon = -1;
    read(pipe_fd[0], &daemon, sizeof(daemon));
    close(pipe_fd[0]);
    close(pipe_fd[1]);

#ifdef DEBUG
    fprintf(stderr, "Launched hide daemon: %d\n", daemon);
#endif

    return 0;
}
