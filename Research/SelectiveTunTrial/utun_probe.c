/* Capability probe only: no addresses, routes, DNS or persistent configuration.
 * The kernel destroys the interface when this process closes its sole fd,
 * including process death. Run elevated only through macOS authorization. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    struct ctl_info info = {0};
    struct sockaddr_ctl addr = {0};
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) { printf("socket errno=%d %s\n", errno, strerror(errno)); return 1; }
    strlcpy(info.ctl_name, "com.apple.net.utun_control", sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        printf("CTLIOCGINFO errno=%d %s\n", errno, strerror(errno)); close(fd); return 2;
    }
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("connect uid=%u errno=%d %s\n", getuid(), errno, strerror(errno));
        close(fd); return 3;
    }
    char name[IFNAMSIZ] = {0}; socklen_t len = sizeof(name);
    if (getsockopt(fd, SYSPROTO_CONTROL, 2 /* UTUN_OPT_IFNAME */, name, &len) < 0) {
        printf("getsockopt errno=%d %s\n", errno, strerror(errno)); close(fd); return 4;
    }
    printf("created uid=%u interface=%s no_addresses_or_routes_requested\n", getuid(), name);
    fflush(stdout);
    close(fd);
    printf("closed interface_fd\n");
    return 0;
}
