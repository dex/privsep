#include "privsep.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#define os_memset memset
#define os_memcpy memcpy
#define os_strstr strstr
#define os_strchr strchr
#define os_strdup strdup
#define os_free free
#define os_strlen strlen
#define os_strlcpy strlcpy
#define os_malloc malloc
#define os_snprintf snprintf
#define os_memset memset

#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

enum privsep_cmd {
    PRIVSEP_CMD_REGISTER,
    PRIVSEP_CMD_UNREGISTER,
    PRIVSEP_CMD_SCAN,
    PRIVSEP_CMD_GET_SCAN_RESULTS,
    PRIVSEP_CMD_ASSOCIATE,
    PRIVSEP_CMD_GET_BSSID,
    PRIVSEP_CMD_GET_SSID,
    PRIVSEP_CMD_SET_KEY,
    PRIVSEP_CMD_GET_CAPA,
    PRIVSEP_CMD_L2_REGISTER,
    PRIVSEP_CMD_L2_UNREGISTER,
    PRIVSEP_CMD_L2_NOTIFY_AUTH_START,
    PRIVSEP_CMD_L2_SEND,
    PRIVSEP_CMD_SET_COUNTRY,
    PRIVSEP_CMD_AUTHENTICATE,
};

/*
struct wpa_driver_privsep_data {
    void *ctx;
    u8 own_addr[ETH_ALEN];
    int priv_socket;
    char *own_socket_path;
    int cmd_socket;
    char *own_cmd_path;
    struct sockaddr_un priv_addr;
    char ifname[16];
};
*/

enum {
    MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR
};

static ssize_t os_strlcpy(char *dst, char *src, ssize_t size)
{
    return snprintf(dst, size, "%s", src);
}

static void *os_zalloc(size_t size)
{
    return calloc(1, size);
}

static void wpa_printf(int level, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);

    vprintf(fmt, ap);
    printf("\n");

    va_end(ap);
}

static int wpa_priv_cmd(struct wpa_driver_privsep_data *drv, int cmd,
                        const void *data, size_t data_len,
                        void *reply, size_t *reply_len)
{
    struct msghdr msg;
    struct iovec io[2];

    io[0].iov_base = &cmd;
    io[0].iov_len = sizeof(cmd);
    io[1].iov_base = (u8 *) data;
    io[1].iov_len = data_len;
    printf("io0.iov_base = %p, io0.iov_len = %d\n", io[0].iov_base, io[0].iov_len);
    printf("cmd = %d\n", cmd);
    printf("io1.iov_base = %p, io1.iov_len = %d\n", io[1].iov_base, io[1].iov_len);

    os_memset(&msg, 0, sizeof(msg));
    msg.msg_iov = io;
    msg.msg_iovlen = data ? 2 : 1;
    msg.msg_name = &drv->priv_addr;
    msg.msg_namelen = sizeof(drv->priv_addr);
    printf("drv->cmd_socket = %d, iov = %p, iovlen = %d, msg_name = %p, priv_addr = %s, msg_namelen = %d\n",
           drv->cmd_socket, msg.msg_iov, msg.msg_iovlen, msg.msg_name, drv->priv_addr.sun_path, msg.msg_namelen);

    if (sendmsg(drv->cmd_socket, &msg, 0) < 0) {
        wpa_printf(MSG_ERROR, "sendmsg(cmd_socket): %s",
                   strerror(errno));
        return -1;
    }

    if (reply) {
        fd_set rfds;
        struct timeval tv;
        int res;

        FD_ZERO(&rfds);
        FD_SET(drv->cmd_socket, &rfds);
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        res = select(drv->cmd_socket + 1, &rfds, NULL, NULL, &tv);
        if (res < 0 && errno != EINTR) {
            wpa_printf(MSG_ERROR, "select: %s", strerror(errno));
            return -1;
        }

        if (FD_ISSET(drv->cmd_socket, &rfds)) {
            res = recv(drv->cmd_socket, reply, *reply_len, 0);
            if (res < 0) {
                wpa_printf(MSG_ERROR, "recv: %s",
                           strerror(errno));
                return -1;
            }
            *reply_len = res;
        } else {
            wpa_printf(MSG_DEBUG, "PRIVSEP: Timeout while waiting "
                       "for reply (cmd=%d)", cmd);
            return -1;
        }
    }

    return 0;
}

static int wpa_priv_reg_cmd(struct wpa_driver_privsep_data *drv, int cmd)
{
    int res;

    res = sendto(drv->priv_socket, &cmd, sizeof(cmd), 0,
                 (struct sockaddr *) &drv->priv_addr,
                 sizeof(drv->priv_addr));
    if (res < 0)
        wpa_printf(MSG_ERROR, "sendto: %s", strerror(errno));
    return res < 0 ? -1 : 0;
}

void *wpa_driver_privsep_new(const char *ifname, const char *param)
{
    struct wpa_driver_privsep_data *drv = os_zalloc(sizeof(struct wpa_driver_privsep_data));
    const char *pos;
    char *own_dir, *priv_dir;
    static unsigned int counter = 0;
    size_t len;
    struct sockaddr_un addr;

    snprintf(drv->ifname, sizeof(drv->ifname), "%s", ifname);
    wpa_printf(MSG_DEBUG, "%s: param='%s'", __func__, param);
    if (param == NULL)
        pos = NULL;
    else
        pos = os_strstr(param, "own_dir=");
    if (pos) {
        char *end;
        own_dir = os_strdup(pos + 8);
        if (own_dir == NULL)
            goto failure;
        end = os_strchr(own_dir, ' ');
        if (end)
            *end = '\0';
    } else {
        own_dir = os_strdup("/tmp");
        if (own_dir == NULL)
            goto failure;
    }

    if (param == NULL)
        pos = NULL;
    else
        pos = os_strstr(param, "priv_dir=");
    if (pos) {
        char *end;
        priv_dir = os_strdup(pos + 9);
        if (priv_dir == NULL) {
            os_free(own_dir);
            goto failure;
        }
        end = os_strchr(priv_dir, ' ');
        if (end)
            *end = '\0';
    } else {
        priv_dir = os_strdup("/var/run/wpa_priv");
        if (priv_dir == NULL) {
            os_free(own_dir);
            goto failure;
        }
    }

    len = os_strlen(own_dir) + 50;
    drv->own_socket_path = os_malloc(len);
    if (drv->own_socket_path == NULL) {
        os_free(priv_dir);
        os_free(own_dir);
        goto failure;
    }
    os_snprintf(drv->own_socket_path, len, "%s/wpa_privsep-%d-%d",
                own_dir, getpid(), counter++);

    len = os_strlen(own_dir) + 50;
    drv->own_cmd_path = os_malloc(len);
    if (drv->own_cmd_path == NULL) {
        os_free(drv->own_socket_path);
        drv->own_socket_path = NULL;
        os_free(priv_dir);
        os_free(own_dir);
        goto failure;
    }
    os_snprintf(drv->own_cmd_path, len, "%s/wpa_privsep-%d-%d",
                own_dir, getpid(), counter++);

    os_free(own_dir);

    drv->priv_addr.sun_family = AF_UNIX;
    os_snprintf(drv->priv_addr.sun_path, sizeof(drv->priv_addr.sun_path),
                "%s/%s", priv_dir, drv->ifname);
    printf("ifname: %s, priv_dir: %s\n", drv->ifname, priv_dir);
    os_free(priv_dir);

    drv->priv_socket = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (drv->priv_socket < 0) {
        wpa_printf(MSG_ERROR, "socket(PF_UNIX): %s", strerror(errno));
        os_free(drv->own_socket_path);
        drv->own_socket_path = NULL;
        goto failure;
    }

    os_memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    os_strlcpy(addr.sun_path, drv->own_socket_path, sizeof(addr.sun_path));
    if (bind(drv->priv_socket, (struct sockaddr *) &addr, sizeof(addr)) <
        0) {
        wpa_printf(MSG_ERROR,
                   "privsep-set-params priv-sock: bind(PF_UNIX): %s",
                   strerror(errno));
        close(drv->priv_socket);
        drv->priv_socket = -1;
        unlink(drv->own_socket_path);
        os_free(drv->own_socket_path);
        drv->own_socket_path = NULL;
        goto failure;
    }
    printf("own_socket_path: %s\n", drv->own_socket_path);

#ifdef PRIVSEP_RECV
    eloop_register_read_sock(drv->priv_socket, wpa_driver_privsep_receive,
                             drv, NULL);
#endif

    drv->cmd_socket = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (drv->cmd_socket < 0) {
        wpa_printf(MSG_ERROR, "socket(PF_UNIX): %s", strerror(errno));
        os_free(drv->own_cmd_path);
        drv->own_cmd_path = NULL;
        goto failure;
    }

    os_memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    os_strlcpy(addr.sun_path, drv->own_cmd_path, sizeof(addr.sun_path));
    if (bind(drv->cmd_socket, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    {
        wpa_printf(MSG_ERROR,
                   "privsep-set-params cmd-sock: bind(PF_UNIX): %s",
                   strerror(errno));
        close(drv->cmd_socket);
        drv->cmd_socket = -1;
        unlink(drv->own_cmd_path);
        os_free(drv->own_cmd_path);
        drv->own_cmd_path = NULL;
        goto failure;
    }
    printf("own_cmd_path: %s\n", drv->own_cmd_path);

    if (wpa_priv_reg_cmd(drv, PRIVSEP_CMD_REGISTER) < 0) {
        wpa_printf(MSG_ERROR, "Failed to register with wpa_priv");
        goto failure;
    }

    return drv;

failure:
    if (drv)
        os_free(drv);
    return NULL;
}

int wpa_driver_privsep_associate(void *priv, struct privsep_cmd_associate *data)
{
    struct wpa_driver_privsep_data *drv = priv;
    const struct privsep_cmd_associate *params = data;
    //struct privsep_cmd_associate *data;
    int res;
    size_t buflen;

    wpa_printf(MSG_DEBUG, "%s: priv=%p freq=%d pairwise_suite=%d "
               "group_suite=%d key_mgmt_suite=%d auth_alg=%d mode=%d",
               __func__, priv, params->freq, params->pairwise_suite,
               params->group_suite, params->key_mgmt_suite,
               params->auth_alg, params->mode);

    buflen = sizeof(*data) + params->wpa_ie_len;

    res = wpa_priv_cmd(drv, PRIVSEP_CMD_ASSOCIATE, data, buflen,
                       NULL, NULL);

    return res;
}

int wpa_driver_privsep_authenticate(void *priv, struct privsep_cmd_authenticate *params)
{
    struct wpa_driver_privsep_data *drv = priv;
    struct privsep_cmd_authenticate *data = params;
    int res;
    size_t buflen;

    wpa_printf(MSG_DEBUG, "%s: priv=%p freq=%d bssid=" MACSTR
               " auth_alg=%d local_state_change=%d p2p=%d",
               __func__, priv, params->freq, MAC2STR(params->bssid),
               params->auth_alg, params->local_state_change, params->p2p);

    buflen = sizeof(*data) + params->ie_len + params->sae_data_len;

    res = wpa_priv_cmd(drv, PRIVSEP_CMD_AUTHENTICATE, data, buflen,
                       NULL, NULL);

    return res;
}
