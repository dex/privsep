#ifndef PRIVSEP_H_GQETV4OL
#define PRIVSEP_H_GQETV4OL

#include <sys/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/if_ether.h>

typedef uint8_t u8;
#define SSID_MAX_LEN 32

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


struct privsep_cmd_authenticate
{
    int freq;
    u8 bssid[ETH_ALEN];
    u8 ssid[SSID_MAX_LEN];
    size_t ssid_len;
    int auth_alg;
    size_t ie_len;
    u8 wep_key[4][16];
    size_t wep_key_len[4];
    int wep_tx_keyidx;
    int local_state_change;
    int p2p;
    size_t sae_data_len;
    /* followed by ie_len bytes of ie */
    /* followed by sae_data_len bytes of sae_data */
};

struct privsep_cmd_associate
{
    u8 bssid[ETH_ALEN];
    u8 ssid[SSID_MAX_LEN];
    size_t ssid_len;
    int hwmode;
    int freq;
    int channel;
    int pairwise_suite;
    int group_suite;
    int key_mgmt_suite;
    int auth_alg;
    int mode;
    size_t wpa_ie_len;
    /* followed by wpa_ie_len bytes of wpa_ie */
};

void *wpa_driver_privsep_new(const char *ifname, const char *param);
int wpa_driver_privsep_authenticate(void *priv, struct privsep_cmd_authenticate *params);
int wpa_driver_privsep_associate(void *priv, struct privsep_cmd_associate *data);

#endif /* end of include guard: PRIVSEP_H_GQETV4OL */
