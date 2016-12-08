#ifndef PRIVSEP_H_GQETV4OL
#define PRIVSEP_H_GQETV4OL

#include <sys/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/if_ether.h>

typedef uint8_t u8;
#define SSID_MAX_LEN 32

struct wpa_driver_privsep_data;

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

struct wpa_driver_privsep_data *wpa_driver_privsep_new(const char *ifname, const char *param);
int wpa_driver_privsep_authenticate(struct wpa_driver_privsep_data *priv, struct privsep_cmd_authenticate *params);
int wpa_driver_privsep_associate(struct wpa_driver_privsep_data *priv, struct privsep_cmd_associate *data);
int wpa_driver_privsep_scan(struct wpa_driver_privsep_data *priv, const u8 *ssid, ssize_t ssid_len);

#endif /* end of include guard: PRIVSEP_H_GQETV4OL */
