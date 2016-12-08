#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "privsep.h"

static int hex2num(char c)
{
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}


int hex2byte(const char *hex)
{
        int a, b;
        a = hex2num(*hex++);
        if (a < 0)
                return -1;
        b = hex2num(*hex++);
        if (b < 0)
                return -1;
        return (a << 4) | b;
}

static const char * hwaddr_parse(const char *txt, u8 *addr)
{
        size_t i;

        for (i = 0; i < ETH_ALEN; i++) {
                int a;

                a = hex2byte(txt);
                if (a < 0)
                        return NULL;
                txt += 2;
                addr[i] = a;
                if (i < ETH_ALEN - 1 && *txt++ != ':')
                        return NULL;
        }
        return txt;
}


/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, u8 *addr)
{
        return hwaddr_parse(txt, addr) ? 0 : -1;
}


int main(int argc, char *argv[])
{
	struct wpa_driver_privsep_data *priv = 0;
	struct privsep_cmd_authenticate priv_auth;
	struct privsep_cmd_associate priv_assoc;


	u8 bssid[6];
	u8 ssid[33];
	int c, freq, auth, assoc, ssid_len;

        memset(&priv_auth, 0, sizeof(priv_auth));
        memset(&priv_assoc, 0, sizeof(priv_assoc));
	priv = (struct wpa_driver_privsep_data *)wpa_driver_privsep_new("wlan0", NULL);

	for (;;) {
                c = getopt(argc, argv,
                           "b:aA:S:F");
                if (c < 0)
                        break;
                switch (c) {
                case 'a':
                        auth = 1;
                        break;
                case 'A':
                        assoc = 1;
                        break;
		case 'b':
                        if (hwaddr_aton(optarg, bssid))
                                return -1;
			break;
                case 'S':
			ssid_len = strlen(optarg);	
                        strncpy(ssid, optarg, ssid_len);
                        break;
                case 'F':
                //        freq = atoi(optarg);
                //        break;

                default:
	       		exit(1);
			break;
                }
       	}

	if (auth) {
		priv_auth.freq = 2412;
		memcpy(priv_auth.bssid, bssid, 6);
		strncpy(priv_auth.ssid, ssid, ssid_len);
		priv_auth.ssid_len = ssid_len;
		priv_auth.auth_alg = 1;

		printf("AUTH: freq:%d, ssid:%s, ssid_len:%d\n", priv_auth.freq, priv_auth.ssid, priv_auth.ssid_len);
		
		wpa_driver_privsep_authenticate(priv, &priv_auth);
	} else if (assoc) {
                memcpy(priv_assoc.bssid, bssid, 6);
                strncpy(priv_assoc.ssid, ssid, ssid_len);
                priv_assoc.ssid_len = ssid_len;
 		priv_assoc.hwmode = 0;
		priv_assoc.freq = 2412;

                printf("ASSOC: freq:%d, ssid:%s, ssid_len:%d\n", priv_assoc.freq, priv_assoc.ssid, priv_assoc.ssid_len);

		wpa_driver_privsep_associate(priv, &priv_assoc);
	}

	return 0;
}
