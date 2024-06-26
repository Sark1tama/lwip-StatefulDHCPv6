/*!
    \file    netconf.c
    \brief   network connection configuration

    \version 2024-01-15, V3.2.0, firmware for GD32F4xx
*/

/*
    Copyright (c) 2024, GigaDevice Semiconductor Inc.

    Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
    3. Neither the name of the copyright holder nor the names of its contributors
       may be used to endorse or promote products derived from this software without
       specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.
*/
#include "lwip/init.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "netif/etharp.h"
#include "lwip/dhcp.h"

#include "lwip/nd6.h"
#include "lwip/ip6_frag.h"
#include "lwip/mld6.h"
#include "lwip/dhcp6.h"

#include "ethernetif.h"
#include "stdint.h"
#include "main.h"
#include "netconf.h"
#include <stdio.h>
#include "lwip/priv/tcp_priv.h"
#include "lwip/timeouts.h"
#include <string.h>
#define MAX_DHCP_TRIES        5

typedef enum {
    DHCP_START = 0,
    DHCP_WAIT_ADDRESS,
    DHCP_ADDRESS_ASSIGNED,
    DHCP_TIMEOUT
} dhcp_state_enum;

#ifdef USE_DHCP_AND_DHCP6
uint32_t dhcp_fine_timer = 0;
uint32_t dhcp_coarse_timer = 0;
dhcp_state_enum dhcp_state = DHCP_START;
#endif /* USE_DHCP_AND_DHCP6 */

struct netif g_mynetif;
uint32_t tcp_timer = 0;
uint32_t arp_timer = 0;

#if LWIP_IPV6
#ifndef TIMEOUT_CHECK_USE_LWIP
uint32_t nd6_timer = 0;
#if LWIP_IPV6_MLD
uint32_t mld6_timer = 0;
#endif
#if LWIP_IPV6_REASS
uint32_t reass_timer = 0;
#endif
#endif
ip_addr_t ip6_address[LWIP_IPV6_NUM_ADDRESSES] = {0};
#endif
ip_addr_t ip_address = {0};

void lwip_dhcp_process_handle(void);
void lwip_netif_status_callback(struct netif *netif);

/*!
    \brief      initializes the LwIP stack
    \param[in]  none
    \param[out] none
    \retval     none
*/
void lwip_stack_init(void)
{
#if LWIP_IPV6
    ip_addr_t ipaddr6;
    ip_addr_t ipaddr4;
    ip_addr_t netmask;
    ip_addr_t gw;
#else
    ip_addr_t ipaddr;
    ip_addr_t netmask;
    ip_addr_t gw;
#endif


#ifdef TIMEOUT_CHECK_USE_LWIP
		lwip_init();
#else
		/* initializes the dynamic memory heap defined by MEM_SIZE */
    mem_init();

    /* initializes the memory pools defined by MEMP_NUM_x */
    memp_init();
#endif /* TIMEOUT_CHECK_USE_LWIP */

#ifdef USE_DHCP_AND_DHCP6
#if LWIP_IPV6
    ipaddr4.u_addr.ip4.addr = 0;
    netmask.u_addr.ip4.addr = 0;
    gw.u_addr.ip4.addr = 0;
#else
    ipaddr.addr = 0;
    netmask.addr = 0;
    gw.addr = 0;
#endif
#else
#if LWIP_IPV6
    IP6_ADDR(ip_2_ip6(&ipaddr6),PP_HTONL(0xFE800000),PP_HTONL(0x0),PP_HTONL(0x59C14B28),PP_HTONL(0xFB844181));
    IP4_ADDR(ip_2_ip4(&ipaddr4), IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
    IP4_ADDR(ip_2_ip4(&netmask), NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
    IP4_ADDR(ip_2_ip4(&gw), GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);
#else
    IP4_ADDR(&ipaddr, IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
    IP4_ADDR(&netmask, NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
    IP4_ADDR(&gw, GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);
#endif
#endif /* USE_DHCP_AND_DHCP6 */

    /* - netif_add(struct netif *netif, ip_addr_t *ipaddr,
              ip_addr_t *netmask, ip_addr_t *gw,
              void *state, err_t (* init)(struct netif *netif),
              err_t (* input)(struct pbuf *p, struct netif *netif))

     Adds your network interface to the netif_list. Allocate a struct
    netif and pass a pointer to this structure as the first argument.
    Give pointers to cleared ip_addr structures when using DHCP,
    or fill them with sane numbers otherwise. The state pointer may be NULL.

    The init function pointer must point to a initialization function for
    your ethernet netif interface. The following code illustrates it's use.*/
#if LWIP_IPV6
		//netif_input根据是否定义NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET选择ethernet_input()或ip_input()
    netif_add(&g_mynetif, ip_2_ip4(&ipaddr4), ip_2_ip4(&netmask), ip_2_ip4(&gw), NULL, &ethernetif_init, &netif_input); 
		netif_create_ip6_linklocal_address(&g_mynetif, 1); //本地链接地址，接口配置了MAC地址，则接口EUI-64格式地址根据接口配置的MAC地址生成，中间填充FFFE
		ip6_address[0] = g_mynetif.ip6_addr[0];
    //IP6_ADDR(ip_2_ip6(&ipaddr6),PP_HTONL(0xFE800000),PP_HTONL(0x0),PP_HTONL(0x59C14B28),PP_HTONL(0xFB844181)); //手动增加一个IPv6本地地址
		//s8_t i;
    //netif_add_ip6_address(&g_mynetif, ip_2_ip6(&ipaddr6), &i);
		
		//2.2.0之前默认关闭IP自动配置，需要手动打开
#if	(LWIP_VERSION_MAJOR <= 2) && (LWIP_VERSION_MINOR < 2)
		netif_set_ip6_autoconfig_enabled(&g_mynetif, 1);
#endif
#else
    netif_add(&g_mynetif, &ipaddr, &netmask, &gw, NULL, &ethernetif_init, &netif_input);
#endif
    /* registers the default network interface */
    netif_set_default(&g_mynetif);
    netif_set_status_callback(&g_mynetif, lwip_netif_status_callback);

    /* when the netif is fully configured this function must be called */
    netif_set_up(&g_mynetif);
}

/*!
    \brief      called when a frame is received
    \param[in]  none
    \param[out] none
    \retval     none
*/
void lwip_pkt_handle(void)
{
    /* read a received packet from the Ethernet buffers and send it to the lwIP for handling */
    ethernetif_input(&g_mynetif);
}

/*!
    \brief      LwIP periodic tasks
    \param[in]  localtime the current LocalTime value
    \param[out] none
    \retval     none
*/
void lwip_periodic_handle(__IO uint32_t localtime)
{
//#if LWIP_IPV6
//		for (int i=0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
//        if (ip6_addr_islinklocal(netif_ip6_addr(&g_mynetif, i))) {
//            // 找到链路本地地址
//            ip6_addr_t* linklocal_addr = (ip6_addr_t*)netif_ip6_addr(&g_mynetif, i);
//            // 输出地址信息（以字符串形式）
//            char addr_str[IP6ADDR_STRLEN_MAX];
//						int status = netif_ip6_addr_state(&g_mynetif, i);
//						u8_t zone = ip6_addr_zone(linklocal_addr);
//						strcpy(addr_str,ip6addr_ntoa(linklocal_addr));
//            printf("link-local address: %s\n", addr_str);
//        }
//				else if(!ip6_addr_isany(netif_ip6_addr(&g_mynetif, i)))
//				{
//					// 找到非链路本地地址
//            ip6_addr_t* non_linklocal_addr = (ip6_addr_t*)netif_ip6_addr(&g_mynetif, i);
//            // 输出地址信息（以字符串形式）
//            char addr_str[IP6ADDR_STRLEN_MAX];
//						int status = netif_ip6_addr_state(&g_mynetif, i);
//						u8_t zone = ip6_addr_zone(non_linklocal_addr);
//						strcpy(addr_str,ip6addr_ntoa(non_linklocal_addr));
//            printf("non link-local address: %s\n", addr_str);
//				}
//    }
//#endif
#ifndef TIMEOUT_CHECK_USE_LWIP
#if LWIP_TCP
    /* TCP periodic process every 250 ms */
    if(localtime - tcp_timer >= TCP_TMR_INTERVAL) {
        tcp_timer =  localtime;
        tcp_tmr();
    }

#endif /* LWIP_TCP */

#if LWIP_IPV6
		if((localtime - nd6_timer) >= ND6_TMR_INTERVAL) {
        nd6_timer = localtime;
        nd6_tmr();
    }
#if LWIP_IPV6_MLD
  	if((localtime - mld6_timer) >= MLD6_TMR_INTERVAL) {
        mld6_timer = localtime;
        mld6_tmr();
    }
#endif /* LWIP_IPV6_MLD */
#if LWIP_IPV6_REASS
  	if((localtime - reass_timer) >= IP6_REASS_TMR_INTERVAL) {
        reass_timer = localtime;
        ip6_reass_tmr();
    }
#endif /* LWIP_IPV6_REASS */
#endif

    /* ARP periodic process every 5s */
    if((localtime - arp_timer) >= ARP_TMR_INTERVAL) {
        arp_timer = localtime;
        etharp_tmr();
    }

#ifdef USE_DHCP_AND_DHCP6
    /* fine DHCP periodic process every 500ms */
    if(localtime - dhcp_fine_timer >= DHCP_FINE_TIMER_MSECS) {
        dhcp_fine_timer =  localtime;
        dhcp_fine_tmr();
#if LWIP_IPV6 && LWIP_IPV6_DHCP6
				dhcp6_tmr();
#endif
        if((DHCP_ADDRESS_ASSIGNED != dhcp_state) && (DHCP_TIMEOUT != dhcp_state)) {
            /* process DHCP state machine */
            lwip_dhcp_process_handle();
        }
    }

    /* DHCP coarse periodic process every 60s */
    if(localtime - dhcp_coarse_timer >= DHCP_COARSE_TIMER_MSECS) {
        dhcp_coarse_timer =  localtime;
        dhcp_coarse_tmr();
    }

#endif /* USE_DHCP_AND_DHCP6 */
#endif /*TIMEOUT_CHECK_USE_LWIP*/
}

#ifdef USE_DHCP_AND_DHCP6
/*!
    \brief      lwip_dhcp_process_handle
    \param[in]  none
    \param[out] none
    \retval     none
*/
void lwip_dhcp_process_handle(void)
{
#if LWIP_IPV6
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;
    ip4_addr_t gw;
#else 
		ip_addr_t ipaddr;
    ip_addr_t netmask;
    ip_addr_t gw;
#endif
    struct dhcp *dhcp_client;

    switch(dhcp_state) {
    case DHCP_START:
        dhcp_start(&g_mynetif);
#if	LWIP_IPV6 && LWIP_IPV6_DHCP6
//				dhcp6_enable_stateless(&g_mynetif);// 无状态配置
				dhcp6_enable_stateful(&g_mynetif); // 有状态配置
#endif
        dhcp_state = DHCP_WAIT_ADDRESS;
        break;

    case DHCP_WAIT_ADDRESS:
        /* read the new IP address */
        ip_address = g_mynetif.ip_addr;
#if LWIP_IPV6 && LWIP_IPV6_DHCP6
				int dhcpv6_state = DHCP_WAIT_ADDRESS;
				for (int i=0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
					if (!ip6_addr_islinklocal(netif_ip6_addr(&g_mynetif, i))\
						&&!ip6_addr_isany(netif_ip6_addr(&g_mynetif, i))) {
						ip6_address[i] = *netif_ip_addr6(&g_mynetif, i);
						dhcpv6_state = DHCP_ADDRESS_ASSIGNED;
					}
				}
#endif	
        if(0 != ip_address.u_addr.ip4.addr 
#if LWIP_IPV6 && LWIP_IPV6_DHCP6
					&& dhcpv6_state == DHCP_ADDRESS_ASSIGNED
#endif
				) {
						dhcp_state = DHCP_ADDRESS_ASSIGNED;
            printf("\r\nDHCP -- eval board ip address: %d.%d.%d.%d \r\n", ip4_addr1_16(&ip_address.u_addr.ip4), \
                   ip4_addr2_16(&ip_address.u_addr.ip4), ip4_addr3_16(&ip_address.u_addr.ip4), ip4_addr4_16(&ip_address.u_addr.ip4));
        } 
				else {
#if LWIP_IPV6 && LWIP_IPV6_DHCP6
            struct dhcp6 *dhcpv6_client = netif_dhcp6_data(&g_mynetif);
						if(dhcpv6_client->tries > MAX_DHCP_TRIES) {
                /* stop DHCP6 */
                dhcp6_disable(&g_mynetif);
            }
#endif
            /* DHCP timeout */
            dhcp_client = netif_dhcp_data(&g_mynetif);
            if(dhcp_client->tries > MAX_DHCP_TRIES 
							) {
                dhcp_state = DHCP_TIMEOUT;
                /* stop DHCP */
                dhcp_stop(&g_mynetif);

                /* static address used */
                IP4_ADDR(&ipaddr, IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
                IP4_ADDR(&netmask, NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
                IP4_ADDR(&gw, GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);
                netif_set_addr(&g_mynetif, &ipaddr, &netmask, &gw);
            }
        }
        break;

    default:
        break;
    }
}
#endif /* USE_DHCP_AND_DHCP6 */

unsigned long sys_now(void)
{
    extern volatile unsigned int g_localtime;
    return g_localtime;
}
