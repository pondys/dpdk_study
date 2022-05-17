#ifndef __YS_REV_NETARCH_H__
#define __YS_REV_NETARCH_H__

#include <rte_ether.h>

#define ARP_TYPE_DYNAMIC 0


#define ARP_TYPE_STATIC 1

//Á´±íÍ·²å
#define L_H_ADD(item, list) do{\
	item->prev = NULL;\
	item->next = list;\
	if (NULL != list) list->prev = item;\
	list = item;\
} while(0)

//É¾
#define L_REMOVE(item, list) do{\
	if (item->prev != NULL) item->prev->next = item->next;\
	if (item->next != NULL) item->next->prev = item->prev;\
	if (item == list) list = item->next;\
	item->prev = item->next = NULL;\
} while(0)

//arp±í
struct ys_arp_entry
{
    uint8_t type;
	uint32_t ip;
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN];

    struct ys_arp_entry *prev;
	struct ys_arp_entry *next;
};

struct ys_arp_table
{
    struct ys_arp_entry* entries;
	int count;
};

#endif
