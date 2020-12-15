/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019-2020 Authors of Cilium */

#ifndef __EGRESS_GW_H_
#define __EGRESS_GW_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "eps.h"
#include "tailcall.h"
#include "nat.h"
#include "edt.h"
#include "lb.h"
#include "common.h"
#include "overloadable.h"
#include "conntrack.h"
#include "csum.h"
#include "encap.h"
#include "trace.h"

/*
static __always_inline int nodeport_nat_ipv4_fwd(struct __ctx_buff *ctx,
						 const __be32 addr)
{
    return 0;
}

*/

static __always_inline int handle_nat_fwd_ipv4(struct __ctx_buff *ctx)
{
    int ret = CTX_ACT_OK;
    struct egress_endpoint_info *info;
    struct ipv4_nat_target target = {
      .min_port = 32767,
      .max_port = 43835,
    };
    bool from_endpoint = true;
    struct iphdr *ip4;
    void *data, *data_end;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

    info = lookup_ip4_egress_endpoint(ip4->saddr, ip4->daddr);
	if (!info) {
		printk("missing egress endpoint\n");
        return DROP_INVALID;
	}
    
    // TODO: Fix 192.168.33.13;
    // __be32 addr = 192 + (168<<8) + (33<<16) + (13<<24);
    target.addr = info->egress_ip4;

    ret = snat_v4_process(ctx, NAT_DIR_EGRESS, &target,
				      from_endpoint);
    return ret;
}


static __always_inline int egress_nat_fwd(struct __ctx_buff *ctx)
{
    int ret = CTX_ACT_OK;
	__u16 proto;

    if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		printk("snat_v4_process %d\n", proto);
        ret = handle_nat_fwd_ipv4(ctx);
        printk("snat_v4_process result: %d\n", ret);
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		break;
#endif /* ENABLE_IPV6 */
	default:
		break;
	}
	return ret;
}


#endif /* __EGRESS_GW_H_ */
