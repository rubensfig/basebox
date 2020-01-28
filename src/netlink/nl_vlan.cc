/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cassert>

#include <glog/logging.h>
#include <netlink/route/link.h>
#include <netlink/route/link/vlan.h>

#include "cnetlink.h"
#include "nl_output.h"
#include "nl_vlan.h"
#include "sai.h"

namespace basebox {

nl_vlan::nl_vlan(cnetlink *nl) : swi(nullptr), nl(nl) {}

int nl_vlan::add_vlan(rtnl_link *link, uint16_t vid, bool tagged,
                      uint16_t vrf_id) {
  assert(swi);

  VLOG(2) << __FUNCTION__ << ": add vid=" << vid << " tagged=" << tagged
          << " vrf=" << vrf_id;
  if (!is_vid_valid(vid)) {
    LOG(ERROR) << __FUNCTION__ << ": invalid vid " << vid;
    return -EINVAL;
  }

  uint32_t port_id = nl->get_port_id(link);

  if (port_id == 0) {
    VLOG(1) << __FUNCTION__ << ": unknown interface " << OBJ_CAST(link);
    return -EINVAL;
  }

  int rv = swi->ingress_port_vlan_add(port_id, vid, !tagged, vrf_id);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to setup ingress vlan 1 (untagged) on port_id="
               << port_id << "; rv=" << rv;
    return rv;
  }

  // setup egress interface
  rv = swi->egress_port_vlan_add(port_id, vid, !tagged);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to setup egress vlan 1 (untagged) on port_id="
               << port_id << "; rv=" << rv;
    (void)swi->ingress_port_vlan_remove(port_id, 1, true);

    return rv;
  }

  auto key = std::make_pair(port_id, vid);
  auto refcount = port_vlan.find(key);
  if (refcount == port_vlan.end()) {
    port_vlan.emplace(key, 1);
  } else
    refcount->second++;

  return rv;
}

int nl_vlan::remove_vlan(rtnl_link *link, uint16_t vid, bool tagged,
                         uint16_t vrf_id) {
  assert(swi);

  if (!is_vid_valid(vid)) {
    LOG(ERROR) << __FUNCTION__ << ": invalid vid " << vid;
    return -EINVAL;
  }

  int rv = 0;

  uint32_t port_id = nl->get_port_id(link);

  if (port_id == 0) {
    VLOG(1) << __FUNCTION__ << ": unknown link " << OBJ_CAST(link);
    return -EINVAL;
  }

  // check for refcount
  auto key = std::make_pair(port_id, vid);
  auto refcount = port_vlan.find(key);
  if (refcount != port_vlan.end()) {
    refcount->second--;
    return rv;
  } else if (refcount->second == 1)
    port_vlan.erase(refcount);

  // remove vid at ingress
  rv = swi->ingress_port_vlan_remove(port_id, vid, !tagged, vrf_id);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed with rv=" << rv
               << " to remove vid=" << vid << "(tagged=" << tagged
               << ") of link " << OBJ_CAST(link);
    return rv;
  }

  // delete all FM pointing to this group first
  rv = swi->l2_addr_remove_all_in_vlan(port_id, vid);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed with rv= " << rv
               << " to remove all bridge entries in vid=" << vid << " link "
               << OBJ_CAST(link);
    return rv;
  }

  // remove vid from egress
  rv = swi->egress_bridge_port_vlan_remove(port_id, vid);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed with rv= " << rv
               << " to remove vid=" << vid << " of link " << OBJ_CAST(link);
    return rv;
  }

  return rv;
}

static int find_next_bit(int i, uint32_t x) {
  int j;

  if (i >= 32)
    return -1;

  /* find first bit */
  if (i < 0)
    return __builtin_ffs(x);

  /* mask off prior finds to get next */
  j = __builtin_ffs(x >> i);
  return j ? j + i : 0;
}

std::vector<uint16_t> parse_vlan_bitmap(const uint32_t *bitmap) {
  int i = -1, j;
  int start = -1, prev = -1;
  int done;
  std::vector<uint16_t> _vid_arr;

  for (int k = 0; k < RTNL_LINK_BRIDGE_VLAN_BITMAP_LEN; k++) {
    int base_bit;
    uint32_t a = bitmap[k];

    base_bit = k * 32;
    i = -1;
    done = 0;
    while (!done) {
      j = find_next_bit(i, a);
      if (j > 0) {
        int vid = j - 1 + base_bit;
        _vid_arr.push_back(vid);

        /* first hit of any bit */
        if (start < 0 && prev < 0) {
          start = prev = j - 1 + base_bit;
        }
        /* this bit is a continuation of prior bits */
        if (j - 2 + base_bit == prev) {
          prev++;
        }

        i = j;
      } else
        done = 1;
    }
  }

  return _vid_arr;
}

std::vector<uint16_t> nl_vlan::get_bridge_vids(rtnl_link *link) {
  assert(link);

  if (!rtnl_link_get_master(link)) {
    LOG(ERROR) << __FUNCTION__ << ": interface is not in bridge";
  }

  std::deque<rtnl_link *> bridge_ports;
  nl->get_bridge_ports(rtnl_link_get_master(link), &bridge_ports);

  auto it = bridge_ports.begin();
  while (true) {
    if (rtnl_link_get_ifindex(*it) == rtnl_link_get_ifindex(link))
      break;

    it++;
  }

  auto ret = rtnl_link_bridge_get_port_vlan(*it);
  if(!ret)
    return std::vector<uint16_t>();

  return parse_vlan_bitmap(ret->vlan_bitmap);
}

uint16_t nl_vlan::get_vid(rtnl_link *link) {
  uint16_t vid = 0;
  uint32_t pport_id = nl->get_port_id(link);
  auto lt = get_link_type(link);

  if (!nl->is_bridge_interface(link) && pport_id == 0) {
    VLOG(2) << __FUNCTION__ << ": invalid interface";
    return vid;
  }

  switch (lt) {
  case LT_BRIDGE:
    VLOG(2) << __FUNCTION__ << ": bridge default vid " << default_vid;
    vid = default_vid;
    break;
  case LT_TUN:
  case LT_BOND:
    vid = default_vid;
    break;
  case LT_VLAN:
  case LT_VRF_SLAVE:
    vid = rtnl_link_vlan_get_id(link);
    break;
  default:
    if (rtnl_link_get_ifindex(link) != 1)
      LOG(ERROR) << __FUNCTION__ << ": unsupported link type " << lt
                 << " of link " << OBJ_CAST(link);
    break;
  }

  VLOG(2) << __FUNCTION__ << ": vid=" << vid << " interface=" << OBJ_CAST(link);

  return vid;
}

} // namespace basebox
