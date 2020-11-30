/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cstdint>
#include <map>

extern "C" {
struct rtnl_link;
}

namespace basebox {

class cnetlink;
class switch_interface;

class nl_vlan {
public:
  nl_vlan(cnetlink *nl);
  ~nl_vlan() {}

  void register_switch_interface(switch_interface *swi) { this->swi = swi; }

  int add_vlan(rtnl_link *link, uint16_t vid, bool tagged, uint16_t vrf_id = 0);
  int remove_vlan(rtnl_link *link, uint16_t vid, bool tagged,
                  uint16_t vrf_id = 0);
  int remove_ingress_vlan(uint32_t port_id, uint16_t vid, bool tagged,
                          uint16_t vrf_id = 0);

  uint16_t get_vid(rtnl_link *link);

  void handle_vrf_attach(rtnl_link *old_link, rtnl_link *new_link);
  void handle_vrf_detach(rtnl_link *old_link, rtnl_link *new_link);

  bool is_vid_valid(uint16_t vid) const {
    if (vid < vid_low || vid > vid_high)
      return false;
    return true;
  }

private:
  static const uint16_t vid_low = 1;
  static const uint16_t vid_high = 0xfff;
  static const uint16_t default_vid = vid_low;

  // ifindex - vlan - refcount
  std::map<std::pair<uint32_t, uint16_t>, uint32_t> port_vlan;

  switch_interface *swi;
  cnetlink *nl;
};

} // namespace basebox
