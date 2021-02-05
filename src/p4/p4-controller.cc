/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#include <linux/if_ether.h>
#include <grpc++/grpc++.h>
#include <systemd/sd-daemon.h>

#include "p4/v1/p4runtime.grpc.pb.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4-controller.h"

namespace basebox {
using namespace grpc;

void P4Controller::setup_connection() {
  std::shared_ptr<grpc::Channel> chan =
      grpc::CreateChannel(remote, grpc::InsecureChannelCredentials());
  ::grpc::ClientContext context;
  
  ::p4::v1::StreamMessageRequest req = ::p4::v1::StreamMessageRequest();
  ::p4::v1::StreamMessageResponse res = ::p4::v1::StreamMessageResponse();
  chan->GetState(true);

  auto stub_ = ::p4::v1::P4Runtime::NewStub(chan);
  std::shared_ptr<grpc_impl::ClientReaderWriter<p4::v1::StreamMessageRequest, p4::v1::StreamMessageResponse> > _stream = stub_->StreamChannel(&context);

  auto arb = req.mutable_arbitration();
  arb->set_device_id( (::google::protobuf::uint64)device_id);
  arb->mutable_election_id()->set_high(1);
  arb->mutable_election_id()->set_low(0);

  _stream->Write(req);
  auto ret = _stream->Read(&res);

  if (res.arbitration().status().code() == 0)
	  VLOG(1) << __FUNCTION__ << " MASTER";

  stream = std::move(_stream);
}

int P4Controller::lag_create(uint32_t *lag_id, std::string name,
                           uint8_t mode) noexcept {
	return 0;
}

int P4Controller::lag_remove(uint32_t lag_id) noexcept {
	return 0;
}

int P4Controller::lag_add_member(uint32_t lag_id, uint32_t port_id) noexcept {
	return 0;
}

int P4Controller::lag_remove_member(uint32_t lag_id, uint32_t port_id) noexcept {
	return 0;
}

int P4Controller::lag_set_member_active(uint32_t lag_id, uint32_t port_id,
                                      uint8_t active) noexcept {
	return 0;
}

int P4Controller::lag_set_mode(uint32_t lag_id, uint8_t mode) noexcept {
	return 0;
}

int P4Controller::overlay_tunnel_add(uint32_t tunnel_id) noexcept {
	return 0;
}

int P4Controller::overlay_tunnel_remove(uint32_t tunnel_id) noexcept {
	return 0;
}

int P4Controller::l2_addr_remove_all_in_vlan(uint32_t port,
                                           uint16_t vid) noexcept {
	return 0;
}

int P4Controller::l2_addr_add(uint32_t port, uint16_t vid,
                            const rofl::caddress_ll &mac, bool filtered,
                            bool permanent) noexcept {
	return 0;
}

int P4Controller::l2_addr_remove(uint32_t port, uint16_t vid,
                               const rofl::caddress_ll &mac) noexcept {
	return 0;
}

int P4Controller::l2_overlay_addr_add(uint32_t lport, uint32_t tunnel_id,
                                    const rofl::cmacaddr &mac,
                                    bool permanent) noexcept {
	return 0;
}

int P4Controller::l2_overlay_addr_remove(uint32_t tunnel_id, uint32_t lport_id,
                                       const rofl::cmacaddr &mac) noexcept {
	return 0;
}

int P4Controller::l2_multicast_group_add(uint32_t port, uint16_t vid,
                                       rofl::caddress_ll mc_group) noexcept {
	return 0;
}

int P4Controller::l2_multicast_group_remove(uint32_t port, uint16_t vid,
                                          rofl::caddress_ll mc_group) noexcept {
	return 0;
}

int P4Controller::l2_multicast_addr_add(uint32_t port, uint16_t vid,
                                      const rofl::caddress_ll &mac) noexcept {
	return 0;
}

int P4Controller::l2_multicast_addr_remove(
    uint32_t port, uint16_t vid, const rofl::caddress_ll &mac) noexcept {
	return 0;
}

int P4Controller::l3_termination_add(uint32_t sport, uint16_t vid,
                                   const rofl::caddress_ll &dmac) noexcept {
	return 0;
}

int P4Controller::l3_termination_add_v6(uint32_t sport, uint16_t vid,
                                      const rofl::caddress_ll &dmac) noexcept {
	return 0;
}

int P4Controller::l3_termination_remove(uint32_t sport, uint16_t vid,
                                      const rofl::caddress_ll &dmac) noexcept {
	return 0;
}

int P4Controller::l3_termination_remove_v6(
    uint32_t sport, uint16_t vid, const rofl::caddress_ll &dmac) noexcept {
	return 0;
}

int P4Controller::l3_egress_create(uint32_t port, uint16_t vid,
                                 const rofl::caddress_ll &src_mac,
                                 const rofl::caddress_ll &dst_mac,
                                 uint32_t *l3_interface_id) noexcept {
	return 0;
}

int P4Controller::l3_egress_update(uint32_t port, uint16_t vid,
                                 const rofl::caddress_ll &src_mac,
                                 const rofl::caddress_ll &dst_mac,
                                 uint32_t *l3_interface_id) noexcept {
	return 0;
}

int P4Controller::l3_egress_remove(uint32_t l3_interface_id) noexcept {
	return 0;
}

int P4Controller::l3_unicast_host_add(const rofl::caddress_in4 &ipv4_dst,
                                    uint32_t l3_interface_id, bool is_ecmp,
                                    bool update_route,
                                    uint16_t vrf_id) noexcept {
	return 0;
}

int P4Controller::l3_unicast_host_add(const rofl::caddress_in6 &ipv6_dst,
                                    uint32_t l3_interface_id, bool is_ecmp,
                                    bool update_route,
                                    uint16_t vrf_id) noexcept {
	return 0;
}

int P4Controller::l3_unicast_host_remove(const rofl::caddress_in4 &ipv4_dst,
                                       uint16_t vrf_id) noexcept {
	return 0;
}

int P4Controller::l3_unicast_host_remove(const rofl::caddress_in6 &ipv6_dst,
                                       uint16_t vrf_id) noexcept {
	return 0;
}

int P4Controller::l3_unicast_route_add(const rofl::caddress_in4 &ipv4_dst,
                                     const rofl::caddress_in4 &mask,
                                     uint32_t l3_interface_id, bool is_ecmp,
                                     bool update_route,
                                     uint16_t vrf_id) noexcept {
	return 0;
}

int P4Controller::l3_unicast_route_add(const rofl::caddress_in6 &ipv6_dst,
                                     const rofl::caddress_in6 &mask,
                                     uint32_t l3_interface_id, bool is_ecmp,
                                     bool update_route,
                                     uint16_t vrf_id) noexcept {
	return 0;
}

int P4Controller::l3_ecmp_add(uint32_t l3_ecmp_id,
                            const std::set<uint32_t> &l3_interfaces) noexcept {
	return 0;
}

int P4Controller::l3_ecmp_remove(uint32_t l3_ecmp_id) noexcept {
	return 0;
}

int P4Controller::l3_unicast_route_remove(const rofl::caddress_in4 &ipv4_dst,
                                        const rofl::caddress_in4 &mask,
                                        uint16_t vrf_id) noexcept {
	return 0;
}

int P4Controller::l3_unicast_route_remove(const rofl::caddress_in6 &ipv6_dst,
                                        const rofl::caddress_in6 &mask,
                                        uint16_t vrf_id) noexcept {
	return 0;
}

int P4Controller::ingress_port_vlan_accept_all(uint32_t port) noexcept {
	return 0;
}

int P4Controller::ingress_port_vlan_drop_accept_all(uint32_t port) noexcept {
	return 0;
}

int P4Controller::ingress_port_vlan_add(uint32_t port, uint16_t vid, bool pvid,
                                      uint16_t vrf_id) noexcept {
	return 0;
}

int P4Controller::ingress_port_vlan_remove(uint32_t port, uint16_t vid, bool pvid,
                                         uint16_t vrf_id) noexcept {
	return 0;
}

int P4Controller::egress_port_vlan_accept_all(uint32_t port) noexcept {
	return 0;
}

int P4Controller::egress_port_vlan_drop_accept_all(uint32_t port) noexcept {
	return 0;
}

int P4Controller::egress_port_vlan_add(uint32_t port, uint16_t vid,
                                     bool untagged) noexcept {
	return 0;
}

int P4Controller::egress_port_vlan_remove(uint32_t port, uint16_t vid) noexcept {
	return 0;
}

int P4Controller::add_l2_overlay_flood(uint32_t tunnel_id,
                                     uint32_t lport_id) noexcept {
	return 0;
}

int P4Controller::del_l2_overlay_flood(uint32_t tunnel_id,
                                     uint32_t lport_id) noexcept {
	return 0;
}

int P4Controller::egress_bridge_port_vlan_add(uint32_t port, uint16_t vid,
                                            bool untagged) noexcept {
	return 0;
}

int P4Controller::egress_bridge_port_vlan_remove(uint32_t port,
                                               uint16_t vid) noexcept {
	return 0;
}

int P4Controller::set_egress_tpid(uint32_t port) noexcept {
	return 0;
}

int P4Controller::delete_egress_tpid(uint32_t port) noexcept {
	return 0;
}

int P4Controller::enqueue(uint32_t port_id, basebox::packet *pkt) noexcept {
	return 0;
}

int P4Controller::subscribe_to(enum swi_flags flags) noexcept {
	return 0;
}

int P4Controller::get_statistics(uint64_t port_no, uint32_t number_of_counters,
                               const sai_port_stat_t *counter_ids,
                               uint64_t *counters) noexcept {
	return 0;
}

int P4Controller::tunnel_tenant_create(uint32_t tunnel_id,
                                     uint32_t vni) noexcept {
	return 0;
}

int P4Controller::tunnel_tenant_delete(uint32_t tunnel_id) noexcept {
	return 0;
}

int P4Controller::tunnel_next_hop_create(uint32_t next_hop_id, uint64_t src_mac,
                                       uint64_t dst_mac, uint32_t physical_port,
                                       uint16_t vlan_id) noexcept {
	return 0;
}

int P4Controller::tunnel_next_hop_modify(uint32_t next_hop_id, uint64_t src_mac,
                                       uint64_t dst_mac, uint32_t physical_port,
                                       uint16_t vlan_id) noexcept {
	return 0;
}

int P4Controller::tunnel_next_hop_delete(uint32_t next_hop_id) noexcept {
	return 0;
}

int P4Controller::tunnel_access_port_create(uint32_t port_id,
                                          const std::string &port_name,
                                          uint32_t physical_port,
                                          uint16_t vlan_id,
                                          bool untagged) noexcept {
	return 0;
}

int P4Controller::tunnel_port_delete(uint32_t port_id) noexcept {
	return 0;
}

int P4Controller::tunnel_enpoint_create(
    uint32_t port_id, const std::string &port_name, uint32_t remote_ipv4,
    uint32_t local_ipv4, uint32_t ttl, uint32_t next_hop_id,
    uint32_t terminator_udp_dst_port, uint32_t initiator_udp_dst_port,
    uint32_t udp_src_port_if_no_entropy, bool use_entropy) noexcept {
	return 0;
}

int P4Controller::tunnel_port_tenant_add(uint32_t lport_id,
                                       uint32_t tunnel_id) noexcept {
	return 0;
}

int P4Controller::tunnel_port_tenant_remove(uint32_t lport_id,
                                          uint32_t tunnel_id) noexcept {
	return 0;
}

int P4Controller::ofdpa_stg_destroy(uint16_t vlan_id) noexcept { return 0; }

int P4Controller::ofdpa_stg_state_port_set(uint32_t port_id, uint16_t vlan_id,
                                         std::string state) noexcept {
	return 0;
}

int P4Controller::ofdpa_stg_create(uint16_t vlan_id) noexcept {
	return 0;
}

} // namespace basebox
