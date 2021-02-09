/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <sys/types.h>
#include <sys/wait.h>

#include <exception>
#include <iostream>
#include <fstream>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <rofl/common/cthread.hpp>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <arpa/inet.h>
#include <bitset>

#include <glog/logging.h>
#include <grpc++/grpc++.h>
#include "p4/v1/p4runtime.grpc.pb.h"
#include "p4/v1/p4runtime.pb.h"

#include "sai.h"

namespace basebox {

class P4Controller : public basebox::switch_interface,
                     public rofl::cthread_env {

  P4Controller(const P4Controller &) = delete;
  P4Controller &operator=(const P4Controller &) = delete;
  std::unique_ptr<nbi> nb;

public:
  P4Controller(std::unique_ptr<nbi> nb) : nb(std::move(nb)), thread(1) {
    this->nb->register_switch(this);
    ::grpc::ClientContext context;

    chan = grpc::CreateChannel(remote, grpc::InsecureChannelCredentials());
    stub = ::p4::v1::P4Runtime::NewStub(chan);
    stream = stub->StreamChannel(&global_context);
    p4_program_fd = open(p4_program_dir.c_str(), O_RDONLY);
    p4_device_fd = open(p4_device_dir.c_str(), O_RDONLY);

    try {
      thread.start("p4-controller");
      setup_p4_connection();
      setup_p4_pipeline_config();
      get_p4_info();
      setup_gnmi_connection();
    } catch (...) {
      LOG(FATAL) << __FUNCTION__ << ": caught unknown exception";
    }
  }

  ~P4Controller() override {
    close(p4_program_fd);
    close(p4_device_fd);
  }

  void start() noexcept;

public:
  // cthread_env
  void handle_wakeup(rofl::cthread &thread) override;
  void handle_read_event(rofl::cthread &thread, int fd) override;
  void handle_write_event(rofl::cthread &thread, int fd) override;
  void handle_timeout(rofl::cthread &thread, uint32_t timer_id) override;

  // switch_interface
  int lag_create(uint32_t *lag_id, std::string name,
                 uint8_t mode) noexcept override;
  int lag_remove(uint32_t lag_id) noexcept override;
  int lag_add_member(uint32_t lag_id, uint32_t port_id) noexcept override;
  int lag_remove_member(uint32_t lag_id, uint32_t port_id) noexcept override;
  int lag_set_member_active(uint32_t lag_id, uint32_t port_id,
                            uint8_t active) noexcept override;
  int lag_set_mode(uint32_t lag_id, uint8_t mode) noexcept override;

  int overlay_tunnel_add(uint32_t tunnel_id) noexcept override;
  int overlay_tunnel_remove(uint32_t tunnel_id) noexcept override;

  int l2_addr_remove_all_in_vlan(uint32_t port, uint16_t vid) noexcept override;
  int l2_addr_add(uint32_t port, uint16_t vid, const rofl::caddress_ll &mac,
                  bool filtered, bool permanent) noexcept override;
  int l2_addr_remove(uint32_t port, uint16_t vid,
                     const rofl::caddress_ll &mac) noexcept override;

  int l2_overlay_addr_add(uint32_t lport, uint32_t tunnel_id,
                          const rofl::cmacaddr &mac,
                          bool permanent) noexcept override;
  int l2_overlay_addr_remove(uint32_t tunnel_id, uint32_t lport_id,
                             const rofl::cmacaddr &mac) noexcept override;
  int l2_multicast_addr_add(uint32_t port, uint16_t vid,
                            const rofl::caddress_ll &mac) noexcept override;
  int l2_multicast_addr_remove(uint32_t port, uint16_t vid,
                               const rofl::caddress_ll &mac) noexcept override;

  /* @ Layer 2 Multicast { */
  int l2_multicast_group_add(uint32_t port, uint16_t vid,
                             rofl::caddress_ll mc_group) noexcept override;
  int l2_multicast_group_remove(uint32_t port, uint16_t vid,
                                rofl::caddress_ll mc_group) noexcept override;
  /* @} */

  // dmac = Multicast or Unicast MAC Address
  int l3_termination_add(uint32_t sport, uint16_t vid,
                         const rofl::caddress_ll &dmac) noexcept override;
  int l3_termination_add_v6(uint32_t sport, uint16_t vid,
                            const rofl::caddress_ll &dmac) noexcept override;
  int l3_termination_remove(uint32_t sport, uint16_t vid,
                            const rofl::caddress_ll &dmac) noexcept override;
  int l3_termination_remove_v6(uint32_t sport, uint16_t vid,
                               const rofl::caddress_ll &dmac) noexcept override;

  int l3_egress_create(uint32_t port, uint16_t vid,
                       const rofl::caddress_ll &src_mac,
                       const rofl::caddress_ll &dst_mac,
                       uint32_t *l3_interface) noexcept override;
  int l3_egress_update(uint32_t port, uint16_t vid,
                       const rofl::caddress_ll &src_mac,
                       const rofl::caddress_ll &dst_mac,
                       uint32_t *l3_interface_id) noexcept override;
  int l3_egress_remove(uint32_t l3_interface) noexcept override;

  int l3_unicast_host_add(const rofl::caddress_in4 &ipv4_dst,
                          uint32_t l3_interface, bool is_ecmp,
                          bool update_route,
                          uint16_t vrf_id = 0) noexcept override;
  int l3_unicast_host_remove(const rofl::caddress_in4 &ipv4_dst,
                             uint16_t vrf_id = 0) noexcept override;

  int l3_unicast_host_add(const rofl::caddress_in6 &ipv6_dst,
                          uint32_t l3_interface, bool is_ecmp,
                          bool update_route,
                          uint16_t vrf_id = 0) noexcept override;
  int l3_unicast_host_remove(const rofl::caddress_in6 &ipv6_dst,
                             uint16_t vrf_id = 0) noexcept override;

  int l3_unicast_route_add(const rofl::caddress_in4 &ipv4_dst,
                           const rofl::caddress_in4 &mask,
                           uint32_t l3_interface, bool is_ecmp,
                           bool update_route,
                           uint16_t vrf_id = 0) noexcept override;
  int l3_unicast_route_remove(const rofl::caddress_in4 &ipv4_dst,
                              const rofl::caddress_in4 &mask,
                              uint16_t vrf_id = 0) noexcept override;

  int l3_unicast_route_add(const rofl::caddress_in6 &ipv6_dst,
                           const rofl::caddress_in6 &mask,
                           uint32_t l3_interface, bool is_ecmp,
                           bool update_route,
                           uint16_t vrf_id = 0) noexcept override;
  int l3_unicast_route_remove(const rofl::caddress_in6 &ipv6_dst,
                              const rofl::caddress_in6 &mask,
                              uint16_t vrf_id = 0) noexcept override;

  int l3_ecmp_add(uint32_t l3_ecmp_id,
                  const std::set<uint32_t> &l3_interfaces) noexcept override;
  int l3_ecmp_remove(uint32_t l3_ecmp_id) noexcept override;

  int ingress_port_vlan_accept_all(uint32_t port) noexcept override;
  int ingress_port_vlan_drop_accept_all(uint32_t port) noexcept override;
  int ingress_port_vlan_add(uint32_t port, uint16_t vid, bool pvid,
                            uint16_t vrf_id = 0) noexcept override;
  int ingress_port_vlan_remove(uint32_t port, uint16_t vid, bool pvid,
                               uint16_t vrf_id = 0) noexcept override;

  int egress_port_vlan_accept_all(uint32_t port) noexcept override;
  int egress_port_vlan_drop_accept_all(uint32_t port) noexcept override;

  int egress_port_vlan_add(uint32_t port, uint16_t vid,
                           bool untagged) noexcept override;
  int egress_port_vlan_remove(uint32_t port, uint16_t vid) noexcept override;

  int add_l2_overlay_flood(uint32_t tunnel_id,
                           uint32_t lport_id) noexcept override;
  int del_l2_overlay_flood(uint32_t tunnel_id,
                           uint32_t lport_id) noexcept override;

  int egress_bridge_port_vlan_add(uint32_t port, uint16_t vid,
                                  bool untagged) noexcept override;
  int egress_bridge_port_vlan_remove(uint32_t port,
                                     uint16_t vid) noexcept override;
  int set_egress_tpid(uint32_t port) noexcept override;
  int delete_egress_tpid(uint32_t port) noexcept override;

  int get_statistics(uint64_t port_no, uint32_t number_of_counters,
                     const sai_port_stat_t *counter_ids,
                     uint64_t *counters) noexcept override;

  /* IO */
  int enqueue(uint32_t port_id, basebox::packet *pkt) noexcept override;

  bool is_connected() noexcept override { return connected; }

  int subscribe_to(enum swi_flags flags) noexcept override;

  /* tunnel */
  int tunnel_tenant_create(uint32_t tunnel_id, uint32_t vni) noexcept override;
  int tunnel_tenant_delete(uint32_t tunnel_id) noexcept override;

  int tunnel_next_hop_create(uint32_t next_hop_id, uint64_t src_mac,
                             uint64_t dst_mac, uint32_t physical_port,
                             uint16_t vlan_id) noexcept override;
  int tunnel_next_hop_modify(uint32_t next_hop_id, uint64_t src_mac,
                             uint64_t dst_mac, uint32_t physical_port,
                             uint16_t vlan_id) noexcept override;
  int tunnel_next_hop_delete(uint32_t next_hop_id) noexcept override;

  int tunnel_access_port_create(uint32_t port_id, const std::string &port_name,
                                uint32_t physical_port, uint16_t vlan_id,
                                bool untagged) noexcept override;
  int tunnel_enpoint_create(uint32_t port_id, const std::string &port_name,
                            uint32_t remote_ipv4, uint32_t local_ipv4,
                            uint32_t ttl, uint32_t next_hop_id,
                            uint32_t terminator_udp_dst_port,
                            uint32_t initiator_udp_dst_port,
                            uint32_t udp_src_port_if_no_entropy,
                            bool use_entropy) noexcept override;
  int tunnel_port_delete(uint32_t port_id) noexcept override;

  int tunnel_port_tenant_add(uint32_t lport_id,
                             uint32_t tunnel_id) noexcept override;
  int tunnel_port_tenant_remove(uint32_t lport_id,
                                uint32_t tunnel_id) noexcept override;

  /* STP */
  // This set of functions is currently defined in our datamodel
  // but no implementation. It is intented that these functions
  // provide the Per VLAN STP functions
  // The stg_create and stg_destroy functions implement creating
  // other Spanning Tree Groups/Instances
  // the stg_vlan_add and stg_vlan_remove function implements adding/removing
  // VLANS from a certain STG
  int ofdpa_stg_create(uint16_t vlan_id) noexcept override;
  int ofdpa_stg_destroy(uint16_t vlan_id) noexcept override;

  int ofdpa_stg_state_port_set(uint32_t port_id, uint16_t vlan_id,
                               std::string state) noexcept override;

  /* print this */
  friend std::ostream &operator<<(std::ostream &os, const P4Controller &box) {
    os << "<P4Controller>" << std::endl;
    return os;
  }

private:
  bool connected;
  std::string remote = "localhost:50001";
  std::string p4_program_dir = "/home/rubens/code/basebox/p4dir/p4info.txt";
  std::string p4_device_dir = "/home/rubens/code/basebox/p4dir/bmv2.json";
  int p4_program_fd;
  int p4_device_fd;
  uint64_t device_id = 1;
  rofl::cthread thread;


  void setup_p4_connection();
  void setup_p4_pipeline_config();
  void setup_gnmi_connection();
  void get_p4_info();

  std::string packed_mac_address(std::string mac) {
    std::stringstream ret;
    auto mac_c = strdup(mac.c_str());
    auto buff = strtok(mac_c,":");
    while (buff != NULL) {
       ret << std::hex << (unsigned char)atoi(buff);
       buff = strtok(NULL,":");
    }

    VLOG(1) << ret.str();
    free(mac_c);
    return ret.str();
  }

  std::string packed_ip_address(std::string ip, int prefixlen) {
    std::stringstream ret;
    auto ip_c = strdup(ip.c_str());

    auto buff = strtok(ip_c,".");
    while (buff != NULL) {
       ret << std::hex << (unsigned char)atoi(buff);
       buff = strtok(NULL,".");
    }

    VLOG(1) << ret.str();
    free(ip_c);
    return ret.str();
  }

  std::string open_file(::google::protobuf::io::FileInputStream *input) {
    const void *buffer;
    int size;
    std::string re;

    while (input->Next(&buffer, &size))
      re += (char *)buffer;

    return re;
  }

  ::grpc::ClientContext global_context;
  std::unique_ptr<grpc_impl::ClientReaderWriter<p4::v1::StreamMessageRequest,
                                                p4::v1::StreamMessageResponse>>
      stream;
  std::shared_ptr<grpc::Channel> chan;
  std::unique_ptr<::p4::v1::P4Runtime::Stub> stub;
}; // class P4Controller

} // end of namespace basebox
