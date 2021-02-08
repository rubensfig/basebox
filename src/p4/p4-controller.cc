/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <arpa/inet.h>
#include <google/protobuf/any.h>
#include <google/protobuf/any.pb.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include <linux/if_ether.h>
#include <grpc++/grpc++.h>
#include <systemd/sd-daemon.h>

#include "p4/v1/p4runtime.grpc.pb.h"
#include "p4/v1/p4runtime.pb.h"
#include "gnmi/gnmi.grpc.pb.h"
#include "gnmi/gnmi.pb.h"
#include "openconfig/openconfig.pb.h"
#include "p4-controller.h"

namespace basebox {
using namespace grpc;

void P4Controller::handle_wakeup(rofl::cthread &thread) {}
void P4Controller::handle_read_event(rofl::cthread &thread, int fd) {}
void P4Controller::handle_write_event(rofl::cthread &thread, int fd) {}
void P4Controller::handle_timeout(rofl::cthread &thread, uint32_t timer_id) {}

// handle arbitration
void P4Controller::setup_p4_connection() {
  ::p4::v1::StreamMessageRequest req = ::p4::v1::StreamMessageRequest();
  ::p4::v1::StreamMessageResponse res = ::p4::v1::StreamMessageResponse();
  chan->GetState(true);

  auto arb = req.mutable_arbitration();
  arb->set_device_id((::google::protobuf::uint64)device_id);
  arb->mutable_role()->set_id(1);
  arb->mutable_election_id()->set_high(0);
  arb->mutable_election_id()->set_low(1);

  stream->Write(req);
  auto arb_res = stream->Read(&res);

  if (res.arbitration().status().code() == 0)
    VLOG(1) << __FUNCTION__ << " MASTER";
}

// setup pipeline config
void P4Controller::setup_p4_pipeline_config() {
  // uint64 device_id = 1;
  // uint64 role_id = 2;
  // Uint128 election_id = 3;
  // Action action = 4;
  // ForwardingPipelineConfig config = 5;
  ::grpc::ClientContext context;
  ::p4::v1::SetForwardingPipelineConfigRequest config_request =
      ::p4::v1::SetForwardingPipelineConfigRequest();
  ::p4::v1::SetForwardingPipelineConfigResponse config_response =
      ::p4::v1::SetForwardingPipelineConfigResponse();
  auto program_stream = ::google::protobuf::io::FileInputStream(p4_program_fd);
  auto device_stream = ::google::protobuf::io::FileInputStream(p4_device_fd);

  config_request.set_device_id((::google::protobuf::uint64)device_id);
  config_request.set_role_id((::google::protobuf::uint64)1);
  config_request.mutable_election_id()->set_high(0);
  config_request.mutable_election_id()->set_low(1);
  config_request.set_action(
      ::p4::v1::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT);
  auto pipeline_config = config_request.mutable_config();
  auto p4info = pipeline_config->mutable_p4info();

  // p4info->ParseFromString(p4_program);
  ::google::protobuf::TextFormat::Merge(&program_stream, p4info);
  // pipeline_config->set_p4_device_config(open_file(&device_stream));

  ::grpc::Status st = stub->SetForwardingPipelineConfig(
      &context, config_request, &config_response);
  VLOG(1) << st.error_message();
}

void P4Controller::get_p4_info() {
  ::grpc::ClientContext context;
  ::p4::v1::GetForwardingPipelineConfigRequest config_request =
      ::p4::v1::GetForwardingPipelineConfigRequest();
  ::p4::v1::GetForwardingPipelineConfigResponse config_response =
      ::p4::v1::GetForwardingPipelineConfigResponse();

  config_request.set_device_id((::google::protobuf::uint64)device_id);
  config_request.set_response_type(
      ::p4::v1::
          GetForwardingPipelineConfigRequest_ResponseType_P4INFO_AND_COOKIE);

  ::grpc::Status st = stub->GetForwardingPipelineConfig(
      &context, config_request, &config_response);
  VLOG(1) << st.error_code() << " " << st.error_message();

  VLOG(1) << __FUNCTION__ << config_response.config().p4info().DebugString();
}

void P4Controller::setup_gnmi_connection() {
  ::grpc::ClientContext context;
  ::gnmi::GetRequest req;
  ::gnmi::GetResponse res;
  ::openconfig::Device dev;
  // ifindex, speed, status
  std::map<std::string, int> port_map;
  std::deque<nbi::port_notification_data> ntfys;

  auto path = req.mutable_path()->Add();
  path->add_elem()->set_name("interfaces");
  path->add_elem()->set_name("interface");

  req.set_type(
      ::gnmi::GetRequest_DataType_ALL); // ALL - gnmi::GetRequest::DataType::All
  req.set_encoding(::gnmi::Encoding::PROTO);
  auto stub_ = ::gnmi::gNMI::NewStub(chan);
  auto rpc_res = stub_->Get(&context, req, &res);

  // VLOG(1) << res.DebugString();
  for (auto not_it : res.notification()) {
    // VLOG(1) << not_it.DebugString();

    for (auto up_it : not_it.update()) {
      for (auto elem_it : up_it.path().elem()) {
        if (elem_it.name() == "interface") {
          // VLOG(1) << elem_it.key().at("name");
          auto name = elem_it.key().at("name");
          auto pm_it = port_map.find(name);
          if (pm_it == port_map.end())
            port_map.emplace(name, 1);
        }
      }
    }
  }

  int id = 1;
  for (auto it : port_map) {
    nbi::port_notification_data dt;
    dt.name = it.first;
    dt.port_id = id++;
    dt.ev = nbi::PORT_EVENT_ADD;
    dt.name = it.first;
    dt.status = true;
    dt.speed = 100000;
    dt.duplex = 0;

    ntfys.emplace_back(dt);
  }

  nb->port_notification(ntfys);
}

int P4Controller::lag_create(uint32_t *lag_id, std::string name,
                             uint8_t mode) noexcept {
  return 0;
}

int P4Controller::lag_remove(uint32_t lag_id) noexcept { return 0; }

int P4Controller::lag_add_member(uint32_t lag_id, uint32_t port_id) noexcept {
  return 0;
}

int P4Controller::lag_remove_member(uint32_t lag_id,
                                    uint32_t port_id) noexcept {
  return 0;
}

int P4Controller::lag_set_member_active(uint32_t lag_id, uint32_t port_id,
                                        uint8_t active) noexcept {
  return 0;
}

int P4Controller::lag_set_mode(uint32_t lag_id, uint8_t mode) noexcept {
  return 0;
}

int P4Controller::overlay_tunnel_add(uint32_t tunnel_id) noexcept { return 0; }

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

int P4Controller::l2_multicast_group_remove(
    uint32_t port, uint16_t vid, rofl::caddress_ll mc_group) noexcept {
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

int P4Controller::l3_termination_add_v6(
    uint32_t sport, uint16_t vid, const rofl::caddress_ll &dmac) noexcept {
  return 0;
}

int P4Controller::l3_termination_remove(
    uint32_t sport, uint16_t vid, const rofl::caddress_ll &dmac) noexcept {
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
  ::grpc::ClientContext context;
  ::p4::v1::WriteRequest req = ::p4::v1::WriteRequest();
  ::p4::v1::WriteResponse res = ::p4::v1::WriteResponse();

  req.set_device_id((::google::protobuf::uint64)device_id);
  req.set_role_id(0);
  req.mutable_election_id()->set_high(0);
  req.mutable_election_id()->set_low(1);
  req.set_atomicity(::p4::v1::WriteRequest_Atomicity_CONTINUE_ON_ERROR);
  auto update = req.add_updates();
  update->set_type(::p4::v1::Update_Type_INSERT);
  auto entity = update->mutable_entity();
  auto table_entry = entity->mutable_table_entry();

  table_entry->set_table_id(33574068); // MyIngress.ipv4_lpm
  auto field_match = table_entry->add_match();
  field_match->set_field_id(1);
  char ip[INET_ADDRSTRLEN] = {0};
  auto _ip = ipv4_dst.str().c_str();
  inet_ntop(AF_INET, _ip, ip, INET_ADDRSTRLEN);
  VLOG(1) << "IP " << ip;
  field_match->mutable_lpm()->set_value(ip);
  field_match->mutable_lpm()->set_prefix_len(24);

  auto action = table_entry->mutable_action()->mutable_action();
  action->set_action_id(16799317); // ipv4_forwarding

  auto param1 = action->add_params();
  param1->set_param_id(1); // name: "dstAddr"
  param1->set_value("00:00:00:00:01:01");

  auto param2 = action->add_params();
  param2->set_param_id(2); // name: "port"
  param2->set_value("1");

  VLOG(1) << __FUNCTION__ << req.DebugString();
  stub->Write(&context, req, &res);

  VLOG(1) << " Configuring IP host";
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
  ::grpc::ClientContext context;
  ::p4::v1::WriteRequest req = ::p4::v1::WriteRequest();
  ::p4::v1::WriteResponse res = ::p4::v1::WriteResponse();

  req.set_device_id((::google::protobuf::uint64)device_id);
  req.set_role_id(0);
  req.mutable_election_id()->set_high(0);
  req.mutable_election_id()->set_low(1);
  req.set_atomicity(::p4::v1::WriteRequest_Atomicity_CONTINUE_ON_ERROR);
  auto update = req.add_updates();
  update->set_type(::p4::v1::Update_Type_INSERT);
  auto entity = update->mutable_entity();
  auto table_entry = entity->mutable_table_entry();

  table_entry->set_table_id(33574068); // MyIngress.ipv4_lpm
  auto field_match = table_entry->add_match();
  field_match->set_field_id(1);

  char ip[INET_ADDRSTRLEN] = {0};
  auto _ip = ipv4_dst.str().c_str();
  inet_ntop(AF_INET, _ip, ip, INET_ADDRSTRLEN);
  VLOG(1) << "IP " << ip;

  field_match->mutable_lpm()->set_value(ip);
  field_match->mutable_lpm()->set_prefix_len(24);

  auto action = table_entry->mutable_action()->mutable_action();
  action->set_action_id(16799317); // ipv4_forwarding

  auto param1 = action->add_params();
  param1->set_param_id(1); // name: "dstAddr"
  param1->set_value("00:00:00:00:01:01");

  auto param2 = action->add_params();
  param2->set_param_id(2); // name: "port"
  param2->set_value("1");

  VLOG(1) << __FUNCTION__ << req.DebugString();
  stub->Write(&context, req, &res);

  return 0;
}

int P4Controller::l3_unicast_route_add(const rofl::caddress_in6 &ipv6_dst,
                                       const rofl::caddress_in6 &mask,
                                       uint32_t l3_interface_id, bool is_ecmp,
                                       bool update_route,
                                       uint16_t vrf_id) noexcept {
  return 0;
}

int P4Controller::l3_ecmp_add(
    uint32_t l3_ecmp_id, const std::set<uint32_t> &l3_interfaces) noexcept {
  return 0;
}

int P4Controller::l3_ecmp_remove(uint32_t l3_ecmp_id) noexcept { return 0; }

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

int P4Controller::ingress_port_vlan_remove(uint32_t port, uint16_t vid,
                                           bool pvid,
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

int P4Controller::egress_port_vlan_remove(uint32_t port,
                                          uint16_t vid) noexcept {
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

int P4Controller::set_egress_tpid(uint32_t port) noexcept { return 0; }

int P4Controller::delete_egress_tpid(uint32_t port) noexcept { return 0; }

int P4Controller::enqueue(uint32_t port_id, basebox::packet *pkt) noexcept {
  return 0;
}

int P4Controller::subscribe_to(enum swi_flags flags) noexcept { return 0; }

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
                                         uint64_t dst_mac,
                                         uint32_t physical_port,
                                         uint16_t vlan_id) noexcept {
  return 0;
}

int P4Controller::tunnel_next_hop_modify(uint32_t next_hop_id, uint64_t src_mac,
                                         uint64_t dst_mac,
                                         uint32_t physical_port,
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

int P4Controller::tunnel_port_delete(uint32_t port_id) noexcept { return 0; }

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

int P4Controller::ofdpa_stg_create(uint16_t vlan_id) noexcept { return 0; }

} // namespace basebox
