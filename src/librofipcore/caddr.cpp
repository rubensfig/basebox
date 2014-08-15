/*
 * caddr.cpp
 *
 *  Created on: 03.07.2013
 *      Author: andreas
 */


#include "caddr.hpp"
#include "cipcore.hpp"

using namespace ipcore;


void
caddr_in4::handle_dpt_open(rofl::crofdpt& dpt)
{
	try {
		rofl::openflow::cofflowmod fe(dpt.get_version());

		switch (state) {
		case STATE_DETACHED: {
			fe.set_command(rofl::openflow::OFPFC_ADD);
		} break;
		case STATE_ATTACHED: {
			fe.set_command(rofl::openflow::OFPFC_MODIFY_STRICT);
		} break;
		}

		fe.set_buffer_id(rofl::openflow::base::get_ofp_no_buffer(dpt.get_version()));
		fe.set_idle_timeout(0);
		fe.set_hard_timeout(0);
		fe.set_priority(0xfffe);
		fe.set_table_id(in_ofp_table_id);
		fe.set_flags(rofl::openflow13::OFPFF_SEND_FLOW_REM);

		rofl::cindex index(0);

		fe.set_instructions().add_inst_apply_actions().set_actions().
				set_action_output(index).set_port_no(rofl::openflow::base::get_ofpp_controller_port(dpt.get_version()));
		fe.set_instructions().set_inst_apply_actions().set_actions().
				set_action_output(index).set_max_len(1518);

		// redirect ARP packets to control plane
		fe.set_match().clear();
		fe.set_match().set_in_port(cipcore::get_instance().get_link_by_ifindex(ifindex).get_ofp_port_no()); // only for ARP (bound to Ethernet segment)
		fe.set_match().set_eth_type(rofl::farpv4frame::ARPV4_ETHER);
		fe.set_match().set_arp_tpa(rofcore::cnetlink::get_instance().get_links().get_link(ifindex).get_addrs_in4().get_addr(adindex).get_local_addr());
		dpt.send_flow_mod_message(rofl::cauxid(0), fe);

		// redirect ICMPv4 packets to control plane
		fe.set_match().clear();
		fe.set_match().set_eth_type(rofl::fipv4frame::IPV4_ETHER);
		fe.set_match().set_ipv4_dst(rofcore::cnetlink::get_instance().get_links().get_link(ifindex).get_addrs_in4().get_addr(adindex).get_local_addr());
		fe.set_match().set_ip_proto(rofl::ficmpv4frame::ICMPV4_IP_PROTO);
		dpt.send_flow_mod_message(rofl::cauxid(0), fe);

		state = STATE_ATTACHED;

	} catch (rofl::eRofDptNotFound& e) {
		rofcore::logging::error << "[caddr_in4][flow_mod_add] unable to find data path" << std::endl << *this;

	} catch (rofcore::eNetLinkNotFound& e) {
		rofcore::logging::error << "[caddr_in4][flow_mod_add] unable to find link" << std::endl << *this;

	} catch (rofcore::crtlink::eRtLinkNotFound& e) {
		rofcore::logging::error << "[caddr_in4][flow_mod_add] unable to find address" << std::endl << *this;

	} catch (...) {
		rofcore::logging::error << "[caddr_in4][flow_mod_add] unexpected error" << std::endl << *this;

	}
}



void
caddr_in4::handle_dpt_close(rofl::crofdpt& dpt)
{
	try {
		rofl::openflow::cofflowmod fe(dpt.get_version());

		fe.set_command(rofl::openflow::OFPFC_DELETE_STRICT);
		fe.set_priority(0xfffe);
		fe.set_table_id(in_ofp_table_id);

		// redirect ARP packets to control plane
		fe.set_match().clear();
		fe.set_match().set_in_port(cipcore::get_instance().get_link_by_ifindex(ifindex).get_ofp_port_no()); // only for ARP (bound to Ethernet segment)
		fe.set_match().set_eth_type(rofl::farpv4frame::ARPV4_ETHER);
		fe.set_match().set_arp_tpa(rofcore::cnetlink::get_instance().get_links().get_link(ifindex).get_addrs_in4().get_addr(adindex).get_local_addr());
		dpt.send_flow_mod_message(rofl::cauxid(0), fe);

		// redirect ICMPv4 packets to control plane
		fe.set_match().clear();
		fe.set_match().set_eth_type(rofl::fipv4frame::IPV4_ETHER);
		fe.set_match().set_ipv4_dst(rofcore::cnetlink::get_instance().get_links().get_link(ifindex).get_addrs_in4().get_addr(adindex).get_local_addr());
		fe.set_match().set_ip_proto(rofl::ficmpv4frame::ICMPV4_IP_PROTO);
		dpt.send_flow_mod_message(rofl::cauxid(0), fe);

		state = STATE_DETACHED;

	} catch (rofl::eRofDptNotFound& e) {
		rofcore::logging::error << "[caddr_in4][flow_mod_delete] unable to find data path" << std::endl << *this;

	} catch (rofcore::eNetLinkNotFound& e) {
		rofcore::logging::error << "[caddr_in4][flow_mod_delete] unable to find link" << std::endl << *this;

	} catch (rofcore::crtlink::eRtLinkNotFound& e) {
		rofcore::logging::error << "[caddr_in4][flow_mod_delete] unable to find address" << std::endl << *this;

	} catch (...) {
		rofcore::logging::error << "[caddr_in4][flow_mod_delete] unexpected error" << std::endl << *this;

	}
}



void
caddr_in6::handle_dpt_open(rofl::crofdpt& dpt)
{
	try {
		rofl::openflow::cofflowmod fe(dpt.get_version());

		switch (state) {
		case STATE_DETACHED: {
			fe.set_command(rofl::openflow::OFPFC_ADD);
		} break;
		case STATE_ATTACHED: {
			fe.set_command(rofl::openflow::OFPFC_MODIFY_STRICT);
		} break;
		}

		fe.set_buffer_id(rofl::openflow::base::get_ofp_no_buffer(dpt.get_version()));
		fe.set_idle_timeout(0);
		fe.set_hard_timeout(0);
		fe.set_priority(0xfffe);
		fe.set_table_id(in_ofp_table_id);
		fe.set_flags(rofl::openflow13::OFPFF_SEND_FLOW_REM);

		rofl::cindex index(0);

		fe.set_instructions().add_inst_apply_actions().set_actions().
				set_action_output(index).set_port_no(rofl::openflow::base::get_ofpp_controller_port(dpt.get_version()));
		fe.set_instructions().set_inst_apply_actions().set_actions().
				set_action_output(index).set_max_len(1518);

		// redirect ICMPv6 packets to control plane
		fe.set_match().clear();
		fe.set_match().set_eth_type(rofl::fipv6frame::IPV6_ETHER);
		fe.set_match().set_ipv6_dst(rofcore::cnetlink::get_instance().get_links().get_link(ifindex).get_addrs_in6().get_addr(adindex).get_local_addr());
		fe.set_match().set_ip_proto(rofl::ficmpv6frame::ICMPV6_IP_PROTO);

		dpt.send_flow_mod_message(rofl::cauxid(0), fe);

		state = STATE_ATTACHED;

	} catch (rofl::eRofDptNotFound& e) {
		rofcore::logging::error << "[caddr_in6][flow_mod_add] unable to find data path" << std::endl << *this;

	} catch (rofcore::eNetLinkNotFound& e) {
		rofcore::logging::error << "[caddr_in6][flow_mod_add] unable to find link" << std::endl << *this;

	} catch (rofcore::crtlink::eRtLinkNotFound& e) {
		rofcore::logging::error << "[caddr_in6][flow_mod_add] unable to find address" << std::endl << *this;

	} catch (...) {
		rofcore::logging::error << "[caddr_in6][flow_mod_add] unexpected error" << std::endl << *this;

	}
}



void
caddr_in6::handle_dpt_close(rofl::crofdpt& dpt)
{
	try {
		rofl::openflow::cofflowmod fe(dpt.get_version());

		fe.set_command(rofl::openflow::OFPFC_DELETE_STRICT);
		fe.set_priority(0xfffe);
		fe.set_table_id(in_ofp_table_id);

		// redirect ICMPv6 packets to control plane
		fe.set_match().clear();
		fe.set_match().set_eth_type(rofl::fipv6frame::IPV6_ETHER);
		fe.set_match().set_ipv6_dst(rofcore::cnetlink::get_instance().get_links().get_link(ifindex).get_addrs_in6().get_addr(adindex).get_local_addr());
		fe.set_match().set_ip_proto(rofl::ficmpv6frame::ICMPV6_IP_PROTO);

		dpt.send_flow_mod_message(rofl::cauxid(0), fe);

		state = STATE_DETACHED;

	} catch (rofl::eRofDptNotFound& e) {
		rofcore::logging::error << "[caddr_in6][flow_mod_delete] unable to find data path" << std::endl << *this;

	} catch (rofcore::eNetLinkNotFound& e) {
		rofcore::logging::error << "[caddr_in6][flow_mod_delete] unable to find link" << std::endl << *this;

	} catch (rofcore::crtlink::eRtLinkNotFound& e) {
		rofcore::logging::error << "[caddr_in6][flow_mod_delete] unable to find address" << std::endl << *this;

	} catch (...) {
		rofcore::logging::error << "[caddr_in6][flow_mod_delete] unexpected error" << std::endl << *this;

	}
}



