/*
 * cfib.cc
 *
 *  Created on: 15.07.2013
 *      Author: andreas
 */

#include <cfib.h>

using namespace ethercore;

std::map<uint64_t, std::map<uint16_t, cfib*> > cfib::fibs;


/*static*/
cfib&
cfib::get_fib(uint64_t dpid, uint16_t vid)
{
	if (cfib::fibs[dpid].find(vid) == cfib::fibs[dpid].end()) {
		throw eFibNotFound();
	}
	return *(cfib::fibs[dpid][vid]);
}


cfib::cfib(cfib_owner *fibowner, uint64_t dpid, uint16_t vid, uint8_t table_id) :
		fibowner(fibowner),
		dpid(dpid),
		vid(vid),
		table_id(table_id)
{
	if (cfib::fibs[dpid].find(vid) != cfib::fibs[dpid].end()) {
		throw eFibExists();
	}
	cfib::fibs[dpid][vid] = this;
}



cfib::~cfib()
{
	cfib::fibs[dpid].erase(vid);
}


void
cfib::add_port(
		uint32_t portno,
		bool tagged)
{
	try {
		sport& port = sport::get_sport(dpid, portno);

		/* notify sport about new VLAN membership => setup of associated FlowTable and GroupTable entries */
		port.add_membership(vid, tagged);

	} catch (eSportNotFound& e) {
		logging::error << "cfib::add_port() sport instance for OF portno:" << (int)portno << " not found" << std::endl;
	} catch (eSportFailed& e) {
		logging::error << "cfib::add_port() adding membership to sport instance failed" << std::endl;
	}
}


void
cfib::drop_port(
		uint32_t portno)
{

}


void
cfib::reset()
{
	for (std::map<rofl::cmacaddr, cfibentry*>::iterator
			it = fibtable.begin(); it != fibtable.end(); ++it) {
		delete (it->second);
	}
	fibtable.clear();
}



void
cfib::fib_timer_expired(cfibentry *entry)
{
	if (fibtable.find(entry->get_lladdr()) != fibtable.end()) {
#if 0
		entry->set_out_port_no(OFPP12_FLOOD);
#else
		fibtable[entry->get_lladdr()]->flow_mod_delete();
		fibtable.erase(entry->get_lladdr());
		delete entry;
#endif
	}

	std::cerr << "EXPIRED: " << *this << std::endl;
}



uint32_t
cfib::get_flood_group_id(uint16_t vid)
{
	return 0;
}



void
cfib::fib_update(
		rofl::crofbase *rofbase,
		rofl::cofdpt *dpt,
		rofl::cmacaddr const& src,
		uint32_t in_port)
{
	std::cerr << "UPDATE: src: " << src << std::endl;

	uint8_t table_id = 0;
	uint16_t vid = 0xffff;


	// update cfibentry for src/inport
	if (fibtable.find(src) == fibtable.end()) {
		fibtable[src] = new cfibentry(this, table_id, src, dpt->get_dpid(), vid, in_port, /*tagged=*/true);
		fibtable[src]->flow_mod_add();

		std::cerr << "UPDATE[2.1]: " << *this << std::endl;

	} else {
		fibtable[src]->set_out_port_no(in_port);

		std::cerr << "UPDATE[3.1]: " << *this << std::endl;

	}
}



cfibentry&
cfib::fib_lookup(
		rofl::crofbase *rofbase,
		rofl::cofdpt *dpt,
		rofl::cmacaddr const& dst,
		rofl::cmacaddr const& src,
		uint32_t in_port)
{
	std::cerr << "LOOKUP: dst: " << dst << " src: " << src << std::endl;

	// sanity checks
	if (src.is_multicast()) {
		throw eFibInval();
	}

	fib_update(rofbase, dpt, src, in_port);

	if (dst.is_multicast()) {
		throw eFibInval();
	}

	// find out-port for dst
	if (fibtable.find(dst) == fibtable.end()) {

		uint8_t table_id = 0;
		uint16_t vid = 0xffff;

		fibtable[dst] = new cfibentry(this, table_id, dst, dpt->get_dpid(), vid, in_port, OFPP12_FLOOD);
		fibtable[dst]->flow_mod_add();

		std::cerr << "LOOKUP[1]: " << *this << std::endl;
	}

	return *(fibtable[dst]);
}




