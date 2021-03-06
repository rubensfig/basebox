/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cassert>
#include <cstring>
#include <exception>
#include <fstream>
#include <glog/logging.h>
#include <iterator>
#include <string_view>

#include <sys/socket.h>
#include <linux/if.h>
#include <netlink/object.h>
#include <netlink/route/addr.h>
#include <netlink/route/bridge_vlan.h>
#include <netlink/route/link.h>
#include <netlink/route/link/bonding.h>
#include <netlink/route/link/vlan.h>
#include <netlink/route/link/vrf.h>
#include <netlink/route/link/vxlan.h>
#ifdef HAVE_NETLINK_ROUTE_MDB_H
#include <netlink/route/mdb.h>
#endif
#include <netlink/route/neighbour.h>
#include <netlink/route/route.h>
#include <systemd/sd-daemon.h>

#include "cnetlink.h"
#include "netlink-utils.h"
#include "nl_output.h"
#include "tap_manager.h"

#include "nl_bond.h"
#include "nl_interface.h"
#include "nl_l3.h"
#include "nl_vlan.h"
#include "nl_vxlan.h"

namespace basebox {

cnetlink::cnetlink()
    : swi(nullptr), thread(1), caches(NL_MAX_CACHE, nullptr), nl_proc_max(10),
      state(NL_STATE_STOPPED), bridge(nullptr), iface(new nl_interface(this)),
      bond(new nl_bond(this)), vlan(new nl_vlan(this)),
      l3(new nl_l3(vlan, this)), vxlan(new nl_vxlan(l3, this)) {

  sock_tx = nl_socket_alloc();
  if (sock_tx == nullptr) {
    LOG(FATAL) << __FUNCTION__ << ": failed to create netlink socket";
  }

  nl_connect(sock_tx, NETLINK_ROUTE);
  set_nl_socket_buffer_sizes(sock_tx);

  try {
    thread.start("netlink");
    init_caches();
  } catch (...) {
    LOG(FATAL) << __FUNCTION__ << ": caught unknown exception";
  }
}

cnetlink::~cnetlink() {
  thread.stop();
  delete bridge;
  destroy_caches();
  nl_socket_free(sock_mon);
  nl_socket_free(sock_tx);
}

int cnetlink::load_from_file(const std::string &path, int base) {
  std::ifstream file(path);
  std::string out;

  if (file.is_open()) {
    while (!file.eof()) {
      file >> out;
    }
  }

  return std::stoi(out, nullptr, base);
}

static int nl_overrun_handler_verbose(struct nl_msg *msg, void *arg) {
  LOG(ERROR) << __FUNCTION__ << ": got called with msg=" << msg;
  return NL_STOP;
}

static int nl_invalid_handler_verbose(struct nl_msg *msg, void *arg) {
  LOG(ERROR) << __FUNCTION__ << ": got called with msg=" << msg;
  return NL_STOP;
}

void cnetlink::init_caches() {

  sock_mon = nl_socket_alloc();
  if (sock_mon == nullptr) {
    LOG(FATAL) << __FUNCTION__ << ": failed to create netlink socket";
  }

  nl_socket_modify_cb(sock_mon, NL_CB_OVERRUN, NL_CB_CUSTOM,
                      nl_overrun_handler_verbose, nullptr);
  nl_socket_modify_cb(sock_mon, NL_CB_INVALID, NL_CB_CUSTOM,
                      nl_invalid_handler_verbose, nullptr);

  int rc = nl_cache_mngr_alloc(sock_mon, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);

  if (rc < 0) {
    LOG(FATAL) << __FUNCTION__ << ": failed to allocate netlink cache manager";
  }

  set_nl_socket_buffer_sizes(sock_mon);

  rc = rtnl_link_alloc_cache_flags(sock_mon, AF_UNSPEC, &caches[NL_LINK_CACHE],
                                   NL_CACHE_AF_ITER);

  if (0 != rc) {
    LOG(FATAL) << __FUNCTION__
               << ": rtnl_link_alloc_cache_flags failed rc=" << rc;
  }

  rc = nl_cache_mngr_add_cache_v2(mngr, caches[NL_LINK_CACHE],
                                  (change_func_v2_t)&nl_cb_v2, this);

  if (0 != rc) {
    LOG(FATAL) << __FUNCTION__ << ": add route/link to cache mngr";
  }

  /* init route cache */
  rc = rtnl_route_alloc_cache(sock_mon, AF_UNSPEC, 0, &caches[NL_ROUTE_CACHE]);
  if (rc < 0) {
    LOG(FATAL) << __FUNCTION__ << ": add route/route to cache mngr";
  }
  rc = nl_cache_mngr_add_cache_v2(mngr, caches[NL_ROUTE_CACHE],
                                  (change_func_v2_t)&nl_cb_v2, this);
  if (rc < 0) {
    LOG(FATAL) << __FUNCTION__ << ": add route/route to cache mngr";
  }

  /* init addr cache*/
  rc = rtnl_addr_alloc_cache(sock_mon, &caches[NL_ADDR_CACHE]);
  if (rc < 0) {
    LOG(FATAL) << __FUNCTION__ << ": add route/addr to cache mngr";
  }
  rc = nl_cache_mngr_add_cache_v2(mngr, caches[NL_ADDR_CACHE],
                                  (change_func_v2_t)&nl_cb_v2, this);
  if (rc < 0) {
    LOG(FATAL) << __FUNCTION__ << ": add route/addr to cache mngr";
  }

  /* init neigh cache */
  rc = rtnl_neigh_alloc_cache_flags(sock_mon, &caches[NL_NEIGH_CACHE],
                                    NL_CACHE_AF_ITER);
  if (0 != rc) {
    LOG(FATAL) << __FUNCTION__
               << ": rtnl_neigh_alloc_cache_flags failed rc=" << rc;
  }
  rc = nl_cache_mngr_add_cache_v2(mngr, caches[NL_NEIGH_CACHE],
                                  (change_func_v2_t)&nl_cb_v2, this);
  if (0 != rc) {
    LOG(FATAL) << __FUNCTION__ << ": add route/neigh to cache mngr";
  }

#ifdef HAVE_NETLINK_ROUTE_MDB_H
  /* init mdb cache */
  rc = rtnl_mdb_alloc_cache_flags(sock_mon, &caches[NL_MDB_CACHE],
                                  NL_CACHE_AF_ITER);
  if (0 != rc) {
    LOG(FATAL) << __FUNCTION__
               << ": rtnl_mdb_alloc_cache_flags failed rc=" << rc;
  }
  rc = nl_cache_mngr_add_cache_v2(mngr, caches[NL_MDB_CACHE],
                                  (change_func_v2_t)&nl_cb_v2, this);
  if (0 != rc) {
    LOG(FATAL) << __FUNCTION__
               << ": nl_cache_mngr_add_cache_v2: add route/mdb to cache mngr";
  }
#endif

  /* init bridge-vlan cache */
  rc = rtnl_bridge_vlan_alloc_cache_flags(sock_mon, &caches[NL_BVLAN_CACHE],
                                          NL_CACHE_AF_ITER);
  if (0 != rc) {
    LOG(FATAL) << __FUNCTION__
               << ": rtnl_bridge_vlan_alloc_cache_flags failed rc=" << rc;
  }
  rc = nl_cache_mngr_add_cache_v2(mngr, caches[NL_BVLAN_CACHE],
                                  (change_func_v2_t)&nl_cb_v2, this);
  if (0 != rc) {
    LOG(FATAL) << __FUNCTION__ << ": add route/bridge-vlan to cache mngr";
  }

  try {
    thread.add_read_fd(this, nl_cache_mngr_get_fd(mngr), true, false);
  } catch (std::exception &e) {
    LOG(FATAL) << "caught " << e.what();
  }
}

void cnetlink::init_subsystems() noexcept {
  assert(swi);
  l3->init();
  vxlan->init();
}

void cnetlink::shutdown_subsystems() noexcept {
  tap_man->clear();
  bond->clear();
}

int cnetlink::set_nl_socket_buffer_sizes(nl_sock *sk) {
  int rx_size = load_from_file("/proc/sys/net/core/rmem_max");
  int tx_size = load_from_file("/proc/sys/net/core/wmem_max");

  LOG(INFO) << __FUNCTION__
            << ": netlink buffers are set to rx_size=" << rx_size
            << ", tx_size=" << tx_size;

  int err = nl_socket_set_buffer_size(sk, rx_size, tx_size);
  if (err != 0) {
    LOG(FATAL) << ": failed to call nl_socket_set_buffer_size: "
               << nl_geterror(err);
  }

  err = nl_socket_set_msg_buf_size(sk, rx_size);
  if (err != 0) {
    LOG(FATAL) << ": failed to call nl_socket_set_msg_buf_size: "
               << nl_geterror(err);
  }

  return err;
}

void cnetlink::destroy_caches() { nl_cache_mngr_free(mngr); }

std::unique_ptr<struct rtnl_link, decltype(&rtnl_link_put)>
cnetlink::get_link_by_ifindex(int ifindex) const {
  rtnl_link *link = rtnl_link_get(caches[NL_LINK_CACHE], ifindex);

  // check the garbage
  if (link == nullptr) {
    for (auto &obj : nl_objs) {
      if (obj.get_action() != NL_ACT_DEL)
        continue;

      if (std::string("route/link")
              .compare(nl_object_get_type(obj.get_old_obj())) != 0)
        continue;

      if (rtnl_link_get_ifindex(LINK_CAST(obj.get_old_obj())) == ifindex) {
        link = LINK_CAST(obj.get_old_obj());
        nl_object_get(OBJ_CAST(link));
        break;
      }
    }
  }

  std::unique_ptr<struct rtnl_link, decltype(&rtnl_link_put)> ret(
      link, *rtnl_link_put);
  return ret;
}

struct rtnl_link *cnetlink::get_link(int ifindex, int family) const {
  struct rtnl_link *_link = nullptr;
  std::unique_ptr<rtnl_link, decltype(&rtnl_link_put)> filter(rtnl_link_alloc(),
                                                              &rtnl_link_put);

  rtnl_link_set_ifindex(filter.get(), ifindex);
  rtnl_link_set_family(filter.get(), family);

  // search link by filter
  nl_cache_foreach_filter(
      caches[NL_LINK_CACHE], OBJ_CAST(filter.get()),
      [](struct nl_object *obj, void *arg) {
        *static_cast<nl_object **>(arg) = obj;
      },
      &_link);

  if (_link == nullptr) {
    // check the garbage
    for (auto &obj : nl_objs) {
      if (obj.get_action() != NL_ACT_DEL)
        continue;

      if (nl_object_match_filter(obj.get_old_obj(), OBJ_CAST(filter.get()))) {
        _link = LINK_CAST(obj.get_old_obj());
        VLOG(1) << __FUNCTION__ << ": found deleted link " << OBJ_CAST(_link);
        break;
      }
    }
  }

  return _link;
}

void cnetlink::get_bridge_ports(
    int br_ifindex, std::deque<rtnl_link *> *link_list) const noexcept {
  assert(link_list);

  if (!bridge)
    return;

  std::unique_ptr<rtnl_link, decltype(&rtnl_link_put)> filter(rtnl_link_alloc(),
                                                              &rtnl_link_put);
  assert(filter && "out of memory");

  rtnl_link_set_family(filter.get(), AF_BRIDGE);
  rtnl_link_set_master(filter.get(), br_ifindex);

  nl_cache_foreach_filter(
      caches[NL_LINK_CACHE], OBJ_CAST(filter.get()),
      [](struct nl_object *obj, void *arg) {
        assert(arg);
        auto *list = static_cast<std::deque<rtnl_link *> *>(arg);

        VLOG(3) << __FUNCTION__ << ": found bridge port " << obj;
        list->push_back(LINK_CAST(obj));
      },
      link_list);

  // check the garbage
  for (auto &obj : nl_objs) {
    if (obj.get_action() != NL_ACT_DEL)
      continue;

    if (nl_object_match_filter(obj.get_old_obj(), OBJ_CAST(filter.get()))) {
      link_list->push_back(LINK_CAST(obj.get_old_obj()));
    }
  }
}

std::set<uint32_t> cnetlink::get_bond_members_by_lag(rtnl_link *bond_link) {
  return bond->get_members(bond_link);
}

int cnetlink::get_l3_addrs(struct rtnl_link *link,
                           std::deque<rtnl_addr *> *addresses) {
  return l3->get_l3_addrs(link, addresses);
}

std::set<uint32_t> cnetlink::get_bond_members_by_port_id(uint32_t port_id) {
  return bond->get_members_by_port_id(port_id);
}

int cnetlink::add_l3_addr(struct rtnl_addr *a) {
  switch (rtnl_addr_get_family(a)) {
  case AF_INET:
    return l3->add_l3_addr(a);
  case AF_INET6:
    return l3->add_l3_addr_v6(a);
  default:
    LOG(ERROR) << __FUNCTION__
               << ": unsupported family=" << rtnl_addr_get_family(a)
               << " for address=" << OBJ_CAST(a);
    break;
  }
  return -EINVAL;
}

int cnetlink::del_l3_addr(struct rtnl_addr *a) { return l3->del_l3_addr(a); }

void cnetlink::get_vlans(int ifindex,
                         std::deque<uint16_t> *vlan_list) const noexcept {
  assert(vlan_list);

  std::unique_ptr<rtnl_link, decltype(&rtnl_link_put)> filter(rtnl_link_alloc(),
                                                              &rtnl_link_put);
  assert(filter && "out of memory");

  rtnl_link_set_family(filter.get(), AF_UNSPEC);
  rtnl_link_set_type(filter.get(), "vlan");
  rtnl_link_set_link(filter.get(), ifindex);

  nl_cache_foreach_filter(
      caches[NL_LINK_CACHE], OBJ_CAST(filter.get()),
      [](struct nl_object *obj, void *arg) {
        assert(arg);
        auto *list = static_cast<std::deque<uint16_t> *>(arg);
        uint16_t vid;

        VLOG(3) << __FUNCTION__ << ": found vlan interface " << obj;
        vid = rtnl_link_vlan_get_id(LINK_CAST(obj));
        list->push_back(vid);
      },
      vlan_list);
}

struct rtnl_neigh *cnetlink::get_neighbour(int ifindex,
                                           struct nl_addr *a) const {
  assert(ifindex);
  assert(a);
  // XXX TODO return unique_ptr
  return rtnl_neigh_get(caches[NL_NEIGH_CACHE], ifindex, a);
}

bool cnetlink::is_bridge_interface(int ifindex) const {
  return is_bridge_interface(get_link_by_ifindex(ifindex).get());
}

bool cnetlink::is_bridge_interface(rtnl_link *l) const {
  assert(l);

  if (bridge && rtnl_link_get_master(l) == bridge->get_ifindex()) {
    return true;
  }
  // is a vlan on top of the bridge?
  if (rtnl_link_is_vlan(l)) {
    LOG(INFO) << __FUNCTION__ << ": vlan ok";

    // get the master and check if it's a bridge
    auto _l = get_link_by_ifindex(rtnl_link_get_link(l));

    if (_l == nullptr)
      return false;

    auto lt = get_link_type(_l.get());

    LOG(INFO) << __FUNCTION__ << ": lt=" << lt << " " << OBJ_CAST(_l.get());
    if (lt == LT_BRIDGE) {
      LOG(INFO) << __FUNCTION__ << ": vlan ok";

      std::deque<rtnl_link *> bridge_interfaces;
      get_bridge_ports(rtnl_link_get_ifindex(_l.get()), &bridge_interfaces);

      for (auto br_intf : bridge_interfaces) {
        if (get_port_id(rtnl_link_get_ifindex(br_intf)) != 0)
          return true;
      }
      // handle this better, need to check for link
    } else if (lt == LT_BRIDGE_SLAVE)
      return true;

    // XXX TODO check rather nl_bridge ?
  }

  return false;
}

int cnetlink::get_port_id(rtnl_link *l) const {
  int ifindex;

  if (l == nullptr) {
    return 0;
  }

  if (rtnl_link_is_vlan(l))
    ifindex = rtnl_link_get_link(l);
  else
    ifindex = rtnl_link_get_ifindex(l);

  return get_port_id(ifindex);
}

int cnetlink::get_port_id(int ifindex) const {
  if (ifindex == 0)
    return 0;

  int port_id = tap_man->get_port_id(ifindex);
  if (port_id > 0)
    return port_id;

  return bond->get_lag_id(ifindex);
}

int cnetlink::get_ifindex_by_port_id(uint32_t port_id) const {

  return tap_man->get_ifindex(port_id);
}

uint16_t cnetlink::get_vrf_table_id(rtnl_link *link) {
  int rv = 0;

  auto vrf = get_link_by_ifindex(rtnl_link_get_master(link));
  if (vrf.get() && !rtnl_link_is_vrf(link) && rtnl_link_is_vrf(vrf.get())) {
    link = vrf.get();
  } else {
    VLOG(2) << __FUNCTION__ << ": link=" << OBJ_CAST(link)
            << " is not a VRF interface ";
    return 0;
  }

  uint32_t vrf_id;
  rv = rtnl_link_vrf_get_tableid(link, &vrf_id);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": error fetching vrf table id for link=" << OBJ_CAST(link);
    return 0;
  }

  VLOG(1) << __FUNCTION__ << ": table id=" << vrf_id
          << " vrf=" << rtnl_link_get_name(link);
  return vrf_id;
}

void cnetlink::handle_wakeup(rofl::cthread &thread) {
  bool do_wakeup = false;

  if (!swi)
    return;

  switch (state) {
  case NL_STATE_INIT:
    init_subsystems();
    state = NL_STATE_RUNNING;
    break;
  case NL_STATE_RUNNING:
    break;
  case NL_STATE_SHUTDOWN:
    shutdown_subsystems();
    state = NL_STATE_STOPPED;

    sd_notify(0, "STATUS=Connection broke");
    /* fallthrough */
  case NL_STATE_STOPPED:
    return;
  }

  // loop through nl_objs
  for (int cnt = 0;
       cnt < nl_proc_max && nl_objs.size() && state == NL_STATE_RUNNING;
       cnt++) {
    auto obj = nl_objs.front();
    nl_objs.pop_front();

    switch (obj.get_msg_type()) {
    case RTM_NEWLINK:
    case RTM_DELLINK:
      route_link_apply(obj);
      break;
    case RTM_NEWNEIGH:
    case RTM_DELNEIGH:
      route_neigh_apply(obj);
      break;
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
      route_route_apply(obj);
      break;
    case RTM_NEWADDR:
    case RTM_DELADDR:
      route_addr_apply(obj);
      break;
#ifdef HAVE_NETLINK_ROUTE_MDB_H
    case RTM_NEWMDB:
    case RTM_DELMDB:
      route_mdb_apply(obj);
      break;
#endif
    case RTM_NEWVLAN:
    case RTM_DELVLAN:
      route_bridge_vlan_apply(obj);
      break;
    default:
      LOG(ERROR) << __FUNCTION__ << ": unexpected netlink type "
                 << obj.get_msg_type();
      break;
    }
  }

  if (handle_source_mac_learn()) {
    do_wakeup = true;
  }

  if (handle_fdb_timeout()) {
    do_wakeup = true;
  }

  if (do_wakeup || nl_objs.size()) {
    VLOG(3) << __FUNCTION__
            << ": calling wakeup nl_objs.size()=" << nl_objs.size();
    this->thread.wakeup(this);
  }
}

void cnetlink::handle_read_event(rofl::cthread &thread, int fd) {
  VLOG(2) << __FUNCTION__ << ": thread=" << thread << ", fd=" << fd;

  if (fd == nl_cache_mngr_get_fd(mngr)) {
    int rv = nl_cache_mngr_data_ready(mngr);
    VLOG(3) << __FUNCTION__ << ": #processed=" << rv;
    // notify update
    if (state != NL_STATE_STOPPED) {
      this->thread.wakeup(this);
    }
  }
}

void cnetlink::handle_write_event(rofl::cthread &thread, int fd) {
  VLOG(1) << __FUNCTION__ << ": thread=" << thread << ", fd=" << fd;
  // currently not in use
}

void cnetlink::handle_timeout(rofl::cthread &thread, uint32_t timer_id) {
  VLOG(1) << __FUNCTION__ << ": thread=" << thread << ", timer_id=" << timer_id;

  switch (timer_id) {
  case NL_TIMER_RESEND_STATE:
// XXX loop through link cache
#if 0
    for (const auto &i : rtlinks.keys()) {
      const crtlink &link = rtlinks.get_link(i);
      link_created(link, get_port_id(link.get_ifindex()));
    }

    // XXX loop through neigh cache
    for (const auto &i : neighs_ll) {
      for (const auto &j : neighs_ll[i.first].keys()) {
        neigh_ll_created(i.first, neighs_ll[i.first].get_neigh(j));
      }
    }
#endif
    // was stopped before
    start();
    break;
  default:
    break;
  }
}

/* static C-callbacks */
void cnetlink::nl_cb_v2(struct nl_cache *cache, struct nl_object *old_obj,
                        struct nl_object *new_obj, uint64_t diff, int action,
                        void *data) {
  VLOG(3) << ": cache=" << cache << ", diff=" << diff << " action=" << action
          << " old_obj=" << static_cast<void *>(old_obj)
          << " new_obj=" << static_cast<void *>(new_obj);

  assert(data);
  auto nl = static_cast<cnetlink *>(data);

  // only enqueue nl msgs if not in stopped state
  if (nl->state != NL_STATE_STOPPED)
    nl->nl_objs.emplace_back(action, old_obj, new_obj);
}

void cnetlink::set_tapmanager(std::shared_ptr<tap_manager> tm) {
  tap_man = tm;
  iface->set_tapmanager(tm);
}

int cnetlink::send_nl_msg(nl_msg *msg) { return nl_send_sync(sock_tx, msg); }

void cnetlink::learn_l2(uint32_t port_id, int fd, basebox::packet *pkt) {
  {
    std::lock_guard<std::mutex> scoped_lock(pi_mutex);
    packet_in.emplace_back(port_id, fd, pkt);
  }

  VLOG(2) << __FUNCTION__ << ": got pkt " << pkt << " for fd=" << fd;
  thread.wakeup(this);
}

int cnetlink::handle_source_mac_learn() {
  // handle source mac learning
  std::deque<nl_pkt_in> _packet_in;

  {
    std::lock_guard<std::mutex> scoped_lock(pi_mutex);
    _packet_in.swap(packet_in);
  }

  for (int cnt = 0;
       cnt < nl_proc_max && _packet_in.size() && state == NL_STATE_RUNNING;
       cnt++) {
    auto p = _packet_in.front();
    int ifindex = tap_man->get_ifindex(p.port_id);

    if (ifindex && bridge) {
      rtnl_link *br_link = get_link(ifindex, AF_BRIDGE);
      VLOG(2) << __FUNCTION__ << ": ifindex=" << ifindex
              << ", bridge=" << bridge << ", br_link=" << OBJ_CAST(br_link);

      if (br_link) {
        // learn the source mac
        bridge->learn_source_mac(br_link, p.pkt);
      }
    }

    VLOG(2) << __FUNCTION__ << ": send pkt " << p.pkt
            << " to tap on fd=" << p.fd;
    // pass process packets to tap_man
    tap_man->enqueue(p.fd, p.pkt);
    _packet_in.pop_front();
  }

  int size = _packet_in.size();
  if (size) {
    VLOG(3) << __FUNCTION__ << ": " << size << " packets not processed";
    std::lock_guard<std::mutex> scoped_lock(pi_mutex);
    std::copy(make_move_iterator(_packet_in.rbegin()),
              make_move_iterator(_packet_in.rend()),
              std::front_inserter(packet_in));
  }

  return size;
}

void cnetlink::fdb_timeout(uint32_t port_id, uint16_t vid,
                           const rofl::caddress_ll &mac) {
  {
    std::lock_guard<std::mutex> scoped_lock(fdb_ev_mutex);
    fdb_evts.emplace_back(port_id, vid, mac);
  }

  VLOG(2) << __FUNCTION__ << ": got port_id=" << port_id << ", vid=" << vid
          << ", mac=" << mac;

  thread.wakeup(this);
}

int cnetlink::handle_fdb_timeout() {
  std::deque<fdb_ev> _fdb_evts;

  {
    std::lock_guard<std::mutex> scoped_lock(fdb_ev_mutex);
    _fdb_evts.swap(fdb_evts);
  }

  for (int cnt = 0; cnt < nl_proc_max && _fdb_evts.size() && bridge &&
                    state == NL_STATE_RUNNING;
       cnt++) {

    auto fdbev = _fdb_evts.front();
    int ifindex = tap_man->get_ifindex(fdbev.port_id);
    rtnl_link *br_link = get_link(ifindex, AF_BRIDGE);

    if (br_link && bridge) {
      bridge->fdb_timeout(br_link, fdbev.vid, fdbev.mac);
    }

    _fdb_evts.pop_front();
  }

  int size = _fdb_evts.size();
  if (size) {
    VLOG(3) << __FUNCTION__ << ": " << size << " events not processed";
    std::lock_guard<std::mutex> scoped_lock(fdb_ev_mutex);
    std::copy(make_move_iterator(_fdb_evts.rbegin()),
              make_move_iterator(_fdb_evts.rend()),
              std::front_inserter(fdb_evts));
  }

  return size;
}

void cnetlink::route_addr_apply(const nl_obj &obj) {
  int family;

  switch (obj.get_action()) {
  case NL_ACT_NEW:
    assert(obj.get_new_obj());

    VLOG(2) << __FUNCTION__ << ": new addr " << obj.get_new_obj();

    switch (family = rtnl_addr_get_family(ADDR_CAST(obj.get_new_obj()))) {
    case AF_INET:
      l3->add_l3_addr(ADDR_CAST(obj.get_new_obj()));
      break;
    case AF_INET6:
      l3->add_l3_addr_v6(ADDR_CAST(obj.get_new_obj()));
      break;
    default:
      LOG(ERROR) << __FUNCTION__ << ": unsupported family " << family;
      break;
    }
    break;

  case NL_ACT_CHANGE:
    assert(obj.get_new_obj());
    assert(obj.get_old_obj());

    VLOG(2) << __FUNCTION__ << ": change new addr " << obj.get_new_obj();
    VLOG(2) << __FUNCTION__ << ": change old addr " << obj.get_new_obj();

    switch (family = rtnl_addr_get_family(ADDR_CAST(obj.get_new_obj()))) {
    case AF_INET:
      LOG(WARNING) << __FUNCTION__ << ": changed IPv4 (not supported)";
      break;
    case AF_INET6:
      VLOG(2) << __FUNCTION__ << ": changed IPv6 not supported";
      break;
    default:
      LOG(WARNING) << __FUNCTION__ << ": unsupported family: " << family;
      break;
    }
    break;

  case NL_ACT_DEL:
    assert(obj.get_old_obj());

    VLOG(2) << __FUNCTION__ << ": del addr " << obj.get_old_obj();

    switch (family = rtnl_addr_get_family(ADDR_CAST(obj.get_old_obj()))) {
    case AF_INET:
    case AF_INET6:
      l3->del_l3_addr(ADDR_CAST(obj.get_old_obj()));
      break;
    default:
      LOG(WARNING) << __FUNCTION__ << ": unsupported family: " << family;
      break;
    }
    break;

  default:
    LOG(ERROR) << __FUNCTION__ << ": invalid netlink action "
               << obj.get_action();
    break;
  }
}

void cnetlink::route_link_apply(const nl_obj &obj) {
  try {
    switch (obj.get_action()) {
    case NL_ACT_NEW:
      assert(obj.get_new_obj());

      VLOG(2) << __FUNCTION__ << ": new link " << obj.get_new_obj();

      link_created(LINK_CAST(obj.get_new_obj()));
      break;

    case NL_ACT_CHANGE:
      assert(obj.get_new_obj());
      assert(obj.get_old_obj());

      VLOG(2) << __FUNCTION__ << ": change new link " << obj.get_new_obj();
      VLOG(2) << __FUNCTION__ << ": change old link " << obj.get_old_obj();

      link_updated(LINK_CAST(obj.get_old_obj()), LINK_CAST(obj.get_new_obj()));
      break;

    case NL_ACT_DEL: {
      assert(obj.get_old_obj());

      VLOG(2) << __FUNCTION__ << ": del link " << obj.get_old_obj();

      link_deleted(LINK_CAST(obj.get_old_obj()));
      break;
    }
    default:
      LOG(ERROR) << __FUNCTION__ << ": invalid netlink action "
                 << obj.get_action();
      break;
    }

  } catch (std::exception &e) { // XXX likely can be dropped now
    LOG(FATAL) << __FUNCTION__ << ": oops unknown exception " << e.what();
  }
}

void cnetlink::route_neigh_apply(const nl_obj &obj) {

  try {
    int family;
    switch (obj.get_action()) {
    case NL_ACT_NEW:
      assert(obj.get_new_obj());

      VLOG(2) << __FUNCTION__ << ": new neigh " << obj.get_new_obj();

      family = rtnl_neigh_get_family(NEIGH_CAST(obj.get_new_obj()));

      switch (family) {
      case AF_BRIDGE:
        neigh_ll_created(NEIGH_CAST(obj.get_new_obj()));
        break;
      case AF_INET:
      case AF_INET6:
        l3->add_l3_neigh(NEIGH_CAST(obj.get_new_obj()));
        break;
      default:
        LOG(ERROR) << __FUNCTION__ << ": invalid family " << family;
        break;
      }
      break;

    case NL_ACT_CHANGE:
      assert(obj.get_new_obj());
      assert(obj.get_old_obj());
      assert(rtnl_neigh_get_family(NEIGH_CAST(obj.get_new_obj())) ==
             rtnl_neigh_get_family(NEIGH_CAST(obj.get_old_obj())));

      VLOG(2) << __FUNCTION__ << ": change new neigh " << obj.get_new_obj();
      VLOG(2) << __FUNCTION__ << ": change old neigh " << obj.get_old_obj();

      family = rtnl_neigh_get_family(NEIGH_CAST(obj.get_new_obj()));

      switch (family) {
      case PF_BRIDGE:
        neigh_ll_updated(NEIGH_CAST(obj.get_old_obj()),
                         NEIGH_CAST(obj.get_new_obj()));
        break;
      case AF_INET:
      case AF_INET6:
        l3->update_l3_neigh(NEIGH_CAST(obj.get_old_obj()),
                            NEIGH_CAST(obj.get_new_obj()));
        break;
      default:
        LOG(ERROR) << __FUNCTION__ << ": invalid family " << family;
        break;
      }
      break;

    case NL_ACT_DEL:
      assert(obj.get_old_obj());

      VLOG(2) << __FUNCTION__ << ": del neigh " << obj.get_old_obj();

      family = rtnl_neigh_get_family(NEIGH_CAST(obj.get_old_obj()));

      switch (rtnl_neigh_get_family(NEIGH_CAST(obj.get_old_obj()))) {
      case PF_BRIDGE:
        neigh_ll_deleted(NEIGH_CAST(obj.get_old_obj()));
        break;
      case AF_INET6:
      case AF_INET:
        l3->del_l3_neigh(NEIGH_CAST(obj.get_old_obj()));
        break;
      default:
        LOG(ERROR) << __FUNCTION__ << ": invalid family " << family;
        break;
      }
      break;
    default:
      LOG(ERROR) << __FUNCTION__ << ": invalid netlink action "
                 << obj.get_action();
    }
  } catch (std::exception &e) {
    LOG(FATAL) << __FUNCTION__ << ": oops unknown exception " << e.what();
  }
}

void cnetlink::route_route_apply(const nl_obj &obj) {
  int family;

  switch (obj.get_action()) {
  case NL_ACT_NEW:
    assert(obj.get_new_obj());

    VLOG(2) << __FUNCTION__ << ": new route " << obj.get_new_obj();

    switch (family = rtnl_route_get_family(ROUTE_CAST(obj.get_new_obj()))) {
    case AF_INET:
    case AF_INET6:
      l3->add_l3_route(ROUTE_CAST(obj.get_new_obj()));
      break;
    default:
      LOG(WARNING) << __FUNCTION__ << ": family not supported: " << family;
      break;
    }
    break;

  case NL_ACT_CHANGE:
    assert(obj.get_new_obj());
    assert(obj.get_old_obj());

    VLOG(2) << __FUNCTION__ << ": change new route " << obj.get_new_obj();
    VLOG(2) << __FUNCTION__ << ": change old route " << obj.get_old_obj();

    switch (family = rtnl_route_get_family(ROUTE_CAST(obj.get_new_obj()))) {
    case AF_INET:
    case AF_INET6:
      l3->update_l3_route(ROUTE_CAST(obj.get_old_obj()),
                          ROUTE_CAST(obj.get_new_obj()));
      break;
    default:
      LOG(WARNING) << __FUNCTION__ << ": family not supported: " << family;
      break;
    }
    break;

  case NL_ACT_DEL:
    assert(obj.get_old_obj());

    VLOG(2) << __FUNCTION__ << ": del route " << obj.get_old_obj();

    switch (family = rtnl_route_get_family(ROUTE_CAST(obj.get_old_obj()))) {
    case AF_INET:
    case AF_INET6:
      l3->del_l3_route(ROUTE_CAST(obj.get_old_obj()));
      break;
    default:
      LOG(WARNING) << __FUNCTION__ << ": family not supported: " << family;
      break;
    }
    break;

  default:
    LOG(ERROR) << __FUNCTION__ << ": invalid action " << obj.get_action();
    break;
  }
}

void cnetlink::link_created(rtnl_link *link) noexcept {
  assert(link);
  assert(tap_man);

  enum link_type lt = get_link_type(link);

  switch (lt) {
  case LT_BRIDGE_SLAVE: // a new bridge slave was created
    try {
      // check for new bridge slaves
      if (rtnl_link_get_master(link) == 0) {
        LOG(ERROR) << __FUNCTION__ << ": bridge slave without master "
                   << OBJ_CAST(link);
        return;
      }

      // slave interface
      // use only the first bridge an interface is attached to
      // XXX TODO more bridges!
      if (bridge == nullptr) {
        std::unique_ptr<rtnl_link, decltype(&rtnl_link_put)> br_link(
            rtnl_link_get(caches[NL_LINK_CACHE], rtnl_link_get_master(link)),
            rtnl_link_put);

        LOG(INFO) << __FUNCTION__ << ": using bridge "
                  << OBJ_CAST(br_link.get());

        bridge = new nl_bridge(this->swi, tap_man, this, vlan, vxlan);
        bridge->set_bridge_interface(br_link.get());
        vxlan->register_bridge(bridge);
      }

      LOG(INFO) << __FUNCTION__ << ": enslaving interface "
                << rtnl_link_get_name(link);

      bridge->add_interface(link);
    } catch (std::exception &e) {
      LOG(ERROR) << __FUNCTION__ << ": failed: " << e.what();
    }
    break;
  case LT_VXLAN: {
    int rv = vxlan->create_vni(link);

    if (rv < 0) {
      LOG(ERROR) << __FUNCTION__ << ": failed to create vni for link "
                 << OBJ_CAST(link);
      break;
    }

    vxlan->create_endpoint(link);
  } break;
  case LT_TUN: {
    tap_man->tapdev_ready(link);
  } break;
  case LT_VLAN: {
    VLOG(1) << __FUNCTION__ << ": new vlan interface " << OBJ_CAST(link);
    uint16_t vid = rtnl_link_vlan_get_id(link);
    vlan->add_vlan(link, vid, true);
  } break;
  case LT_BOND: {
    VLOG(1) << __FUNCTION__ << ": new bond interface " << OBJ_CAST(link);
    bond->add_lag(link);
  } break;
  case LT_VRF: {
    VLOG(1) << __FUNCTION__ << ": new vrf interface " << OBJ_CAST(link);
  } break;
  default:
    LOG(WARNING) << __FUNCTION__ << ": ignoring link with lt=" << lt
                 << " link:" << OBJ_CAST(link);
    break;
  } // switch link type
}

void cnetlink::link_updated(rtnl_link *old_link, rtnl_link *new_link) noexcept {
  link_type lt_old = get_link_type(old_link);
  link_type lt_new = get_link_type(new_link);
  int af_old = rtnl_link_get_family(old_link);
  int af_new = rtnl_link_get_family(new_link);

  VLOG(3) << __FUNCTION__ << ": old_link_type="
          << std::string_view(rtnl_link_get_type(old_link))
          << ", new_link_type="
          << std::string_view(rtnl_link_get_type(new_link))
          << ", old_link_slave_type="
          << std::string_view(rtnl_link_get_slave_type(old_link))
          << ", new_link_slave_type="
          << std::string_view(rtnl_link_get_slave_type(new_link))
          << ", af_old=" << af_old << ", af_new=" << af_new;

  if (af_old != af_new) {
    VLOG(1) << __FUNCTION__ << ": af changed from " << af_old << " to "
            << af_new;
    // this is currently handled elsewhere
    // the for us interesting case is the bridge port creation
    return;
  }

  switch (lt_old) {
  case LT_BOND_SLAVE:
    if (lt_new == LT_BOND_SLAVE) { // bond slave updated
      bond->update_lag_member(old_link, new_link);
    } else if (lt_new == LT_TUN) { // bond slave removed
      bond->remove_lag_member(old_link);
    }
    break;
  case LT_BRIDGE_SLAVE: // a bridge slave was changed
    if (bridge) {
      try {
        if (rtnl_link_get_family(old_link) == AF_BRIDGE &&
            rtnl_link_get_family(new_link) == AF_BRIDGE)
          bridge->update_interface(old_link, new_link);
      } catch (std::exception &e) {
        LOG(ERROR) << __FUNCTION__ << ": failed: " << e.what();
      }
    }
    break;
  case LT_VLAN: {
    if (lt_new != LT_VRF_SLAVE) {
      VLOG(1) << __FUNCTION__ << ": ignoring update of VLAN interface";
      break;
    }
    LOG(INFO) << __FUNCTION__ << ": link enslaved "
              << rtnl_link_get_name(new_link) << " to vrf "
              << OBJ_CAST(
                     get_link_by_ifindex(rtnl_link_get_master(new_link)).get());
    // Lookup l3 addresses to delete
    // We can delete the addresses on the interface because we will later
    // receive a notification readding the addresses, that time with the correct
    // VRF
    std::deque<rtnl_addr *> addresses;
    get_l3_addrs(old_link, &addresses);
    for (auto i : addresses)
      l3->del_l3_addr(i);

    vlan->vrf_attach(old_link, new_link);
  } break;
  case LT_VRF_SLAVE: {
    if (lt_new == LT_VLAN) {
      LOG(INFO) << __FUNCTION__ << ": freed vrf slave interface "
                << OBJ_CAST(old_link);

      // Lookup l3 addresses to delete
      // We can delete the addresses on the interface because we will later
      // receive a notification readding the addresses, that time with the
      // correct VRF
      std::deque<rtnl_addr *> addresses;
      get_l3_addrs(old_link, &addresses);
      // delete l3 addresses no longer associated with vrf
      for (auto i : addresses)
        l3->del_l3_addr(i);
      vlan->vrf_detach(old_link, new_link);
    } else if (lt_new == LT_VRF_SLAVE) {
      LOG(INFO) << __FUNCTION__ << ": link updated " << OBJ_CAST(new_link);
      vlan->vrf_attach(old_link, new_link);
    }
    // TODO handle LT_TAP/LT_BOND, currently unimplemented
    // happens when a bond/tap interface enslaved directly to a VRF and you set
    // nomaster
  } break;
  case LT_TUN:
    if (lt_new == LT_BOND_SLAVE) {
      // XXX link enslaved
      LOG(INFO) << __FUNCTION__ << ": link enslaved "
                << rtnl_link_get_name(new_link);
      rtnl_link *_bond = get_link(rtnl_link_get_master(new_link), AF_UNSPEC);
      bond->add_lag_member(_bond, new_link);

      LOG(INFO) << __FUNCTION__ << " set active member " << get_port_id(_bond)
                << " port id " << rtnl_link_get_ifindex(new_link);
    } else if (lt_new == LT_VRF_SLAVE) {
      LOG(INFO) << __FUNCTION__ << ": link enslaved "
                << rtnl_link_get_name(new_link) << " but not handled";
    }
    iface->changed(old_link, new_link);
    break;
  case LT_BOND:
    bond->update_lag(old_link, new_link);
    break;
  case LT_VRF: // No need to care about the vrf interface itself
  case LT_BRIDGE:
  case LT_UNSUPPORTED:
    VLOG(2) << __FUNCTION__
            << ": ignoring update (not supported) of old_lt=" << lt_old
            << " old link: " << OBJ_CAST(old_link)
            << ", new link: " << OBJ_CAST(new_link);
    break;
  default:
    LOG(ERROR) << __FUNCTION__ << ": link type not handled lt=" << lt_old
               << ", link: " << OBJ_CAST(old_link);
    break;
  }
}

void cnetlink::link_deleted(rtnl_link *link) noexcept {
  assert(link);

  enum link_type lt = get_link_type(link);

  int ifindex(rtnl_link_get_ifindex(link));
  std::string portname(rtnl_link_get_name(link));

  switch (lt) {
  case LT_BRIDGE_SLAVE:
    try {
      if (bridge) {
        if (rtnl_link_get_family(link) == AF_BRIDGE)
          bridge->delete_interface(link);
      }
    } catch (std::exception &e) {
      LOG(ERROR) << __FUNCTION__ << ": failed: " << e.what();
    }
    break;
  case LT_TUN:
    tap_man->tapdev_removed(ifindex, portname);
    break;
  case LT_BRIDGE:
    if (bridge && bridge->is_bridge_interface(link)) {
      LOG(INFO) << __FUNCTION__ << ": deleting bridge";
      vxlan->register_bridge(nullptr);
      bridge->clear_tpid_entries(); // clear the Egress TPID table
      delete bridge;
      bridge = nullptr;
    }
    break;
  case LT_VXLAN: {
    int rv = vxlan->delete_endpoint(link);
    // XXX TODO check
    rv = vxlan->remove_vni(link);

    if (rv < 0) {
      LOG(WARNING) << __FUNCTION__ << ": could not remove vni represented by "
                   << OBJ_CAST(link);
    }

  } break;
  case LT_VLAN:
    VLOG(1) << __FUNCTION__ << ": removed vlan interface " << OBJ_CAST(link);
    vlan->remove_vlan(link, rtnl_link_vlan_get_id(link), true);
    break;
  case LT_BOND: {
    VLOG(1) << __FUNCTION__ << ": removed bond interface " << OBJ_CAST(link);
    bond->remove_lag(link);
  } break;
  case LT_VRF:
  case LT_VRF_SLAVE:
  default:
    LOG(ERROR) << __FUNCTION__ << ": link type not handled " << lt;
    break;
  }
}

// TODO this function could already be moved to nl_bridge
void cnetlink::neigh_ll_created(rtnl_neigh *neigh) noexcept {
  if (nullptr == bridge) {
    LOG(ERROR) << __FUNCTION__ << ": bridge not set";
    return;
  }

  int ifindex = rtnl_neigh_get_ifindex(neigh);

  if (ifindex == 0) {
    VLOG(1) << __FUNCTION__ << ": no ifindex for neighbour " << neigh;
    return;
  }

  rtnl_link *base_link = get_link(ifindex, AF_UNSPEC); // either tap, vxlan, ...
  rtnl_link *br_link = get_link(ifindex, AF_BRIDGE);

  if (base_link == nullptr) {
    LOG(ERROR) << __FUNCTION__
               << ": unknown link ifindex=" << rtnl_neigh_get_ifindex(neigh)
               << " of new L2 neighbour";
    return;
  }

  if (nl_addr_cmp(rtnl_link_get_addr(base_link),
                  rtnl_neigh_get_lladdr(neigh)) == 0) {
    // mac of interface itself is ignored, others added
    VLOG(2) << __FUNCTION__ << ": bridge port mac address is ignored";
    return;
  }

  if (VLOG_IS_ON(2)) {
    if (base_link) {
      LOG(INFO) << __FUNCTION__ << ": base link: " << OBJ_CAST(base_link);
    }
    if (br_link) {
      LOG(INFO) << __FUNCTION__ << ": br link: " << OBJ_CAST(br_link);
    }
  }

  if (vxlan->add_l2_neigh(neigh, base_link, br_link) == 0) {
    // vxlan domain
  } else {
    // XXX TODO maybe we have to do this as well wrt. local bridging
    // normal bridging
    try {
      if (bridge)
        bridge->add_neigh_to_fdb(neigh);
    } catch (std::exception &e) {
      LOG(ERROR) << __FUNCTION__
                 << ": failed to add mac to fdb"; // TODO log mac, port,...?
    }
  }
}

void cnetlink::neigh_ll_updated(__attribute__((unused)) rtnl_neigh *old_neigh,
                                __attribute__((unused))
                                rtnl_neigh *new_neigh) noexcept {
  LOG(WARNING) << __FUNCTION__ << ": neighbor update not supported";
}

void cnetlink::neigh_ll_deleted(rtnl_neigh *neigh) noexcept {
  int ifindex = rtnl_neigh_get_ifindex(neigh);

  if (ifindex == 0) {
    VLOG(1) << __FUNCTION__ << ": no ifindex for neighbour " << neigh;
    return;
  }

  rtnl_link *l = get_link(ifindex, AF_UNSPEC);

  if (l == nullptr) {
    LOG(ERROR) << __FUNCTION__
               << ": unknown link ifindex=" << rtnl_neigh_get_ifindex(neigh);
    return;
  }

  // XXX move to bridge
  if (nl_addr_cmp(rtnl_link_get_addr(l), rtnl_neigh_get_lladdr(neigh)) == 0) {
    VLOG(2) << __FUNCTION__ << ": bridge port mac address is ignored";
    return;
  }

  auto lt = get_link_type(l);

  switch (lt) {
  case LT_VXLAN: {
    rtnl_link *br_link = get_link(ifindex, AF_BRIDGE);
    vxlan->delete_l2_neigh(neigh, l, br_link);
  } break;

  default:
    if (bridge)
      bridge->remove_neigh_from_fdb(neigh);
  }
}

void cnetlink::resend_state() noexcept {
  stop();
  thread.add_timer(this, NL_TIMER_RESEND_STATE, rofl::ctimespec().expire_in(0));
}

void cnetlink::register_switch(switch_interface *swi) noexcept {
  assert(swi);
  this->swi = swi;
  l3->register_switch_interface(swi);
  vlan->register_switch_interface(swi);
  bond->register_switch_interface(swi);
  vxlan->register_switch_interface(swi);

  swi->subscribe_to(switch_interface::SWIF_ARP);
}

void cnetlink::unregister_switch(__attribute__((unused))
                                 switch_interface *swi) noexcept {
  // TODO we should remove the swi here
  stop();
}

void cnetlink::start() noexcept {
  if (state == NL_STATE_RUNNING)
    return;
  VLOG(1) << __FUNCTION__ << ": started netlink processing";
  state = NL_STATE_INIT;
  thread.wakeup(this);
}

void cnetlink::stop() noexcept {
  if (state == NL_STATE_STOPPED)
    return;

  VLOG(1) << __FUNCTION__ << ": stopped netlink processing";
  state = NL_STATE_SHUTDOWN;
  thread.wakeup(this);
}

bool cnetlink::is_bridge_configured(rtnl_link *l) {
  assert(l);

  if (bridge == nullptr) {
    VLOG(1) << __FUNCTION__ << ": no bridge configured";
    return false;
  }

  if (rtnl_link_is_vlan(l))
    return is_bridge_interface(l);

  return bridge->is_bridge_interface(l);
}

int cnetlink::set_bridge_port_vlan_tpid(rtnl_link *l) {
  if (!bridge) {
    return -EINVAL;
  }

  return bridge->set_vlan_proto(l);
}

int cnetlink::unset_bridge_port_vlan_tpid(rtnl_link *l) {
  if (!bridge) {
    return -EINVAL;
  }

  return bridge->delete_vlan_proto(l);
}

std::deque<rtnl_neigh *> cnetlink::search_fdb(uint16_t vid, nl_addr *lladdr) {
  std::deque<rtnl_link *> br_ports;
  get_bridge_ports(bridge->get_ifindex(), &br_ports);

  std::deque<rtnl_neigh *> fdb_entries;
  for (auto port : br_ports) {
    auto fdb = bridge->get_fdb_entries_of_port(port, vid, lladdr);

    std::copy(fdb.begin(), fdb.end(), std::back_inserter(fdb_entries));
  }

  return fdb_entries;
}

void cnetlink::route_mdb_apply(const nl_obj &obj) {

  switch (obj.get_msg_type()) {
  case RTM_NEWMDB:
    assert(obj.get_new_obj());
    LOG(INFO) << __FUNCTION__ << ": new mdb entry";

    if (bridge)
      bridge->mdb_entry_add(MDB_CAST(obj.get_new_obj()));
    break;
  case RTM_DELMDB:
    assert(obj.get_old_obj());
    LOG(INFO) << __FUNCTION__ << ": deleting mdb entry";

    if (bridge)
      bridge->mdb_entry_remove(MDB_CAST(obj.get_new_obj()));
    break;
  default:
    LOG(ERROR) << __FUNCTION__ << ": invalid action " << obj.get_action();
    break;
  }
}

void cnetlink::route_bridge_vlan_apply(const nl_obj &obj) {
  assert(obj.get_new_obj());

  switch (obj.get_msg_type()) {
  case RTM_NEWVLAN:
    if (bridge)
      bridge->set_pvlan_stp(BRIDGE_VLAN_CAST(obj.get_new_obj()));
    break;
#if 0
  case RTM_DELVLAN:
	if (bridge)
	        bridge->set_pvlan_stp(BRIDGE_VLAN_CAST(obj.get_new_obj()));
	break;
#endif
  default:
    LOG(ERROR) << __FUNCTION__ << ": invalid action " << obj.get_action();
    break;
  }
}

} // namespace basebox
