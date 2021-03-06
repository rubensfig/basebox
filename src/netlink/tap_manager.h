/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <deque>
#include <string>
#include <map>
#include <memory>
#include <mutex>

#include "sai.h"
#include <linux/ethtool.h>

extern "C" {
struct rtnl_link;
}

namespace basebox {

class cnetlink;
class ctapdev;
class tap_io;
class tap_manager;

class switch_callback {
public:
  virtual ~switch_callback() = default;
  virtual int enqueue_to_switch(uint32_t port_id, basebox::packet *) = 0;
};

class tap_manager final {

public:
  tap_manager(std::shared_ptr<cnetlink> nl);
  ~tap_manager();

  int create_tapdev(uint32_t port_id, const std::string &port_name,
                    switch_callback &callback);

  int destroy_tapdev(uint32_t port_id, const std::string &port_name);

  int enqueue(int fd, basebox::packet *pkt);

  std::map<std::string, uint32_t> get_registered_ports() const {
    std::lock_guard<std::mutex> lock(tn_mutex);
    return tap_names2id;
  }

  uint32_t get_port_id(int ifindex) const noexcept {
    // XXX TODO add assert wrt threading
    auto it = ifindex_to_id.find(ifindex);
    if (it == ifindex_to_id.end()) {
      return 0;
    } else {
      return it->second;
    }
  }

  int get_ifindex(uint32_t port_id) const noexcept {
    // XXX TODO add assert wrt threading
    auto it = id_to_ifindex.find(port_id);
    if (it == id_to_ifindex.end()) {
      return 0;
    } else {
      return it->second;
    }
  }

  void clear() noexcept {
    std::lock_guard<std::mutex> lock(tn_mutex);
    ifindex_to_id.clear();
    id_to_ifindex.clear();
  }

  int get_fd(uint32_t port_id) const noexcept;

  int change_port_status(const std::string name, bool status);
  int set_port_speed(const std::string name, uint32_t speed, uint8_t duplex);

  // access from northbound (cnetlink)
  int tapdev_removed(int ifindex, const std::string &portname);
  void tapdev_ready(rtnl_link *link);
  int update_mtu(rtnl_link *link);

private:
  tap_manager(const tap_manager &other) = delete; // non construction-copyable
  tap_manager &operator=(const tap_manager &) = delete; // non copyable

  // locked access
  mutable std::mutex tn_mutex; // tap names mutex
  std::map<std::string, uint32_t> tap_names2id;
  std::map<std::string, int> tap_names2fds;

  // only accessible from southbound
  std::map<uint32_t, ctapdev *> tap_devs; // port id:tap_device
  std::deque<uint32_t> port_deleted;

  // only accessible from cnetlink
  std::map<int, uint32_t> ifindex_to_id;
  std::map<uint32_t, int> id_to_ifindex;

  std::unique_ptr<tap_io> io;
  std::shared_ptr<cnetlink> nl;

  int recreate_tapdev(int ifindex, const std::string &portname);
};

} // namespace basebox
