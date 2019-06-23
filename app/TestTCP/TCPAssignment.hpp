/*
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{
struct socket_base{
	int domain;
	int type;
	int protocol;
	bool is_bound = false;
	bool is_connected = false;

	struct sockaddr src_addr;
	struct sockaddr dst_addr;

	socklen_t src_len;
	socklen_t dst_len;

};
class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	std::map<std::pair<int,int>, socket_base*> socket_list;
private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, int type, int protocol);
	virtual void syscall_close(UUID syscallUUID, int pid, int sock_fd);
	virtual void syscall_bind(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *my_addr, socklen_t addrlen);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *addr, socklen_t *addrlen);
	virtual void syscall_listen(UUID syscallUUID, int pid, int sock_fd, int backlog);
	virtual void syscall_accept(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *addr, socklen_t *addrlen);
	virtual void syscall_connect(UUID syscallUUID,int pid,int sock_fd, struct sockaddr *addr, socklen_t addrlen);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *addr, socklen_t *addrlen);

	virtual void syscall_write(UUID syscallUUID, int pid, int sock_fd, void* buf, size_t count);
	virtual void syscall_read(UUID syscallUUID, int pid, int fd, void* buf, size_t count);

	virtual unsigned short alloc_port(uint32_t);
};


class TCPAssignmentProvider
{;
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
