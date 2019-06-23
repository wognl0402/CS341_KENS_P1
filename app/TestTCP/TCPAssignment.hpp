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
enum socket_state{CLOSED, LISTENING, SYN_SENT, SYN_RCVD, ESTAB};
enum blocked_syscall{NONE, SYS_CONN, SYS_LIS, SYS_ACC, SYS_WRITE, SYS_READ};

struct socket_base{
	int domain;
	int type;
	int protocol;
	bool is_bound = false;
	bool is_connected = false;

	socket_state state;

	struct sockaddr src_addr;
	struct sockaddr dst_addr;

	socklen_t src_len;
	socklen_t dst_len;

	uint32_t seq_num;
	uint32_t ack_num;
	
	blocked_syscall syscall;

	UUID syscallUUID;

	uint32_t send_base;

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

	virtual Packet *packet_signal(uint32_t src_ip, uint32_t dst_ip, unsigned short src_port,
						unsigned short dst_port, uint32_t seq_num, uint32_t ack_num, unsigned short flag);

	virtual unsigned short alloc_port(uint32_t);
	virtual std::pair<int, int> search_quartet(uint32_t src_ip, uint32_t dst_ip, 
												unsigned short src_port,unsigned short dst_port);
	virtual std::pair<uint32_t, unsigned short> GetSrcIpPort(struct socket_base *);
	virtual std::pair<uint32_t, unsigned short> GetDstIpPort(struct socket_base *);
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
