/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <E/E_TimeUtil.hpp>

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type){
	int sock_fd = createFileDescriptor(pid);
	socket_base *new_socket = new socket_base;
	
	new_socket->domain = domain;
	new_socket->type = type;
	new_socket->protocol = IPPROTO_TCP;
	new_socket->is_bound = false;
	new_socket->is_connected = false;
	
	this->socket_list.insert(std::make_pair(std::make_pair(pid, sock_fd), new_socket ));
	returnSystemCall(syscallUUID, sock_fd);

}
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sock_fd){
	auto it = this->socket_list.find(std::make_pair(pid,sock_fd));
	if (it == this->socket_list.end()){
		returnSystemCall(syscallUUID, -1);
		return;
	}
	if (!it->second->is_connected){
		// If it is not connected
		removeFileDescriptor(pid, sock_fd);
		//memleak
		delete(it->second);
		this->socket_list.erase(it);
		returnSystemCall(syscallUUID, 0);
		return;
	}
}
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *my_addr, socklen_t addrlen){
	struct sockaddr_in ori = *(struct sockaddr_in *)my_addr;

	for (auto it = this->socket_list.begin();
		 it != this->socket_list.end();
		 it = std::next(it)){
		if (! it->second->is_bound){
			continue;
		}
		struct sockaddr_in temp = *(struct sockaddr_in *) &it->second->src_addr;

		if ((ori.sin_port==temp.sin_port) && (ori.sin_addr.s_addr == temp.sin_addr.s_addr || 
													ori.sin_addr.s_addr == INADDR_ANY ||
													temp.sin_addr.s_addr == INADDR_ANY)){
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}

	auto it = this->socket_list.find(std::make_pair(pid, sock_fd));
	if (it != this->socket_list.end()){
		if (it->second->is_bound){
			returnSystemCall(syscallUUID, -1);
		}else{
			it->second->src_addr = *my_addr;
			it->second->src_len = addrlen;
			it->second->is_bound=true;
			returnSystemCall(syscallUUID, 0);
			return;
		}
	}else{
		returnSystemCall(syscallUUID, -1);
	}
}
void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *addr, socklen_t *addrlen){
	auto it = this->socket_list.find(std::make_pair(pid, sock_fd));
	if (it != this->socket_list.end()){
		if(!it->second->is_bound){
			returnSystemCall(syscallUUID, -1);
			return;
		}
		*addr = it->second->src_addr;
		*addrlen = it->second->src_len;
		returnSystemCall(syscallUUID, 0);
	}else{
		returnSystemCall(syscallUUID, -1);
	}
}
void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sock_fd, int backlog){

}
void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *addr, socklen_t *addrlen)
{
}
void TCPAssignment::syscall_connect(UUID syscallUUID,int pid, int sock_fd, struct sockaddr *addr, socklen_t addrlen)
{
}
void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *addr, socklen_t *addrlen)
{
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sock_fd, void* buf, size_t count)
{
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sock_fd, void* buf, size_t count)
{
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

	return;

}

void TCPAssignment::timerCallback(void* payload)
{
}

unsigned short TCPAssignment::alloc_port(uint32_t src_ip){
	unsigned short port = 64581;
	
	bool duplicated = false;
	while(port < 65536){
		//check if current port is busy
		duplicated = false;
		for (auto it = this->socket_list.begin();
				it != this->socket_list.end();
				it = std::next(it)){
			if (!it->second->is_bound)
				continue;
			struct sockaddr_in e = *(struct sockaddr_in *) &it->second->src_addr;
			if (src_ip == INADDR_ANY || e.sin_addr.s_addr == INADDR_ANY || src_ip == INADDR_ANY)
			{
				if (htons(port) == e.sin_port)
					duplicated = true;
			}
		}
		if (!duplicated)
			return htons(port);
		else
			port++;
	}
	return 12;
}

}
