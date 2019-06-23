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
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
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
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
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
void TCPAssignment::syscall_connect(UUID syscallUUID,int pid, int sock_fd, struct sockaddr *addr, socklen_t addrlen){
	auto it = this->socket_list.find(std::make_pair(pid, sock_fd));
	if (it == this->socket_list.end()){
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct sockaddr_in dst_addr = *(struct sockaddr_in*)addr;
	uint32_t dst_ip = dst_addr.sin_addr.s_addr;
	unsigned short dst_port = dst_addr.sin_port;
	struct sockaddr_in src_addr = *(struct sockaddr_in*)(&it->second->src_addr);
	socklen_t src_addrlen = sizeof(src_addr);
	uint32_t src_ip;
	unsigned short src_port;

	Host *host = this->getHost();

	// Perform implicit bind if it is not bound
	if (!it->second->is_bound){
		// Get local address
		int index = host->getRoutingTable ((uint8_t *) &dst_ip);
		if (!host->getIPAddr ((uint8_t *) &src_ip, index)){
			returnSystemCall(syscallUUID, -1);
		}
		src_port = (alloc_port(src_ip));
		src_addr.sin_family = AF_INET;
		src_addr.sin_addr.s_addr = (src_ip);
		src_addr.sin_port = (src_port);

		it->second->src_addr = *(sockaddr *) &src_addr;
		it->second->src_len = src_addrlen;
		it->second->is_bound = true;
	}else{
		src_ip = src_addr.sin_addr.s_addr;
		src_port = src_addr.sin_port;
	}

	it->second->is_connected = true;
	it->second->dst_addr = *addr;
	it->second->dst_len = addrlen;

	it->second->syscall = SYS_CONN;
	it->second->syscallUUID = syscallUUID;
	it->second->state = SYN_SENT;
	it->second->seq_num = 1020;
	it->second->send_base = it->second->seq_num;
	
	unsigned short flag = 0x02;
	Packet *packet = this->packet_signal(src_ip, dst_ip, src_port, dst_port, it->second->seq_num, 0, flag);
	
	this->sendPacket("IPv4", packet);

	it->second->seq_num++;
}
void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *addr, socklen_t *addrlen){
	auto it = this->socket_list.find(std::make_pair(pid, sock_fd));
	if (it != this->socket_list.end()){
		if(!it->second->is_connected){
			//NO bind!
		}
		*addr = it->second->dst_addr;
		*addrlen = it->second->dst_len;
		returnSystemCall(syscallUUID, 0);
	}else{
		returnSystemCall(syscallUUID, -1);
	}
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sock_fd, void* buf, size_t count)
{
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sock_fd, void* buf, size_t count)
{
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	size_t ip_start = 14;
	size_t hlen;
	size_t tcp_len;
	unsigned char flag;
	unsigned short s_buf;
	unsigned char buf;

	packet->readData(ip_start+2, &s_buf, 2);
	packet->readData(ip_start, &buf, 1);

	hlen = buf & (0x0f);
	hlen = hlen * 4;
	s_buf = ntohs(s_buf);
	tcp_len = s_buf - hlen;

	uint32_t dst_ip ;
	uint32_t src_ip ;
	unsigned short dst_port;
	unsigned short src_port; 	
	uint32_t seq_num;
	uint32_t ack_num;
	unsigned short check_sum;
	char tcp_seg[tcp_len];
	
	packet->readData(ip_start+12, &src_ip, 4);
	packet->readData(ip_start+16, &dst_ip, 4);
	packet->readData(ip_start +hlen, &src_port, 2);
	packet->readData(ip_start +hlen+2, &dst_port, 2);
	packet->readData(ip_start +hlen+13, &buf, 1);
	packet->readData(ip_start +hlen+4, &seq_num, 4);
	packet->readData(ip_start +hlen+8, &ack_num, 4);
	packet->readData(ip_start +hlen+16, &check_sum, 2);
	packet->readData(ip_start +hlen, tcp_seg, tcp_len);
	
	flag = 0;
	flag = buf&(0x3f);

	packet->readData(ip_start + hlen + 14, &s_buf, 2);

	if (seq_num == (0x0000f02c)){
		printf("what\n");
	}
	
	if(NetworkUtil::tcp_sum(src_ip, dst_ip,((uint8_t*) tcp_seg) , tcp_len)!=0xffff) {
		return;
	}
	std::pair<int, int> key = search_quartet(dst_ip, src_ip, dst_port, src_port);
	
	// SYNACK - [SYN_SENT] to [ESTAB] and send ACK back.
	//			[SYN_RCVD] to [ESTAB] and do nothing (simultaneous connect)
	if(flag == 0x12){
		if(key == std::make_pair(-1,-1)) {return;}
			
		auto s = this->socket_list.find(key);
		if (s->second->state == SYN_SENT || s->second->state ==ESTAB){
			s->second->state = ESTAB;

			s->second->ack_num = ntohl(seq_num)+1;
			unsigned short signal = 0x10;
			this->freePacket(packet);
			Packet *A_packet = this->packet_signal(dst_ip, src_ip, dst_port, src_port, s->second->seq_num, ntohl(seq_num)+1, signal);
			this->sendPacket("IPv4", A_packet);

			if(s->second->syscall != SYS_CONN){return;}
			returnSystemCall(s->second->syscallUUID, 0);
			s->second->syscall = NONE;
			s->second->syscallUUID = 0;
			return;
		}else if (s->second->state == SYN_RCVD){
			s->second->state = ESTAB;
			s->second->send_base = ntohl(ack_num);

			if(s->second->syscall != SYS_CONN){return;}
			returnSystemCall(s->second->syscallUUID, 0);
			s->second->syscall = NONE;
			s->second->syscallUUID = 0;
			this->freePacket(packet);
			return;
		}else{
			// ???
		}
		this->freePacket(packet);
		return;		
	}

	this->freePacket(packet);
	return;

}

Packet * TCPAssignment::packet_signal(const uint32_t src_ip, const uint32_t dst_ip, unsigned short src_port,
						unsigned short dst_port, uint32_t seq_num, uint32_t ack_num, unsigned short flag){
	
	Packet *packet = this->allocatePacket(54);
	size_t ip_start = 14;
	size_t hlen = 20;
	//Assume header length is 5 (20 bytes)
	uint8_t len = 0x50;
	uint8_t sig = flag;

	// Match the endianess
	uint32_t seq_num_n = htonl(seq_num);
	uint32_t ack_num_n = htonl(ack_num);
	unsigned short win_size = 0x00c8;

	packet->writeData(ip_start + 12, &src_ip, 4);
	packet->writeData(ip_start + 16, &dst_ip, 4);
	packet->writeData(ip_start + hlen, &src_port, 2);
	packet->writeData(ip_start + hlen + 2, &dst_port, 2);
	packet->writeData(ip_start + hlen + 4, &seq_num_n, 4);
	packet->writeData(ip_start + hlen + 8, &ack_num_n, 4);
	packet->writeData(ip_start + hlen + 13, &sig, 1);
	packet->writeData(ip_start + hlen + 12, &len, 1);
	packet->writeData(ip_start + hlen + 14, &win_size, 2);

	uint16_t checksum = 0;
	packet->writeData(ip_start + hlen + 16, &checksum, 2);

	unsigned char tcp_seg[20];
	packet->readData(14+20, tcp_seg, 20);
	checksum = ~htons(NetworkUtil::tcp_sum(src_ip, dst_ip, (uint8_t*)tcp_seg, 20));
	packet->writeData(14+20+16, &checksum, 2);
	return packet;
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
std::pair<int, int> TCPAssignment::search_quartet(uint32_t src_ip, uint32_t dst_ip, 
												unsigned short src_port,unsigned short dst_port){
	bool correct = false;
	int i = 0;
	for (auto it = this->socket_list.begin();
		it != this->socket_list.end();
		it = std::next(it)){
		if ((! it->second->is_bound)|| ! (it->second->is_connected) ){
			continue;
		}

		std::pair<uint32_t, unsigned short> it_si = this->GetSrcIpPort(it->second);
		std::pair<uint32_t, unsigned short> it_di = this->GetDstIpPort(it->second);
		correct = (src_port == it_si.second) && (dst_port == it_di.second);
		correct = correct && (src_ip == INADDR_ANY || it_si.first==INADDR_ANY || src_ip == it_si.first);
		correct = correct && (dst_ip == INADDR_ANY || it_di.first==INADDR_ANY ||  it_di.first == dst_ip);
		if (correct)
			return it->first;
		i++;
	}
	return std::make_pair(-1,-1);
}
std::pair<uint32_t, unsigned short> TCPAssignment::GetSrcIpPort(struct socket_base *sock){
		if (!sock->is_bound){
			return std::make_pair((uint32_t)-1, (unsigned short)-1);
		}
		struct sockaddr_in src_addr_in = *(struct sockaddr_in *) &sock->src_addr;
		uint32_t src_ip = (uint32_t)src_addr_in.sin_addr.s_addr;
		unsigned short src_port = src_addr_in.sin_port;
		return std::make_pair(src_ip,src_port);
}
std::pair<uint32_t, unsigned short> TCPAssignment::GetDstIpPort(struct socket_base *sock){
		if (!sock->is_connected){
			return std::make_pair((uint32_t)-1, (unsigned short)-1);
		}
		struct sockaddr_in dst_addr_in = *(struct sockaddr_in *) &sock->dst_addr;
		uint32_t dst_ip = (uint32_t)dst_addr_in.sin_addr.s_addr;
		unsigned short dst_port = dst_addr_in.sin_port;
		return std::make_pair(dst_ip,dst_port);
}

}
