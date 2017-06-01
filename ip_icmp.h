/**
 * Created by suli on 6/1/17.
 */

#ifndef PING_IP_ICMP_H
#define PING_IP_ICMP_H

// icmp 头部
struct icmp {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_cksum;
	// 不同类型的 icmp 报文，后面都不一样
};

// icmp 回显报文头部
struct icmp_echo {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_cksum;
	uint16_t icmp_id;
	uint16_t icmp_seq;
	char icmp_data[0];
};

// icmp 子网掩码头部
struct icmp_mask {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_cksum;
	uint16_t icmp_id;
	uint16_t icmp_seq;
	struct in_addr icmp_mask;
};

// icmp 时间戳头部
struct icmp_time {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_cksum;
	uint16_t icmp_id;
	uint16_t icmp_seq;
	uint32_t icmp_origtime;
	uint32_t icmp_recvtime;
	uint32_t icmp_sendtime;
};

struct ip{
	// 主机字节序判断
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t ip_hl:4;        // 首部长度
	uint8_t ip_v:4;     // 版本
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t ip_v:4;
	uint8_t ip_hl:4;
#endif
	uint8_t ip_tos;             // 服务类型
	uint16_t ip_len;             // 总长度
	uint16_t ip_id;                // 标识符
	uint16_t ip_off;            // 标志和片偏移
#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* dont fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
	uint8_t ip_ttl;            // 生存时间
	uint8_t ip_p;       // 协议
	uint16_t ip_sum;       // 校验和
	struct in_addr ip_src;    // 32位源ip地址
	struct in_addr ip_dst;   // 32位目的ip地址
	// 可选项、数组起始部分
};



#endif //PING_IP_ICMP_H
