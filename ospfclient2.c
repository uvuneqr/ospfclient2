#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <time.h>

#define BUFSIZE 1024

#define OSPF_VERSION 2
#define OSPF_TYPE_DB_DESCRIPTION 2
#define OSPF_TYPE_LS_REQUEST 3
#define OSPF_TYPE_LS_UPDATE 4
#define OSPF_TYPE_LS_ACKNOWLEDGEMENT 5

#pragma pack(1)
struct ospf_hello {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t router_id;
    uint32_t area_id;
    uint16_t checksum;
    uint16_t auth_type;
    uint64_t auth_data;
    uint32_t network_mask;
    uint16_t hello_interval;
    uint8_t options;
    uint8_t priority;
    uint32_t dead_interval;
    uint32_t de_router;
    uint32_t backup_router;
};


#pragma pack(1)
struct ospf_db_description {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t router_id;
    uint32_t area_id;
    uint16_t checksum;
    uint16_t auth_type;
    uint64_t auth_data;
    uint16_t interface_mtu;
    uint8_t options;
    uint8_t flags;
    uint32_t dd_sequence_number;
};


uint16_t check_sum(const void *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *words = data;

    // Add up all the 16-bit words.
    for (size_t i = 0; i < len / 2; i++) {
        sum += ntohs(words[i]);
    }

    // If the length is odd, add the last byte with zero padding.
    if (len % 2) {
        uint16_t last_word = ntohs(*(const uint8_t *)(data + len - 1));
        sum += last_word;
    }

    // Add the carries and invert the result.
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

uint32_t get_random_uint32() {
    uint32_t result = 0;
    int i;
    srand(time(NULL)); // 设置随机数种子

    for (i = 0; i < 4; i++) {
        result = (result << 8) + rand(); // 每次生成8位随机数，然后合并为32位整数
    }
    return result;
}



int main(int argc, char **argv) {
    int sockfd, ret;
    char *src_ip_str;
    char *src_mask_str;

    /* check command line arguments */
    if (argc != 3) {
       fprintf(stderr,"usage: %s <hostname> <port>\n", argv[0]);
       exit(0);
    }
    src_ip_str = argv[1];
    src_mask_str = argv[2];
    
    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_RAW, 0x59);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    //禁止组播回送（防止收到自己发送的组播包）
    int op = 0;
    ret = setsockopt(sockfd, IPPROTO_IP , IP_MULTICAST_LOOP, &op, sizeof(op));
    if (ret < 0) {
        perror("setsockopt");
        return -1;
    }
    // 设置套接字选项，允许地址重用
    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    // IP_TOS字段（也称为IP服务类型）用于表示IP数据包的类型，其中包括四个子字段：优先级（3 bits）、延迟（1 bit）、吞吐量（1 bit）和可靠性（1 bit）。
    // 优先级子字段用于设置IP数据包的服务等级，其中包括网络控制、重要数据、普通数据、非关键数据等4种不同级别。
    // 默认情况下，IP数据包的服务类型是0，即best-effort服务，这个服务类型对应的包类型是“send by us”。
    // 如果要将服务类型设置为multicast类型，可以将IP_TOS字段的最高位（第7位）设置为1，将优先级子字段设置为4，表示组播优先级。
    // 这个服务类型对应的包类型就是multicast
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &on, sizeof(on)) < 0) {
        perror("setsockopt() failed");
        exit(EXIT_FAILURE);
    }
    unsigned char tos = 0xc0; // 1110 0000, 将最高位设置为1，优先级设置为4
    if (setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0) {
        perror("setsockopt() failed");
        exit(EXIT_FAILURE);
    }

    // 绑定到本地地址
    // struct sockaddr_in addr;
    // memset(&addr, 0, sizeof(addr));
    // addr.sin_family = AF_INET;
    // addr.sin_port = htons(55225);
    // addr.sin_addr.s_addr = INADDR_ANY;
    // if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    //     perror("bind");
    //     exit(1);
    // }

    // 设置组播选项
    struct ip_mreqn group;
    memset(&group, 0, sizeof(struct ip_mreqn));
    group.imr_multiaddr.s_addr = inet_addr("224.0.0.5"); // 组播地址
    group.imr_address.s_addr = htonl(INADDR_ANY); // 本机IP地址
    group.imr_ifindex =  0;//if_nametoindex("ens33");  // 网卡编号
    ret = setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group, sizeof(group));
    if (ret < 0) {
        perror("setsockopt");
        return -1;
    }
 
    // 设置hello包
    struct ospf_hello hello;
    memset(&hello, 0, sizeof(hello));
    hello.version = 2;
    hello.type = 1; // hello包
    hello.length = htons(sizeof(hello));
    hello.router_id = inet_addr(src_ip_str);//inet_addr("192.168.5.107");
    hello.area_id = 0;
    hello.checksum = 0;
    hello.auth_type = 0;
    hello.auth_data = 0;
    hello.hello_interval = htons(10);
    hello.network_mask = inet_addr(src_mask_str);
    hello.options = 0x02; // V6支持
    hello.checksum = 0;
    hello.priority = 1;
    hello.dead_interval = htonl(40);
    hello.de_router = inet_addr(src_ip_str);
    hello.backup_router = inet_addr("0.0.0.0");
    hello.checksum = htons(check_sum(&hello, sizeof(hello)));
    
    // 发送hello包
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr("224.0.0.5");
    // dst_addr.sin_port = htons(55521);
    ret = sendto(sockfd, &hello, sizeof(hello), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    if (ret < 0) {
        perror("sendto");
        return -1;
    }
    sleep(1);
    ret = sendto(sockfd, &hello, sizeof(hello), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    if (ret < 0) {
        perror("sendto");
        return -1;
    }


    // 接收路由传回来的应答包
    char buffer[1024];
    struct ospf_hello *hello_resp;
    struct sockaddr_in *from_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    socklen_t from_len = sizeof(from_addr);
    memset(from_addr, 0, from_len);

    memset(buffer, 0, sizeof(buffer));
    ret = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)from_addr, &from_len);
    if (ret < 0) {
        perror("recvfrom");
        return -1;
    }

    // 解析应答包
    hello_resp = (struct ospf_hello *)(buffer+20);        //会返回包括ip head
    char *dst_ip_str = (char *)malloc(strlen(inet_ntoa(from_addr->sin_addr)));
    char *dst_mask_str = (char *)malloc(strlen(inet_ntoa(*(struct in_addr *)&hello_resp->network_mask)));
    char *dst_id_str = (char *)malloc(strlen(inet_ntoa(*(struct in_addr *)&hello_resp->router_id)));
            
    memcpy(dst_ip_str, inet_ntoa(from_addr->sin_addr), strlen(inet_ntoa(from_addr->sin_addr)));
    memcpy(dst_mask_str, inet_ntoa(*(struct in_addr *)&hello_resp->network_mask), strlen(inet_ntoa(*(struct in_addr *)&hello_resp->network_mask)));
    memcpy(dst_id_str, inet_ntoa(*(struct in_addr *)&hello_resp->router_id), strlen(inet_ntoa(*(struct in_addr *)&hello_resp->router_id)));
    
    printf("Received Hello packet from %s\n", dst_ip_str);
    printf("  OSPF version: %d\n", hello_resp->version);
    printf("  Router ID: %s\n", inet_ntoa(*(struct in_addr *)&hello_resp->router_id));
    printf("  Network mask: %s\n", dst_mask_str);
    printf("  Hello interval: %d seconds\n", ntohs(hello_resp->hello_interval));
   
    //关闭socket
    close(sockfd);

    sockfd = socket(AF_INET, SOCK_RAW, 0x59);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    //create db 
    uint32_t random = get_random_uint32();
    struct ospf_db_description db_desc;
    memset(&db_desc, 0, sizeof(db_desc));
    db_desc.version = OSPF_VERSION;
    db_desc.type = OSPF_TYPE_DB_DESCRIPTION;
    db_desc.length = htons(sizeof(db_desc));
    db_desc.router_id = inet_addr(src_ip_str);
    db_desc.area_id = inet_addr("0.0.0.0");
    db_desc.checksum = 0;
    db_desc.auth_data = 0;
    db_desc.auth_type = 0;
    db_desc.interface_mtu = htonl(1500);
    db_desc.options = 0x02;  // set E-bit
    db_desc.flags = 0x07;    // set M-bit
    db_desc.dd_sequence_number = htonl(random);
    db_desc.checksum = htons(check_sum(&db_desc, sizeof(db_desc)));

    // 发送db包
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(dst_ip_str);
    // dst_addr.sin_port = htons(55521);
    ret = sendto(sockfd, &db_desc, sizeof(db_desc), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    if (ret < 0) {
        perror("sendto");
        return -1;
    }

    // 接收路由传回来的应答包
    struct ospf_db_description *db_resp;
    memset(from_addr, 0, from_len);
    memset(buffer, 0, sizeof(buffer));
    ret = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)from_addr, &from_len);
    if (ret < 0) {
        perror("recvfrom");
        return -1;
    }

    // 解析应答包

    db_resp = (struct ospf_db_description *)(buffer+20);
    printf("recieve db\n");

    //关闭socket
    close(sockfd);
    return 0;
}
