#include <iostream>
#include <optional>
#include <charconv>
#include <chrono>
#include <cstring>

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>

class FileDescriptor {
    int fd;

public:
    operator int() const {
        return fd;
    }

    explicit FileDescriptor(int fd) : fd{fd} {}
    FileDescriptor(const FileDescriptor&) = delete;
    ~FileDescriptor() { close(fd); }
};

class Socket : public FileDescriptor {
public:
    Socket(sa_family_t family, int type, int protocol) : FileDescriptor{::socket(family, type, protocol)} {}
};

struct TCPIP {
    struct ip ip;
    struct tcphdr tcp;
};

template <class T>
std::optional<T> parseNumber(std::string_view str) {
    T result;
    const auto [prt, ec] = std::from_chars(str.begin(), str.end(), result);
    if (ec != std::errc{}) {
        return std::nullopt;
    }
    return result;
}

ssize_t receive(const Socket& sock, auto& v) {
    return ::recv(sock, &v, sizeof(v), 0);
}

ssize_t send(const Socket& sock, const auto& v, const sockaddr_in& addr) {
    return ::sendto(sock, &v, sizeof(v), 0, (const sockaddr*)&addr, sizeof(addr));
}

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short checksum(const void* v, unsigned size)
{
    auto buf = (const char*)v;
    unsigned sum = 0, i;

    /* Accumulate checksum */
    for (i = 0; i < size - 1; i += 2)
    {
        unsigned short word16 = *(unsigned short *) &buf[i];
        sum += word16;
    }

    /* Handle odd-sized case */
    if (size & 1)
    {
        unsigned short word16 = (unsigned char) buf[i];
        sum += word16;
    }

    /* Fold to get the ones-complement result */
    while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

    /* Invert to get the negative in ones-complement arithmetic */
    return ~sum;
}

TCPIP createSynAckPacket(const struct sockaddr_in& src, const struct sockaddr_in& dst, uint32_t ack_seq)
{
    TCPIP packet{
            .ip = ip{
                    .ip_hl = 5,
                    .ip_v = 4,
                    .ip_len = sizeof(TCPIP),
                    .ip_id = (uint16_t)htonl(rand() % UINT16_MAX), // id of this packet,
                    .ip_ttl = 64,
                    .ip_p = IPPROTO_TCP,
                    .ip_src = src.sin_addr,
                    .ip_dst = dst.sin_addr,
            },
            .tcp = tcphdr{
                    .th_sport = src.sin_port,
                    .th_dport = dst.sin_port,
                    .th_seq = htonl(rand() % UINT32_MAX),
                    .th_ack = htonl(ack_seq),
                    .th_off = 5, // tcp header size
                    .th_flags = TH_SYN | TH_ACK,
                    .th_win = htons(5840),
            }
    };

    // required structs for IP and TCP header
    struct pseudo_header psh{};

    // TCP pseudo header for checksum calculation
    psh.source_address = src.sin_addr.s_addr;
    psh.dest_address = dst.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    constexpr auto psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    // fill pseudo packet
    char pseudogram[psize];
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), &packet.tcp, sizeof(packet.tcp));

    packet.tcp.th_sum = checksum(pseudogram, psize);
    packet.ip.ip_sum = checksum((const char*)&packet, sizeof(packet));

    return packet;
}

std::string_view now() {
    constexpr auto BUFFER_SIZE = 30;
    static char buffer[BUFFER_SIZE];
    auto t = time(nullptr);
    strftime(buffer, BUFFER_SIZE, "[%Y-%m-%d %H:%M:%S] ", localtime(&t));
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: \n" << argv[0] << " <port> <sleep-seconds>" << std::endl;
        return 1;
    }

    auto port = parseNumber<uint16_t>(argv[1]);
    if (port == std::nullopt) {
        std::cout << "Bad port" << std::endl;
        return 1;
    }

    auto sleepSeconds = parseNumber<uint32_t>(argv[2]);
    if (sleepSeconds == std::nullopt) {
        std::cout << "Bad sleep seconds" << std::endl;
        return 1;
    }

    Socket sock{AF_INET, SOCK_RAW, IPPROTO_TCP};
    if (sock == -1) {
        std::cout << "Socket failed " << std::strerror(errno) << std::endl;
        return 1;
    }

    struct sockaddr_in addr{
            .sin_family = AF_INET,
            .sin_port = htons(*port),
            .sin_addr = in_addr{
                    .s_addr = INADDR_ANY,
            },
    };

    if (::bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        std::cout << "Bind failed " << std::strerror(errno) << std::endl;
        return 1;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
        std::cout << "setsockopt(IP_HDRINCL, 1) failed " << std::strerror(errno) << std::endl;
        return 1;
    }

    std::cout << now() << "starting listening" << std::endl;
    TCPIP tcpIP{};
    for (;;) {
        auto received = receive(sock, tcpIP);
        if (received == 0) continue;
        if (received < 0) {
            std::cout << now() << "recv failed " << std::strerror(errno) << std::endl;
            return 1;
        }
        auto destPort = ntohs(tcpIP.tcp.dest);
        if (destPort != *port) {
            continue;
        }

        std::string_view ip = inet_ntoa(tcpIP.ip.ip_src);
        std::cout << now() << "new packet, size: " << received << ", from: " << ip << ":" << tcpIP.tcp.source << std::endl;

        if (tcpIP.tcp.syn) {
            std::cout << now() << "got SYN, seq: " << ntohl(tcpIP.tcp.seq) << std::endl;

            std::cout << now() << "sleeping " << *sleepSeconds << " seconds" << std::endl;
            sleep(*sleepSeconds);

            auto src = sockaddr_in{
                    .sin_port = tcpIP.tcp.dest,
                    .sin_addr = tcpIP.ip.ip_dst,
            };
            auto dst = sockaddr_in{
                    .sin_port = tcpIP.tcp.source,
                    .sin_addr = tcpIP.ip.ip_src,
            };
            auto seq = ntohl(tcpIP.tcp.seq);

            auto packet = createSynAckPacket(src, dst, seq + 1);
            auto sent = send(sock, packet, dst);
            if (sent < 0) {
                std::cout << now() << "send failed " << std::strerror(errno) << std::endl;
                return 1;
            }
            std::cout << now() << "sent SYN-ACK, seq: " << ntohl(packet.tcp.seq) << ", size: " << sent << std::endl;
        } else if (tcpIP.tcp.ack) {
            std::cout << now() << "got ACK, ack_seq: " << ntohl(tcpIP.tcp.ack_seq) << std::endl;
        }
    }

    return 0;
}
