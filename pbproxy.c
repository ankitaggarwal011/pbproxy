#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#define BUFFER_SZ 4096
#define IV_SZ 8

struct thread_args {
    int socket_fd;
    struct sockaddr connect_address;
    int connect_address_length;
    struct sockaddr_in socket_service;
    AES_KEY aes_key;
};

void* create_connection(void *args) {
    if (args == NULL) {
        pthread_exit(0);
    }

    struct thread_args *connection_params = (struct thread_args *) args;
    int socket_fd = connection_params->socket_fd;
    struct sockaddr connect_address = connection_params->connect_address;
    int connect_address_length = connection_params->connect_address_length;
    struct sockaddr_in socket_service = connection_params->socket_service;
    AES_KEY aes_key = connection_params->aes_key;
    
    int fd_service = socket(AF_INET, SOCK_STREAM, 0), packet_len;

    char buffer[BUFFER_SZ];
    
    if (connect(fd_service, (struct sockaddr *) &socket_service, sizeof(socket_service)) == -1) {
        fprintf(stderr, "Connection failed.\n");
        pthread_exit(0);
    }
    fprintf(stderr, "New connection established\n");
    
    int flgs = fcntl(socket_fd, F_GETFL);
    fcntl(socket_fd, F_SETFL, flgs | O_NONBLOCK);
    
    flgs = fcntl(fd_service, F_GETFL);
    fcntl(fd_service, F_SETFL, flgs | O_NONBLOCK);
    
    unsigned char ivec[AES_BLOCK_SIZE], ecount[AES_BLOCK_SIZE], IV[IV_SZ]; 
    unsigned int num;

    unsigned char ivec_d[AES_BLOCK_SIZE], ecount_d[AES_BLOCK_SIZE], IV_d[IV_SZ]; 
    unsigned int num_d;

    RAND_bytes(IV, 8);
    num = 0;
    memset(ecount, 0, AES_BLOCK_SIZE);
    memset(ivec + 8, 0, 8);
    memcpy(ivec, IV, 8);

    num_d = 0;
    memset(ecount_d, 0, AES_BLOCK_SIZE);
    memset(ivec_d + 8, 0, 8);
    
    while (1) {
        packet_len = read(socket_fd, buffer, BUFFER_SZ);
        while (packet_len > 0) {
            unsigned char decrypted[packet_len - 8];

            memcpy(IV_d, buffer, 8);
            memcpy(ivec_d, IV_d, 8);
            AES_ctr128_encrypt(buffer + 8, decrypted, packet_len - 8, &aes_key, ivec_d, ecount_d, &num_d);
            if (write(fd_service, decrypted, packet_len - 8) < 0) {
                fprintf(stderr, "Closing connection.\n");
                close(socket_fd);
                close(fd_service);
                free(connection_params);
                pthread_exit(0);
            }
            if (packet_len < BUFFER_SZ) {
                break;
            }
        }

        if (packet_len == 0) {
            break;
        }
        
        packet_len = read(fd_service, buffer, BUFFER_SZ);
        while (packet_len > 0) {
            unsigned char encrypted[packet_len];
            
            char *payload = (char*) malloc(packet_len + 8);
            memcpy(payload, IV, 8);

            AES_ctr128_encrypt(buffer, encrypted, packet_len, &aes_key, ivec, ecount, &num);
            memcpy(payload + 8, encrypted, packet_len);
            
            if (write(socket_fd, payload, packet_len + 8) < 0) {
                fprintf(stderr, "Closing connection.\n");
                close(socket_fd);
                close(fd_service);
                free(connection_params);
                pthread_exit(0);
            }
            free(payload);
            
            if (packet_len < BUFFER_SZ) {
                break;
            }
        }
        
        if (packet_len == 0) {
            break;
        }
    }
    
    fprintf(stderr, "Closing connection.\n");
    close(socket_fd);
    close(fd_service);
    free(connection_params);
    pthread_exit(0);
}

int init_server_mode(long l_port, struct hostent *d_host, long d_port, AES_KEY aes_key) {
    pthread_t connection_thread;
    struct sockaddr_in socket_client, socket_service;
    memset(&socket_client, 0, sizeof(socket_client));
    memset(&socket_service, 0, sizeof(socket_service));
    int fd_client = socket(AF_INET, SOCK_STREAM, 0);
    
    socket_client.sin_family = AF_INET;
    socket_client.sin_addr.s_addr = htons(INADDR_ANY);
    socket_client.sin_port = htons(l_port);
    
    socket_service.sin_family = AF_INET;
    socket_service.sin_addr.s_addr = ((struct in_addr *)(d_host->h_addr))->s_addr;
    socket_service.sin_port = htons(d_port);
    
    bind(fd_client, (struct sockaddr *) &socket_client, sizeof(socket_client));
    
    if (listen(fd_client, 8) < 0) {
        fprintf(stderr, "Listening has failed.\n");
        return 0;
    }
    
    while (1) {
        int socket_fd, connect_address_length;
        struct sockaddr connect_address;
        socket_fd = accept(fd_client, &connect_address, &connect_address_length);
        if (socket_fd > 0) {
            struct thread_args *args = (struct thread_args *) malloc(sizeof(struct thread_args));
            args->socket_fd = socket_fd;
            args->connect_address = connect_address;
            args->connect_address_length = connect_address_length;
            args->socket_service = socket_service;
            args->aes_key = aes_key;
            pthread_create(&connection_thread, 0, create_connection, (void*) args);
            pthread_detach(connection_thread);
        }
    }

    return 0;
}

int init_client_mode(struct hostent *d_host, long d_port, AES_KEY aes_key) {
    struct sockaddr_in socket_proxy;
    memset(&socket_proxy, 0, sizeof(socket_proxy));
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0), packet_len;
    char buffer[BUFFER_SZ];

    socket_proxy.sin_family = AF_INET;
    socket_proxy.sin_addr.s_addr = ((struct in_addr *)(d_host->h_addr))->s_addr;
    socket_proxy.sin_port = htons(d_port);
    
    if (connect(socket_fd, (struct sockaddr *) &socket_proxy, sizeof(socket_proxy)) == -1) {
        fprintf(stderr, "Connection failed.\n");
        return 0;
    }
    
    fcntl(socket_fd, F_SETFL, O_NONBLOCK);
    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    
    unsigned char ivec[AES_BLOCK_SIZE], ecount[AES_BLOCK_SIZE], IV[IV_SZ]; 
    unsigned int num;

    unsigned char ivec_d[AES_BLOCK_SIZE], ecount_d[AES_BLOCK_SIZE], IV_d[IV_SZ]; 
    unsigned int num_d;

    RAND_bytes(IV, 8);
    num = 0;
    memset(ecount, 0, AES_BLOCK_SIZE);
    memset(ivec + 8, 0, 8);
    memcpy(ivec, IV, 8);

    num_d = 0;
    memset(ecount_d, 0, AES_BLOCK_SIZE);
    memset(ivec_d + 8, 0, 8);
    
    while(1) {
        packet_len = read(STDIN_FILENO, buffer, BUFFER_SZ);
        while (packet_len > 0) {
            unsigned char encrypted[packet_len];
            char *payload = (char*) malloc(packet_len + 8);
            memcpy(payload, IV, 8);

            AES_ctr128_encrypt(buffer, encrypted, packet_len, &aes_key, ivec, ecount, &num);
            memcpy(payload + 8, encrypted, packet_len);
            
            if (write(socket_fd, payload, packet_len + 8) < 0) {
                close(socket_fd);
                return 0;
            }
            free(payload);

            if (packet_len < BUFFER_SZ) {
                break;
            }
        }
        
        packet_len = read(socket_fd, buffer, BUFFER_SZ);
        while (packet_len > 0) {
            unsigned char decrypted[packet_len - 8];
            memcpy(IV_d, buffer, 8);
            memcpy(ivec_d, IV_d, 8);
            
            AES_ctr128_encrypt(buffer + 8, decrypted, packet_len - 8, &aes_key, ivec_d, ecount_d, &num_d);
            
            write(STDOUT_FILENO, decrypted, packet_len - 8);
            if (packet_len < BUFFER_SZ) {
                break;
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int opt, server = 0;
    char *key = NULL, *listening_port = NULL, *destination = NULL, *destination_port = NULL;
    while ((opt = getopt(argc, argv, "l:k:")) != -1) {
        switch(opt) {
            case 'l':
                listening_port = optarg;
                server = 1;
                break;
            case 'k':
                key = optarg;
                break;
            case '?':
                if (optopt == 'l' || optopt == 'k') return 0;
                else break;
            default:
                break;
        }
    }
    if (optind < argc - 2 || optind > argc - 2) {
        fprintf(stderr, "Please enter the correct number of arguments.\n");
        fprintf(stderr, "Usage: ./pbproxy [-l port] -k keyfile destination port\n");
        return 0;
    }
    else if (optind == argc - 2) {
        destination = argv[optind];
        destination_port = argv[optind + 1];
    }

    // read key file
    FILE *fp = fopen(key, "rb");
    if (!fp) {
        fprintf(stderr, "Given key is not valid. Please try again.\n");
        return 0;
    }
    fseek(fp, 0L, SEEK_END);
    int _key_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    char *buf = malloc(_key_size * sizeof(char));
    fread(buf, sizeof(char), _key_size, fp);
    const char *_key = buf;
    fclose(fp);

    AES_KEY aes_key;
    if (AES_set_encrypt_key(_key, 128, &aes_key) < 0) {
        fprintf(stderr, "AES encrypted key error.\n");
        return 0;
    }
    
    long l_port, d_port;
    d_port = atol(destination_port);

    struct hostent *d_host = gethostbyname(destination);
    if (!d_host) {
        fprintf(stderr, "Destination host name is not valid. Please try again.\n");
        return 0;
    }

    if (server) {
        l_port = atol(listening_port);
        init_server_mode(l_port, d_host, d_port, aes_key);
    }
    else {
        init_client_mode(d_host, d_port, aes_key);
    }
    return 0;
}