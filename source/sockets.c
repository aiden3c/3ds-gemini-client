#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>

#include <3ds.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/net_sockets.h>

#define SOC_ALIGN 0x1000
#define SOC_BUFFERSIZE 0x100000

__attribute__((format(printf, 1, 2)))
void failExit(const char *fmt, ...);

static u32 *SOC_buffer = NULL;
int clientsock = -1;

bool autotrust() {
    return true;
}

void socShutdown() {
    socExit();
}

void handshake() {

}

static void my_debug( void *ctx, int level,
                      const char *file, int line, const char *str )
{
    printf( str );
}

int main() {
    int ret;

    gfxInitDefault();
    atexit(gfxExit);
    consoleInit(GFX_TOP, NULL);

    printf("3DS Gemini Client\n");

    // Specify the protocol, hostname, port, and path
    //const char *protocol = "gopher";
    //const char *hostname = "cosmic.voyage";
    //const char *port = "70";
    //const char *path = "/1/";
    const char *protocol = "gemini";
    const char *hostname = "voidspace.blog";
    const char *port = "1965";
    const char *path = "/";
    

    // Set up socket service
    SOC_buffer = (u32 *)memalign(SOC_ALIGN, SOC_BUFFERSIZE);
    if (SOC_buffer == NULL) {
        failExit("memalign: failed to allocate\n");
    }
    // Now initialize soc:u service
    if ((ret = socInit(SOC_buffer, SOC_BUFFERSIZE)) != 0) {
        failExit("socInit: 0x%08X\n", (unsigned int)ret);
    }
    atexit(socShutdown);

    // Resolve the IP address for the server
    struct addrinfo *res;
    if (getaddrinfo(hostname, port, NULL, &res) != 0) {
        failExit("Could not resolve hostname \"%s\" on port %s", hostname, port);
    }

    printf("Resolved hostname \"%s\"\n", hostname);

    // Create a socket
    clientsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (clientsock == -1) {
        failExit("Failed to create socket: %s", strerror(errno));
    }

    //Set up Mbed TLS
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;

    mbedtls_x509_crt_init( &cacert );

    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_debug_set_threshold( 3 );



    if( ( ret = mbedtls_ssl_config_defaults ( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) ) != 0 ) {
        failExit("Failed to configure SSL");
    }

    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // TLS 1.3
    mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // TLS 1.3
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    mbedtls_ssl_set_verify( &ssl, autotrust, &server_fd );
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE );
    

    printf("Connecting...\n");
    if( ( ret = mbedtls_net_connect( &server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
        failExit("Failed to connect!");
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, hostname ) ) != 0 ) {
        failExit("Failed to set hostname");
    }
    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
    mbedtls_ssl_setup(&ssl, &conf);

    while ( ( ret = mbedtls_ssl_handshake(&ssl) ) != 0 ) {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            failExit("Failed to shake hands! Error: %i", ret);
        }
    }


    printf("Sending request\n");
    char request[1024];
    snprintf(request, sizeof(request), "%s://%s%s\r\n", protocol, hostname, path);

    if( mbedtls_ssl_write( &ssl, request, strlen(request) ) == -1) {
        failExit("Failed to send request\n%s", request);
    }

    char response[1024 * 4];
    ret = mbedtls_ssl_read( &ssl, response, sizeof(response) );
    printf(response);
    printf("%i bytes read", ret);

    printf("Press START to exit\n");
    while (aptMainLoop()) {
        gspWaitForVBlank();
        gfxSwapBuffers();
        hidScanInput();

        u32 kDown = hidKeysDown();

        if (kDown & KEY_START)
            break;
    }

    // Close the socket
    if (clientsock != -1) {
        close(clientsock);
    }

    gfxExit();
    return 0;
}

void failExit(const char *fmt, ...) {
    va_list ap;

    printf("\x1b[31;1m"); // Set color to red
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\x1b[0m"); // Reset color
    printf("\nPress B to exit\n");

    while (aptMainLoop()) {
        gspWaitForVBlank();
        hidScanInput();

        u32 kDown = hidKeysDown();
        if (kDown & KEY_B) exit(0);
    }
}
