#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>


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

#include <3ds.h>

#define SOC_ALIGN 0x1000
#define SOC_BUFFERSIZE 0x100000
static u32 *SOC_buffer = NULL;

__attribute__((format(printf, 1, 2)))
void failExit(const char *fmt, ...);

void socShutdown() {
    socExit();
}

static void my_debug( void *ctx, int level, const char *file, int line, const char *str )
{
    printf( str );
}

char* getGeminiPage(char* hostname, char* path, char* port, char* protocol) {
    int ret;
    //Set up Mbed TLS
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;
    mbedtls_entropy_context entropy;

    mbedtls_debug_set_threshold( 1 );
    
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    if(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        failExit("Failed to seed entropy, the universe is doomed!");
    }


    if( ( ret = mbedtls_ssl_config_defaults ( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) ) != 0 ) {
        failExit("Failed to configure SSL");
    }

    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    printf("Connecting...\n");
    if( ( ret = mbedtls_net_connect( &server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
        failExit("Failed to connect!%i",ret);
    }

    printf("Setting hostname\n");
    if( ( ret = mbedtls_ssl_set_hostname( &ssl, hostname ) ) != 0 ) {
        failExit("Failed to set hostname");
    }
    
    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
    printf("Setting up ssl\n");
    mbedtls_ssl_setup(&ssl, &conf);
    printf("Shaking hands...\n");
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

    char response[128];
    ret = mbedtls_ssl_read( &ssl, response, sizeof(response) );
    printf(response);
    printf("%i bytes read\n", ret);


    char body[1024 * 16];
    memset(body, 0, sizeof body);
    ret = mbedtls_ssl_read( &ssl, body, sizeof(body) );
    printf(body);

    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ssl_free(&ssl);
    mbedtls_entropy_free( &entropy );
    mbedtls_net_free( &server_fd );
    return body;
}

void pressAtocontinue() {
    printf("Press A to continue\n");
    while (aptMainLoop()) {
        gspWaitForVBlank();
        hidScanInput();

        u32 kDown = hidKeysDown();
        if (kDown & KEY_A) break;
    }
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
    const char *hostname = "hidden.nexus";
    const char *port = "1965";
    const char *path = "/";
    
    SOC_buffer = (u32 *)memalign(SOC_ALIGN, SOC_BUFFERSIZE);
    if (SOC_buffer == NULL) {
        failExit("memalign: failed to allocate\n");
    }
    if ((ret = socInit(SOC_buffer, SOC_BUFFERSIZE)) != 0) {
        failExit("socInit: 0x%08X\n", (unsigned int)ret);
    }
    atexit(socShutdown);

    getGeminiPage(hostname, path, port, protocol);
    pressAtocontinue();
    getGeminiPage("gemini.circumlunar.space", "/", "1965", "gemini");
    pressAtocontinue();
    getGeminiPage("voidspace.blog", "/", "1965", "gemini");
    pressAtocontinue();
    getGeminiPage("gemi.dev", "/weird.gmi", "1965", "gemini");
    pressAtocontinue();
    getGeminiPage("gemi.dev", "/apple-folklore/039.gmi", "1965", "gemini");



    failExit("Done!");
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
