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

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/net_sockets.h>

#include <3ds.h>

#define SOC_ALIGN 0x1000
#define SOC_BUFFERSIZE 0x100000

__attribute__((format(printf, 1, 2)))
void failExit(const char *fmt, ...);

static u32 *SOC_buffer = NULL;
int clientsock = -1;

void socShutdown() {
    socExit();
}

void handshake() {

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
    const char *protocol = "http";
    const char *hostname = "voidspace.blog";
    const char *port = "80";
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

    // Connect to the server
    if (connect(clientsock, res->ai_addr, res->ai_addrlen) == -1) {
        failExit("Couldn't connect!");
    }

    // Send the Gopher/Gemini request
    char request[1024];
    snprintf(request, sizeof(request), "GET / HTTP/1.0\r\n\r\n");
    //snprintf(request, sizeof(request), "%s://%s:%s%s\r\n", protocol, hostname, port, path);
    //snprintf(request, sizeof(request), "%s\r\n", path);
    
    printf("Requesting \"%s\"\n", request);
    if (write(clientsock, request, strlen(request)) == -1) {
        failExit("Could not send request to server. Requesting:\n\n%s", request);
    }

    printf("Reading response...\n");
    char buffer[1024];
    ssize_t bytes_read = 0;
    while (read(clientsock, buffer, sizeof(buffer)) > 0) {
        bytes_read++;
    }

    printf("Read %i bytes\n", bytes_read);
    printf(buffer);

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
