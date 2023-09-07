#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>


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

#include <curl/curl.h>

#include <citro2d.h>

#include <3ds.h>

#define TOP_SCREEN_WIDTH 400
#define TOP_SCREEN_HEIGHT 240
#define TOP_CHAR_WIDTH 56
#define TOP_CHAR_HEIGHT 30

#define BOTTOM_SCREEN_WIDTH 320
#define BOTTOM_SCREEN_HEIGHT 240

#define MAX_PAGE_SIZE 1024 * 16


#define MAX_UI_BUTTONS 64 //Arbitrary

#define SOC_ALIGN 0x1000
#define SOC_BUFFERSIZE 0x100000
static u32 *SOC_buffer = NULL;

enum Action {
    NONE,
    EXIT,
    NEW_PAGE,
    NEW_TAB,
    CLOSE_TAB,
    OPEN_LINK
};

enum LineType {
    LINE_PLAIN,
    LINE_H1,
    LINE_H2,
    LINE_H3,
    LINE_LINK,
};

typedef struct {
    char* path;
    char* caption;
} Link;

typedef struct {
    char* text;
    enum LineType type;
} Line;

typedef struct {
    int x;
    int y;
    int z;
    int w;
    int h;
    int padding;
    u32 background;
    u32 border;
    u32 color;
    char text[15];
    enum Action action;
} UiButton;

__attribute__((format(printf, 1, 2)))
void failExit(const char *fmt, ...);

void socShutdown() {
    socExit();
}

static void my_debug( void *ctx, int level, const char *file, int line, const char *str )
{
    printf( str );
}

//Solid recs only for our UI for now
void drawRectangleWithPadding(int x, int y, int z, int w, int h, int padding, u32 background, u32 border) {
    C2D_DrawRectangle(x-padding, y-padding, z, w+padding, h+padding, border, border, border, border);
    C2D_DrawRectangle(x+(padding / 2), y + (padding / 2), z + 1, w - padding, h - padding, background, background, background, background);
}

void drawText(int x, int y, int z, float scale, u32 color, char* text, int flags, C2D_Font font) {
    C2D_Text drawText;
    C2D_TextBuf dynamicBuffer = C2D_TextBufNew(MAX_PAGE_SIZE);
    C2D_TextBufClear(dynamicBuffer);
    C2D_TextFontParse( &drawText, font, dynamicBuffer, text );
    C2D_TextOptimize( &drawText );

    C2D_DrawText( &drawText, flags, x, y, z, scale, scale, color, TOP_SCREEN_WIDTH - 9.0 );

    C2D_TextBufDelete(dynamicBuffer);
}

void drawButton(UiButton button, C2D_Font font) {
    int x = button.x;
    int y = button.y;
    int z = button.z;
    int w = button.w;
    int h = button.h;

    int padding = button.padding;
    u32 background = button.background;
    u32 border = button.border;
    u32 color = button.color;
    char *text = button.text;

    C2D_Text drawText;
    C2D_TextBuf dynamicBuffer = C2D_TextBufNew(4096);
    C2D_TextBufClear(dynamicBuffer);
    C2D_TextFontParse(&drawText, font, dynamicBuffer, text);
    C2D_TextOptimize(&drawText);
    C2D_DrawRectangle(x, y, z - 1, w, h, border, border, border, border);
    C2D_DrawRectangle(x+(padding / 2), y + (padding / 2), z, w-padding, h-padding, background, background, background, background);
    float scale = 0.8;
    C2D_DrawText(&drawText, C2D_WithColor, x + padding, y + ( (1-scale) * padding ), z, scale, scale, color);
    C2D_TextBufDelete(dynamicBuffer);
}

void getGeminiPage(char* hostname, char* path, char* port, char response_body[MAX_PAGE_SIZE]) {
    u32 clrIced  = C2D_Color32(0xFB, 0xFC, 0xFC, 0xFF);
    u32 clrClear = C2D_Color32(0x04, 0x0D, 0x13, 0xFF);
    int ret;
    memset(response_body, 0, MAX_PAGE_SIZE);

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
    mbedtls_ssl_conf_handshake_timeout( &conf, 1000, 7000 );

    if( ( ret = mbedtls_net_connect( &server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
        memcpy(response_body, "Failed to connect!", MAX_PAGE_SIZE);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_ssl_free(&ssl);
        mbedtls_entropy_free( &entropy );
        mbedtls_net_free( &server_fd );
        return;
    }

    printf("Setting hostname\n");
    if( ( ret = mbedtls_ssl_set_hostname( &ssl, hostname ) ) != 0 ) {
        memcpy(response_body, "Failed to set hostname", MAX_PAGE_SIZE);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_ssl_free(&ssl);
        mbedtls_entropy_free( &entropy );
        mbedtls_net_free( &server_fd );
        return;
    }
    
    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
    printf("Setting up ssl\n");
    mbedtls_ssl_setup(&ssl, &conf);
    printf("Shaking hands...\n");
    while ( ( ret = mbedtls_ssl_handshake(&ssl) ) != 0 ) {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            char retstr[32];

            sprintf(retstr, "%d", ret);
            char* err = "Failed to shake hands! Error: ";
            memcpy(response_body, strcat(err, retstr), MAX_PAGE_SIZE);
            mbedtls_x509_crt_free(&cacert);
            mbedtls_ssl_config_free(&conf);
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_ssl_free(&ssl);
            mbedtls_entropy_free( &entropy );
            mbedtls_net_free( &server_fd );
            return;
        }
    }


    char request[1024];
    snprintf(request, sizeof(request), "%s://%s%s\r\n", "gemini", hostname, path);

    if( mbedtls_ssl_write( &ssl, request, strlen(request) ) == -1) {
        memcpy(response_body, strcat("Failed to send request\n", request), MAX_PAGE_SIZE);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_ssl_free(&ssl);
        mbedtls_entropy_free( &entropy );
        mbedtls_net_free( &server_fd );
        return;
    }

    char response[128];
    ret = mbedtls_ssl_read( &ssl, response, sizeof(response) );
    
    memcpy(response_body, response, strlen(response));
    mbedtls_ssl_read( &ssl, response_body+strlen(response), MAX_PAGE_SIZE );
    
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ssl_free(&ssl);
    mbedtls_entropy_free( &entropy );
    mbedtls_net_free( &server_fd );
    return;
}

void getKeyboardInput(char output[1024]) {
    bool in_keyboard = true;
    static SwkbdState swkbd;
    static char keyboardBuffer[1024];
    SwkbdButton button = SWKBD_BUTTON_NONE;
    static SwkbdStatusData swkbdStatus;
    swkbdInit(&swkbd, SWKBD_TYPE_NORMAL, 2, -1);
    swkbdSetInitialText(&swkbd, keyboardBuffer);
    swkbdSetHintText(&swkbd, "A gemini url, without \"gemini://\"");
    static bool reload = false;
    swkbdSetStatusData(&swkbd, &swkbdStatus, reload, true);
    reload = true;
    button = swkbdInputText(&swkbd, keyboardBuffer, sizeof(keyboardBuffer));    

    if(in_keyboard) {
        if(button != SWKBD_BUTTON_NONE) {
            memset(output, 0, 1024);
            memcpy( output, keyboardBuffer, 1024 );
        }
    }
    return;
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

Line* parseGemtext(const char* text, int* total) {
    Line* lines = NULL;
    const char* delimiter = "\n";
    char* text_copy = strdup(text); // Make a copy of the input text

    char *textline = strtok(text_copy, delimiter);

    while (textline != NULL) {
        int type = LINE_PLAIN;
        // Replace unconventional whitespace with normal spaces
        for (int i = 0; textline[i]; i++) {
            if (isspace((unsigned char)textline[i]) && textline[i] != '\n') {
                textline[i] = ' ';
            }
        }

        const char* h1_token = "#";
        const char* h2_token = "##";
        const char* h3_token = "###";
        const char* link_token = "=>";
        
        if (textline) {
            //Remove preceding whitespace, I dont think this is necessary but hey
            while (isspace(*textline)) {
                textline++;
            }
            
            if (strncmp(textline, h3_token, strlen(h3_token)) == 0) {
                type = LINE_H3;
                textline += strlen(h3_token);
            } else if (strncmp(textline, h2_token, strlen(h2_token)) == 0) {
                type = LINE_H2;
                textline += strlen(h2_token);
            } else if (strncmp(textline, h1_token, strlen(h1_token)) == 0) {
                type = LINE_H1;
                textline += strlen(h1_token);
            } else if (strncmp(textline, link_token, strlen(link_token)) == 0) {
                type = LINE_LINK;
                textline += strlen(link_token);
            }

            //Remove any spaces after declaration of special functions
            while (isspace(*textline)) {
                textline++;
            }
        }

        // Allocate memory for the Line structure
        lines = realloc(lines, (*total + 1) * sizeof(Line));

        // Initialize the Line structure and copy the textline
        lines[*total].text = strdup(textline); // strdup allocates memory for the text
        lines[*total].type = type;

        (*total)++; // Increment the total count

        textline = strtok(NULL, delimiter);
    }

    free(text_copy); // Free the copied text
    return lines;
}

void parseUrl(const char *url, char *host, char *port, char *path) {
    char *protocol = "gemini://";
    char *colon, *slash;

    // Check if the URL starts with a protocol
    if (strncmp(url, protocol, strlen(protocol)) == 0) {
        url += strlen(protocol);
    }

    // Find the first colon (:) to determine if there is a port
    colon = strchr(url, ':');

    // Find the first slash (/) to determine the end of the host and start of the path
    slash = strchr(url, '/');

    if (colon) {
        // Port is specified
        strncpy(host, url, colon - url);
        host[colon - url] = '\0';
        strncpy(port, colon + 1, slash ? slash - colon - 1 : strlen(url) - (colon - url));
        port[slash ? slash - colon - 1 : strlen(url) - (colon - url)] = '\0';
    } else {
        // No port specified
        if (slash) {
            strncpy(host, url, slash - url);
            host[slash - url] = '\0';
        } else {
            // No port and no path
            strcpy(host, url);
        }
        strcpy(port, "1965"); // Default port if not specified
    }

    if (slash) {
        // Path is specified
        strcpy(path, slash);
    } else {
        // No path specified
        strcpy(path, "/");
    }
}

UiButton uiButtons[MAX_UI_BUTTONS];
char current_text[MAX_PAGE_SIZE] = "3DS Gemini Client\nBy abraxas@hidden.nexus\n";
char current_url[1024] = "Enter URL";
Link links[128];
// Create a URL handle
int main() {
    int ret;
    int scroll = 0;
    int linkCount = 0;
    int currentUiButtons = 0;
    romfsInit();
    cfguInit();
    gfxInitDefault();
    atexit(gfxExit);
    C3D_Init(C3D_DEFAULT_CMDBUF_SIZE);
    C2D_Init(C2D_DEFAULT_MAX_OBJECTS);
    C2D_Prepare();
    C3D_RenderTarget* top = C2D_CreateScreenTarget(GFX_TOP, GFX_LEFT);

    C3D_RenderTarget* bottom = C2D_CreateScreenTarget(GFX_BOTTOM, GFX_LEFT);
    C2D_Font font = C2D_FontLoad("romfs:/ffbold.bcfnt");
    

    u32 clrWhite = C2D_Color32(0xFF, 0xFF, 0xFF, 0xFF);
	u32 clrGreen = C2D_Color32(0x00, 0xFF, 0x00, 0xFF);
	u32 clrRed   = C2D_Color32(0xFF, 0x00, 0x00, 0xFF);
	u32 clrBlue  = C2D_Color32(0x00, 0x00, 0xFF, 0xFF);

    u32 clrIced  = C2D_Color32(0xFB, 0xFC, 0xFC, 0xFF);
    u32 clrLink  = C2D_Color32(0xFF, 0xF4, 0xD2, 0xFF);
    u32 clrClear = C2D_Color32(0x04, 0x0D, 0x13, 0xFF);
    
    SOC_buffer = (u32 *)memalign(SOC_ALIGN, SOC_BUFFERSIZE);
    if (SOC_buffer == NULL) {
        failExit("memalign: failed to allocate\n");
    }
    if ((ret = socInit(SOC_buffer, SOC_BUFFERSIZE)) != 0) {
        failExit("socInit: 0x%08X\n", (unsigned int)ret);
    }
    atexit(socShutdown);
    atexit(C2D_Fini);
    atexit(C3D_Fini);
    UiButton urlButton = { 0, 0, 0, BOTTOM_SCREEN_WIDTH/2, BOTTOM_SCREEN_HEIGHT/10, 6, clrClear, clrWhite, clrIced, "Enter URL", NEW_PAGE };
    UiButton exitButton = { (BOTTOM_SCREEN_WIDTH / 2) - 3, 0, 0, (BOTTOM_SCREEN_WIDTH/2) + 3, BOTTOM_SCREEN_HEIGHT/10, 6, clrClear, clrWhite, clrIced, "Exit", EXIT };
    while (aptMainLoop())
    {
        currentUiButtons = 0;
        uiButtons[currentUiButtons++] = urlButton;
        uiButtons[currentUiButtons++] = exitButton;
        hidScanInput();
        u32 kDown = hidKeysDown();
        u32 kHeld = hidKeysHeld();
		if (kDown & KEY_START)
            break; //TODO replace this with a proper menu screen
        
        //Process button inputs
        if (kHeld & KEY_DOWN) {
            scroll -= 3;
        }
        if (kHeld & KEY_UP) {
            scroll += 3;
        }

        touchPosition touch;
        hidTouchRead( &touch );

        C3D_FrameBegin(C3D_FRAME_SYNCDRAW);
        C2D_TargetClear(top, clrClear);
        C2D_SceneBegin(top);

        int lineCount = 0;
        Line *lines = parseGemtext(current_text, &lineCount);
        Link links[128];
        int i;
        int offset = 0;
        for (i = 0; i < lineCount; i++ ) {
            
            if(lines[i].type == LINE_PLAIN) {
                drawText(6, 6 + scroll + offset, 0, .6, clrIced, lines[i].text, C2D_WithColor | C2D_WordWrap, font);
            } else if (lines[i].type == LINE_H1) {
                drawText(6, 6 + scroll + offset, 0, 1, clrGreen, lines[i].text, C2D_WithColor | C2D_WordWrap, font);
                offset += 12;
            } else if (lines[i].type == LINE_H2) {
                drawText(6, 6 + scroll + offset, 0, .8, clrRed, lines[i].text, C2D_WithColor | C2D_WordWrap, font);
                offset += 9;
            } else if (lines[i].type == LINE_H3) {
                drawText(6, 6 + scroll + offset, 0, .7, clrBlue, lines[i].text, C2D_WithColor | C2D_WordWrap, font);
                offset += 6;
            } else if (lines[i].type == LINE_LINK) {
                drawText(6, 6 + scroll + offset + 3, 0, .6, clrLink, lines[i].text, C2D_WithColor | C2D_WordWrap, font);
                char* linktext = malloc(strlen(lines[i].text) + 1);
                char linkbuttontext[14];
                strcpy(linktext, lines[i].text);
                Link link = { strtok(linktext, " "), strtok(NULL, "") };
                free(linktext);
                if (linkCount < 128) {
                    UiButton linkbutton = { 0, 16 + (linkCount * (BOTTOM_SCREEN_HEIGHT / 10)), 0, BOTTOM_SCREEN_WIDTH, 2*(BOTTOM_SCREEN_HEIGHT/10), 6, clrClear, clrWhite, clrLink, "Link", OPEN_LINK };
                    uiButtons[currentUiButtons++] = linkbutton;
                    memset(uiButtons[currentUiButtons-1].text, 0, sizeof(urlButton.text));
                    memcpy(uiButtons[currentUiButtons-1].text, lines[i].text, 14);
                    links[linkCount++] = link; // Add the link to the array and increment the counter
                }
                offset += 3;
            }
            

            
            for (int j = strlen(lines[i].text); j >= 0; j -= 56 ) {
                offset += 24; //Good offset, looks nice and groups WordWrap lines together nicely
            }
        }

        //Render UI
        C2D_TargetClear(bottom, clrClear);
        C2D_SceneBegin(bottom);

        enum Action uiAction = NONE;
        for(i = 0; i < currentUiButtons; i++) {
            UiButton button = uiButtons[i];
            if( (touch.px > button.x) && (touch.py > button.y && touch.py < button.h ) ) {
                uiAction = button.action;
            }
            drawButton(button, font);
        }

        if(uiAction == NEW_PAGE) {
            memset(current_text, 0, sizeof(current_text));
            getKeyboardInput(&current_url);

            memset(uiButtons[0].text, 0, sizeof(urlButton.text));
            memcpy(uiButtons[0].text, current_url, 14);
            
            char host[256];
            char port[6];
            char path[1024];
            memset(host, 0, sizeof host);
            memset(port, 0, sizeof port);
            memset(path, 0, sizeof path);
            

            parseUrl(current_url, &host, &port, &path);
            getGeminiPage(host, path, port, &current_text);

            scroll = 0;
        }
        else if(uiAction == EXIT) {
            exit(0);
        }

        C3D_FrameEnd(0);
        
        //Clean up dynamic buttons (links) RMEMBER IF MORE EXIST YOU HAVE YOU STACK AND REMOVE IN ORDER
        while(linkCount > 0) {
            linkCount--;
            uiButtons[linkCount] = uiButtons[linkCount + 1];
        }
    }
    C2D_FontFree(font);
    exit(0);
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
