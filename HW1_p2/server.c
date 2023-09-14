#include <sys/select.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/sha.h>
#define SERVER_PORT 3005
#define BUFFER_LENGTH 256
#define FALSE 0
#define HASH_LENGTH SHA_DIGEST_LENGTH
#include <errno.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL -1

typedef unsigned char byte;

void printHex(const unsigned char *buffer, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

void bytesToHex(const unsigned char *bytes, size_t length, char *hex)
{
    for (size_t i = 0; i < length; i++)
    {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
}

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("can't bind port");
        abort();
    }
    if (listen(sd, 10) != 0)
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

SSL_CTX *InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms(); /* load & register all cryptos, etc. */
    SSL_load_error_strings();     /* load all error messages */
    method = TLS_server_method(); /* create new server-method instance */
    ctx = SSL_CTX_new(method);    /* create new context from method */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
void Servlet(SSL *ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int sd, bytes;
    const char *ServerResponse = "<\\Body>\
                               <Name>aticleworld.com</Name>\
                 <year>1.5</year>\
                 <BlogType>Embedede and c\\c++<\\BlogType>\
                 <Author>amlendra<Author>\
                 <\\Body>";
    const char *cpValidMessage = "<Body>\
                               <UserName>aticle<UserName>\
                 <Password>123<Password>\
                 <\\Body>";
    if (SSL_accept(ssl) == FAIL) /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);                                            /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */ // here return the response of the PIN

        buf[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buf);

        SHA_CTX shactx;
        byte digest[SHA_DIGEST_LENGTH];
        byte client[SHA_DIGEST_LENGTH];
        int pin = 0;
        memcpy(client, buf, HASH_LENGTH);
        char str[20];

        while (pin < 10000)
        {
            snprintf(str, sizeof(str), "%d", pin);

            SHA1_Init(&shactx);
            SHA1_Update(&shactx, str, strlen(str));
            SHA1_Final(digest, &shactx);
            // printf("Client Hash: ");
            // for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
            // {
            //     printf("%02x", client[i]);
            // }
            // printf("\n");

            char digestHex[SHA_DIGEST_LENGTH * 2 + 1];
            bytesToHex(digest, SHA_DIGEST_LENGTH, digestHex);
            digestHex[SHA_DIGEST_LENGTH * 2] = '\0';
            // printf("Hash: ");
            // for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
            // {
            //     printf("%02x", digestHex[i]);
            // }
            // printf("\n");

            if (memcmp(digestHex, client, HASH_LENGTH) == 0)
            {

                printf("Found PIN: %s\n", str);
                break;
            }

            pin++;
        }
        if (pin >= 10000)
        {

            memset(buf, '0', sizeof(buf));
            sprintf(buf, "%d", -1);
        }
        else
        {

            memset(buf, '0', sizeof(buf));
            sprintf(buf, "%d", pin);
        }

        printf("server msg: \"%s\"\n", buf);
        if (bytes > 0)
        {
            // if (strcmp(cpValidMessage, buf) == 0)
            // {
            SSL_write(ssl, buf, strlen(buf)); /* send reply */
            // }
            // else
            // {
            //     SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); /* send reply */
            // }
        }
        else
        {
            ERR_print_errors_fp(stderr);
        }
    }
    sd = SSL_get_fd(ssl); /* get socket connection */
    SSL_free(ssl);        /* release SSL state */
    close(sd);            /* close connection */

    // rc = recv(sd2, buffer, BUFFER_LENGTH, 0);
    // if (rc <= 0)
    // {
    //     perror("Receive failed");
    //     close(sd2);
    //     continue;
    // }

    // buffer[rc] = '\0';
    // printf("Received hash from client: %s\n", buffer);

    // printf("\n");

    // unsigned char hash[HASH_LENGTH];

    // SHA_CTX shactx;
    // byte digest[SHA_DIGEST_LENGTH];
    // byte client[SHA_DIGEST_LENGTH];
    // int pin = 0;
    // memcpy(client, buffer, HASH_LENGTH);
    // char str[20];

    // while (pin < 10000)
    // {
    //     snprintf(str, sizeof(str), "%d", pin);

    //     SHA1_Init(&shactx);
    //     SHA1_Update(&shactx, str, strlen(str));
    //     SHA1_Final(digest, &shactx);
    //     // printf("Client Hash: ");
    //     // for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    //     // {
    //     //     printf("%02x", client[i]);
    //     // }
    //     // printf("\n");

    //     char digestHex[SHA_DIGEST_LENGTH * 2 + 1];
    //     bytesToHex(digest, SHA_DIGEST_LENGTH, digestHex);
    //     digestHex[SHA_DIGEST_LENGTH * 2] = '\0';
    //     // printf("Hash: ");
    //     // for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    //     // {
    //     //     printf("%02x", digestHex[i]);
    //     // }
    //     // printf("\n");

    //     if (memcmp(digestHex, client, HASH_LENGTH) == 0)
    //     {

    //         printf("Found PIN: %s\n", str);
    //         break;
    //     }

    //     pin++;
    // }
    // if (pin >= 10000)
    // {

    //     memset(buffer, '0', sizeof(buffer));
    //     sprintf(buffer, "%d", -1);
    // }
    // else
    // {

    //     memset(buffer, '0', sizeof(buffer));
    //     sprintf(buffer, "%d", pin);
    // }

    // rc = send(sd2, buffer, sizeof(buffer), 0);
    // if (rc < 0)
    // {
    //     perror("Send failed");
    // }

    // close(sd2);
}

int main()
{
    // int sd = -1, sd2 = -1;
    // int rc, length, on = 1;
    // char buffer[BUFFER_LENGTH];
    // fd_set read_fd;
    // struct timeval timeout;
    // struct sockaddr_in serveraddr;

    SSL_CTX *ctx;
    int server;
    int portnum;
    // libpincrack.so: pincrack.c
    // $(CC) -shared -o libpincrack.so pincrack.c $(CFLAGS) $(LDFLAGS) $(LIBS)

    // Only root user have the permsion to run the server
    // if (!isRoot())
    // {
    //     printf("This program must be run as root/sudo user!!");
    //     exit(0);
    // }
    // if (count != 2)
    // {
    //     printf("Usage: %s <portnum>\n", Argc[0]);
    //     exit(0);
    // }
    // Initialize the SSL library
    SSL_library_init();
    portnum = SERVER_PORT;
    ctx = InitServerCTX();                        /* initialize SSL */
    LoadCertificates(ctx, "cert.pem", "key.pem"); /* load certs */
    server = OpenListener(portnum);

    printf("Ready for client connect().\n");

    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr *)&addr, &len); /* accept connection as usual */
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);      /* get new SSL state with context */
        SSL_set_fd(ssl, client); /* set connection socket to SSL state */
        Servlet(ssl);            /* service connection */
    }
    close(server);     /* close server socket */
    SSL_CTX_free(ctx); /* release context */

    return 0;
}
