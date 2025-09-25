/**************************************************************************
 * Archivo: util.h
 * 
 * Descripción: Cabecera de utilidades y definiciones comunes para el loader.
 * Este archivo proporciona:
 * - Definiciones para análisis de archivos ELF
 * - Constantes de arquitecturas soportadas
 * - Funciones de utilidad para red y strings
 * - Estructuras de datos compartidas
 * 
 * El código es fundamental para el análisis de binarios y la
 * comunicación en red del loader de Mirai.
 **************************************************************************/

#pragma once

/* Inclusión de cabeceras necesarias */
#include "server.h"      /* Definiciones del servidor */
#include "includes.h"    /* Definiciones comunes */

/* Tamaño del buffer para operaciones de red y archivo */
#define BUFFER_SIZE 4096

/***************************************************************************
 * Definiciones para análisis de encabezados ELF
 ***************************************************************************/

/* Constantes para el encabezado ELF */
#define EI_NIDENT   16  /* Tamaño del campo e_ident en encabezado ELF */
#define EI_DATA     5   /* Offset para endianness en e_ident */

/* Tipos de endianness soportados */
#define EE_NONE     0   /* Sin endianness definido */
#define EE_LITTLE   1   /* Little endian (x86, ARM) */
#define EE_BIG      2   /* Big endian (MIPS, PowerPC) */

/***************************************************************************
 * Tipos de archivos ELF
 ***************************************************************************/
#define ET_NOFILE   0   /* Sin tipo definido */
#define ET_REL      1   /* Archivo reubicable (objeto) */
#define ET_EXEC     2   /* Archivo ejecutable */
#define ET_DYN      3   /* Objeto compartido (biblioteca) */
#define ET_CORE     4   /* Archivo core (volcado de memoria) */

/***************************************************************************
 * Arquitecturas soportadas en formato ELF
 * 
 * Esta sección define las constantes que identifican las diferentes
 * arquitecturas de procesador soportadas en el formato ELF.
 * Estas definiciones son cruciales para:
 * - Identificación correcta de binarios
 * - Selección de payload apropiado
 * - Compatibilidad de ejecución
 ***************************************************************************/

#define EM_NONE         0       /* Sin arquitectura específica */
#define EM_M32          1       /* AT&T WE 32100 */
#define EM_SPARC        2       /* SPARC */
#define EM_386          3       /* Intel 80386 */
#define EM_68K          4       /* Motorola 68000 */
#define EM_88K          5       /* Motorola 88000 */
#define EM_486          6       /* Intel 80486 */
#define EM_860          7       /* Intel 80860 */
#define EM_MIPS         8       /* MIPS R3000 (solo big-endian oficial) */
                                /* Las siguientes dos definiciones son históricas
                                   y los binarios y módulos de estos tipos serán
                                   rechazados por Linux */
#define EM_MIPS_RS3_LE  10      /* MIPS R3000 little-endian (histórico) */
#define EM_MIPS_RS4_BE  10      /* MIPS R4000 big-endian (histórico) */

/* Arquitecturas modernas y sistemas embebidos */
#define EM_PARISC       15      /* HP PA-RISC */
#define EM_SPARC32PLUS  18      /* SPARC v8+ mejorado */
#define EM_PPC          20      /* PowerPC 32 bits */
#define EM_PPC64        21      /* PowerPC 64 bits */
#define EM_SPU          23      /* Cell Broadband Engine SPU */
#define EM_ARM          40      /* ARM 32 bits - Común en IoT */
#define EM_SH           42      /* Renesas SuperH */
#define EM_SPARCV9      43      /* SPARC v9 64 bits */
#define EM_H8_300       46      /* Renesas H8/300 - Sistemas embebidos */
#define EM_IA_64        50      /* Intel Itanium */
#define EM_X86_64       62      /* AMD/Intel x86-64 */
#define EM_S390         22      /* IBM System/390 */

/* Procesadores para sistemas embebidos y especializados */
#define EM_CRIS         76      /* Axis Communications 32 bits */
#define EM_M32R         88      /* Renesas M32R */
#define EM_MN10300      89      /* Panasonic MN10300 */
#define EM_OPENRISC     92      /* OpenRISC 32 bits */
#define EM_BLACKFIN     106     /* Analog Devices Blackfin */
#define EM_ALTERA_NIOS2 113     /* Altera Nios II */
#define EM_TI_C6000     140     /* Texas Instruments C6x DSP */
#define EM_AARCH64      183     /* ARM 64 bits - Servidores/Móviles */
#define EM_TILEPRO      188     /* Tilera TILEPro - Multiprocesador */
#define EM_MICROBLAZE   189     /* Xilinx MicroBlaze */
#define EM_TILEGX       191     /* Tilera TILE-Gx */
#define EM_FRV          0x5441  /* Fujitsu FR-V VLIW */
#define EM_AVR32        0x18ad  /* Atmel AVR32 - Microcontroladores */

/***************************************************************************
 * Estructura del encabezado ELF
 * 
 * Esta estructura representa el inicio de un archivo ELF y contiene
 * información crítica sobre el binario:
 * - Identificación del formato ELF
 * - Tipo de archivo
 * - Arquitectura objetivo
 * - Versión del formato
 ***************************************************************************/
struct elf_hdr {
    uint8_t e_ident[EI_NIDENT];     /* Identificación ELF y datos de formato */
    uint16_t e_type, e_machine;      /* Tipo de archivo y arquitectura */
    uint32_t e_version;              /* Versión del formato ELF */
} __attribute__((packed));           /* Empaquetado sin padding */

/***************************************************************************
 * Prototipos de funciones de utilidad
 ***************************************************************************/

/**
 * Crea y configura un socket para el servidor
 * 
 * @param srv  Estructura del servidor a configurar
 * @return     Descriptor del socket o -1 en caso de error
 */
int util_socket_and_bind(struct server *srv);

/**
 * Busca una secuencia de bytes en un buffer
 * 
 * @param buf      Buffer donde buscar
 * @param buf_len  Longitud del buffer
 * @param mem      Secuencia a buscar
 * @param mem_len  Longitud de la secuencia
 * @return         Posición donde se encontró o -1 si no se encontró
 */
int util_memsearch(char *buf, int buf_len, char *mem, int mem_len);

/**
 * Envía datos formateados a través de un socket
 * 
 * @param fd   Descriptor del socket
 * @param fmt  Formato de los datos (estilo printf)
 * @param ...  Argumentos variables según formato
 * @return     TRUE si se envió correctamente, FALSE si falló
 */
BOOL util_sockprintf(int fd, const char *fmt, ...);

/**
 * Elimina espacios en blanco al inicio y final de una cadena
 * 
 * @param str  Cadena a procesar
 * @return     Puntero a la cadena procesada
 */
char *util_trim(char *str);
