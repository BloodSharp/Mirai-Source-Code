/**************************************************************************
 * Archivo: nogdb.c
 * 
 * Descripción: Herramienta para corromper encabezados ELF y prevenir
 * el análisis con GDB. Esta utilidad modifica secciones críticas del
 * encabezado ELF para dificultar la depuración del binario.
 * 
 * Funcionamiento:
 * - Modifica la tabla de secciones del archivo ELF
 * - Invalida índices de sección críticos
 * - Preserva la funcionalidad del binario
 * - Dificulta el análisis estático y dinámico
 **************************************************************************/

/***************************************************************************
 * Inclusión de cabeceras
 ***************************************************************************/
#include <stdio.h>      /* Entrada/salida estándar */
#include <sys/mman.h>   /* Mapeo de memoria */
#include <unistd.h>     /* Funciones POSIX */
#include <stdlib.h>     /* Funciones de utilidad */
#include <elf.h>        /* Manejo de formato ELF */
#include <sys/stat.h>   /* Estado de archivos */
#include <sys/types.h>  /* Tipos de sistema */
#include <sys/procfs.h> /* Información de procesos */
#include <fcntl.h>      /* Control de archivos */

/**
 * Función principal del programa
 * 
 * Modifica el encabezado ELF de un binario para prevenir
 * su análisis con GDB. La modificación se centra en:
 * - Offset de la tabla de secciones
 * - Número de secciones
 * - Índice de la tabla de strings
 * 
 * @param argc  Número de argumentos
 * @param argv  Array de argumentos
 * @return      0 si exitoso, 1 si hay error
 */
int main(int argc, char** argv) {
    /* Variables para manejo del archivo y encabezado ELF */
    int f;                      /* Descriptor de archivo */
    static Elf32_Ehdr* header; /* Puntero al encabezado ELF */

    printf(".: Corruptor de ELF :.\n");

    /* Verificar que se proporcione un archivo como argumento */
    if(argc < 2){
        printf("Uso: %s archivo\n", argv[0]);
        return 1;
    }

    /* Abrir archivo en modo lectura/escritura */
    if((f = open(argv[1], O_RDWR)) < 0){
        perror("Error al abrir archivo");
        return 1;
    }

    /* 
     * Mapear el encabezado ELF en memoria
     * MAP_SHARED es necesario para que los cambios se escriban en el archivo
     */
    if((header = (Elf32_Ehdr *) mmap(NULL,              /* Sin dirección específica */
                                    sizeof(header),      /* Tamaño del mapeo */
                                    PROT_READ | PROT_WRITE, /* Permisos */
                                    MAP_SHARED,         /* Cambios persistentes */
                                    f,                  /* Descriptor */
                                    0)) == MAP_FAILED){ /* Offset */
        perror("Error en mmap");
        close(f);
        return 1;
    }

    /* Mostrar valores actuales del encabezado */
    printf("[*] Valores actuales del encabezado:\n");
    printf("\te_shoff:%d\n\te_shnum:%d\n\te_shstrndx:%d\n",
            header->e_shoff, header->e_shnum, header->e_shstrndx);

    /* 
     * Corromper valores críticos del encabezado:
     * - e_shoff: Offset de la tabla de secciones
     * - e_shnum: Número de entradas en la tabla
     * - e_shstrndx: Índice de la tabla de strings
     */
    header->e_shoff = 0xffff;     /* Invalida offset */
    header->e_shnum = 0xffff;     /* Invalida conteo */
    header->e_shstrndx = 0xffff;  /* Invalida índice */

    /* Mostrar valores modificados */
    printf("[*] Valores modificados del encabezado:\n");
    printf("\te_shoff:%d\n\te_shnum:%d\n\te_shstrndx:%d\n",
            header->e_shoff, header->e_shnum, header->e_shstrndx);

    /* Sincronizar cambios con el archivo en disco */
    if(msync(NULL, 0, MS_SYNC) == -1){
        perror("Error en msync");
        close(f);
        return 1;
    }

    /* Limpiar recursos */
    close(f);                    /* Cerrar archivo */
    munmap(header, 0);          /* Liberar mapeo */
    
    printf("El archivo \"%s\" ya no debería poder ejecutarse en GDB\n", argv[1]);
    return 0; /* Éxito */
}