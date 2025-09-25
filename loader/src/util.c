/**************************************************************************
 * Archivo: util.c
 * Descripción: Implementación de funciones de utilidad para el cargador de Mirai.
 * Incluye funciones para manipulación de sockets, búsqueda en memoria,
 * formateo de cadenas y otras utilidades comunes.
 **************************************************************************/

#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "headers/includes.h"
#include "headers/util.h"
#include "headers/server.h"

/**
 * Función que imprime un volcado hexadecimal de memoria
 * @param desc   Descripción del volcado (puede ser NULL)
 * @param addr   Puntero al inicio de la memoria a volcar
 * @param len    Longitud en bytes de la memoria a volcar
 */
void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

/**
 * Crea y vincula un socket TCP a una de las direcciones disponibles del servidor
 * @param srv    Puntero a la estructura del servidor que contiene las direcciones IP
 * @return       Descriptor del socket vinculado o -1 en caso de error
 * 
 * Esta función intenta crear un socket TCP y vincularlo a una de las direcciones IP
 * disponibles en el servidor. Si falla con una dirección, intenta con la siguiente.
 * El socket se configura en modo no bloqueante para mejor rendimiento.
 */
int util_socket_and_bind(struct server *srv)
{
    struct sockaddr_in bind_addr;   // Estructura para la dirección de vinculación
    int i, fd, start_addr;
    BOOL bound = FALSE;             // Bandera que indica si se logró la vinculación

    // Crear un socket TCP
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return -1;

    // Configura la estructura de dirección para la vinculación
    bind_addr.sin_family = AF_INET;     // Familia de direcciones IPv4
    bind_addr.sin_port = 0;             // Puerto 0 permite que el sistema elija un puerto disponible

    // Intenta vincular el socket a una de las direcciones disponibles
    start_addr = rand() % srv->bind_addrs_len;
    for (i = 0; i < srv->bind_addrs_len; i++)
    {
        bind_addr.sin_addr.s_addr = srv->bind_addrs[start_addr];
        if (bind(fd, (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
            if (++start_addr == srv->bind_addrs_len)
                start_addr = 0;
        }
        else
        {
            bound = TRUE;
            break;
        }
    }
    if (!bound)
    {
        close(fd);
#ifdef DEBUG
        printf("Failed to bind on any address\n");
#endif
        return -1;
    }

    // Configura el socket en modo no bloqueante para mejor rendimiento
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1)
    {
#ifdef DEBUG
        printf("Error al configurar el socket en modo no bloqueante. Esto tendrá implicaciones SERIAS en el rendimiento\n");
#endif
    }
    return fd;  // Devuelve el descriptor del socket configurado
}

/**
 * Busca una secuencia de bytes en un buffer de memoria
 * @param buf       Buffer donde buscar
 * @param buf_len   Longitud del buffer
 * @param mem       Secuencia de bytes a buscar
 * @param mem_len   Longitud de la secuencia a buscar
 * @return          Posición donde se encontró la secuencia + 1, o -1 si no se encontró
 * 
 * Esta función implementa un algoritmo de búsqueda simple para encontrar una
 * secuencia de bytes específica dentro de un buffer más grande.
 */
int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;    // matched cuenta cuántos bytes coinciden consecutivamente

    // Si la secuencia a buscar es más grande que el buffer, es imposible encontrarla
    if (mem_len > buf_len)
        return -1;

    // Recorre el buffer byte por byte
    for (i = 0; i < buf_len; i++)
    {
        // Si el byte actual coincide con el siguiente byte esperado de la secuencia
        if (buf[i] == mem[matched])
        {
            // Si hemos encontrado todos los bytes de la secuencia
            if (++matched == mem_len)
                return i + 1;  // Devuelve la posición después de la secuencia
        }
        else
            matched = 0;  // Reinicia la búsqueda si un byte no coincide
    }

    return -1;  // No se encontró la secuencia completa
}

/**
 * Formatea y envía una cadena a través de un socket
 * @param fd    Descriptor del socket
 * @param fmt   Formato de la cadena (estilo printf)
 * @param ...   Argumentos variables para el formato
 * @return      TRUE si se envió correctamente, FALSE si hubo error
 * 
 * Esta función combina la funcionalidad de printf con el envío a través de
 * sockets. Formatea la cadena según los argumentos proporcionados y la
 * envía por el socket especificado.
 */
BOOL util_sockprintf(int fd, const char *fmt, ...)
{
    char buffer[BUFFER_SIZE + 2];  // Buffer temporal para la cadena formateada
    va_list args;                  // Lista de argumentos variables
    int len;                       // Longitud de la cadena formateada

    va_start(args, fmt);
    len = vsnprintf(buffer, BUFFER_SIZE, fmt, args);
    va_end(args);

    if (len > 0)
    {
        if (len > BUFFER_SIZE)
            len = BUFFER_SIZE;

#ifdef DEBUG
        hexDump("TELOUT", buffer, len);
#endif
        if (send(fd, buffer, len, MSG_NOSIGNAL) != len)
            return FALSE;
    }

    return TRUE;
}

/**
 * Elimina espacios en blanco al inicio y final de una cadena
 * @param str   Cadena a recortar
 * @return      Puntero a la cadena recortada
 * 
 * Esta función elimina todos los caracteres de espacio (espacios, tabulaciones,
 * saltos de línea, etc.) tanto al principio como al final de la cadena.
 * Modifica la cadena original y devuelve un puntero al primer carácter no espacio.
 */
char *util_trim(char *str)
{
    char *end;

    // Elimina espacios al inicio
    while(isspace(*str))
        str++;

    // Si la cadena está vacía después de eliminar espacios iniciales
    if(*str == 0)
        return str;

    // Encuentra el último carácter no espacio desde el final
    end = str + strlen(str) - 1;
    while(end > str && isspace(*end))
        end--;

    // Coloca el terminador nulo después del último carácter no espacio
    *(end+1) = 0;

    return str;  // Devuelve el puntero al inicio de la cadena recortada
}
