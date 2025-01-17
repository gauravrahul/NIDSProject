package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
)

type ProtocolData struct {
	TCP, UDP, ICMP, Total int
	sync.RWMutex
}
type ThreatSummary struct {
	Protocol string `json:"protocol"`
	Count    int    `json:"count"`
	Severity string `json:"severity"`
}

var threatSummaryData = map[string]int{
	"TCP":  0,
	"UDP":  0,
	"ICMP": 0,
}

type AttackSignature struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Pattern     string         `json:"pattern"`
	Severity    string         `json:"severity"`
	Protocol    string         `json:"protocol"` // NEW: Specify TCP, UDP, HTTP
	Regex       *regexp.Regexp `json:"-"`        // NEW: Pre-compiled regex
}

var (
	protocolData     = &ProtocolData{}
	signatures       []AttackSignature
	availableDevices []pcap.Interface
	selectedDevice   string
	attackLogs       []gin.H
	logMutex         sync.RWMutex

	// ✅ Correct broadcast channel initialization
	broadcast = make(chan map[string]interface{})

	// ✅ Correct websocket.Upgrader initialization
	upgrader = websocket.Upgrader{
		CheckOrigin:       func(r *http.Request) bool { return true },
		EnableCompression: true,
		ReadBufferSize:    4096, // Increased buffer
		WriteBufferSize:   4096, // Increased buffer
	}

	// ✅ Correct clients map initialization
	clients   = make(map[*websocket.Conn]bool)
	clientsMu sync.Mutex
)

func startBroadcasting() {
	go func() {
		for {
			logMutex.RLock()
			logs := make([]gin.H, len(attackLogs))
			copy(logs, attackLogs)
			logMutex.RUnlock()

			protocolData.RLock()
			summary := []gin.H{
				{"protocol": "TCP", "count": protocolData.TCP},
				{"protocol": "UDP", "count": protocolData.UDP},
				{"protocol": "ICMP", "count": protocolData.ICMP},
				{"protocol": "Total", "count": protocolData.Total},
			}
			protocolData.RUnlock()

			broadcast <- gin.H{
				"logs":    logs,
				"summary": summary,
			}

			time.Sleep(5 * time.Second) // Broadcast every 5 seconds
		}
	}()
}

func analyzePackets(packetChan <-chan gopacket.Packet) {
	for packet := range packetChan {
		analyzePacket(packet) // ✅ Delegates to analyzePacket
	}
}

func main() {
	log.Println("[INFO] Starting NIDS...")

	// Load network devices
	if err := loadNetworkDevices(); err != nil {
		log.Fatalf("[ERROR] %v", err)
	}

	// Select active network device
	selectedDevice = selectActiveNetworkDevice()
	log.Printf("[INFO] Selected device: %s", selectedDevice)

	// Load attack signatures
	if err := loadSignatures("signatures.json"); err != nil {
		log.Fatalf("[ERROR] Error loading signatures: %v", err)
	}

	// Open network device for packet capture
	handle, err := pcap.OpenLive(selectedDevice, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("[ERROR] Error initializing packet capture: %v", err)
	}
	defer handle.Close()

	// Apply BPF filter for TCP/UDP/ICMP traffic
	if err := handle.SetBPFFilter("tcp or udp or icmp"); err != nil {
		log.Fatalf("[ERROR] Error setting BPF filter: %v", err)
	}
	log.Println("[INFO] BPF filter applied: tcp or udp or icmp")

	// Packet processing setup
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := make(chan gopacket.Packet, runtime.NumCPU()*10)

	for i := 0; i < runtime.NumCPU(); i++ {
		go analyzePackets(packetChan) // ✅ CALL analyzePackets here
	}

	go func() {
		for packet := range packetSource.Packets() {
			protocolData.Lock()
			protocolData.Total++
			protocolData.Unlock()
			packetChan <- packet
		}
	}()

	// ✅ Start broadcasting logs and summaries every 5 seconds
	go startBroadcasting()

	// ✅ Periodically broadcast the threat summary every 10 seconds
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			broadcastThreatSummary()
		}
	}()

	// Setup HTTP server
	router := setupRouter()

	// Graceful shutdown on interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("[INFO] Shutting down server...")
		os.Exit(0)
	}()

	log.Println("[INFO] Server running on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("[ERROR] Error starting server: %v", err)
	}
}

func loadNetworkDevices() error {
	var err error
	availableDevices, err = pcap.FindAllDevs()
	if err != nil {
		return errors.New("failed to fetch network devices")
	}
	if len(availableDevices) == 0 {
		return errors.New("no network devices found")
	}
	log.Printf("[INFO] Found %d devices", len(availableDevices))
	return nil
}

func selectActiveNetworkDevice() string {
	for _, device := range availableDevices {
		if len(device.Addresses) > 0 && containsAny(device.Description, []string{"Wi-Fi", "Wireless", "Ethernet"}) {
			return device.Name
		}
	}
	for _, device := range availableDevices {
		if strings.Contains(strings.ToLower(device.Description), "loopback") {
			return device.Name
		}
	}
	log.Println("[WARN] No suitable network device found. Defaulting to the first available device.")
	return availableDevices[0].Name
}

func containsAny(description string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(description), strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func loadSignatures(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open signatures file: %v", err)
	}
	defer file.Close()

	var rawSignatures []AttackSignature
	if err := json.NewDecoder(file).Decode(&rawSignatures); err != nil {
		return fmt.Errorf("failed to parse signatures: %v", err)
	}

	for _, sig := range rawSignatures {
		regex, err := regexp.Compile(sig.Pattern)
		if err != nil {
			log.Printf("[ERROR] Invalid regex in signature %s: %v", sig.ID, err)
			continue
		}
		sig.Regex = regex
		signatures = append(signatures, sig)
	}

	log.Printf("[INFO] Loaded %d attack signatures", len(signatures))
	return nil
}

func setupRouter() *gin.Engine {
	router := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("session", store))

	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")

	// Middleware for session validation
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("user") == nil && !(c.Request.URL.Path == "/login" || c.Request.URL.Path == "/ws") {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	})

	// Redirect root to login page
	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/login")
	})

	// Login page handler
	router.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("user") != nil {
			c.Redirect(http.StatusFound, "/dashboard")
			return
		}
		c.HTML(http.StatusOK, "login.html", nil)
	})

	// Login form submission handler
	router.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		if username == "admin" && password == "password" {
			session := sessions.Default(c)
			session.Set("user", username)
			session.Save()
			c.JSON(http.StatusOK, gin.H{"redirect": "/dashboard"})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		}
	})

	// Logout handler with redirect
	router.POST("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear()
		if err := session.Save(); err != nil {
			log.Printf("[ERROR] Failed to clear session: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to log out"})
			return
		}
		c.Redirect(http.StatusFound, "/login")
	})

	// Dashboard route
	router.GET("/dashboard", func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", nil)
	})

	// API for attack logs
	router.GET("/api/attack-logs", func(c *gin.Context) {
		logMutex.RLock()
		defer logMutex.RUnlock()
		c.JSON(http.StatusOK, attackLogs)
	})

	// API for threat summary
	router.GET("/api/threat-summary", func(c *gin.Context) {
		protocolData.RLock()
		defer protocolData.RUnlock()

		totalCount := protocolData.TCP + protocolData.UDP + protocolData.ICMP
		totalSeverity := calculateSeverity(protocolData.TCP, protocolData.UDP, protocolData.ICMP)

		summary := []gin.H{
			{"protocol": "TCP", "count": protocolData.TCP, "severity": "Low"},
			{"protocol": "UDP", "count": protocolData.UDP, "severity": "Medium"},
			{"protocol": "ICMP", "count": protocolData.ICMP, "severity": "High"},
			{"protocol": "Total", "count": totalCount, "severity": totalSeverity},
		}

		c.JSON(http.StatusOK, summary)
	})

	// WebSocket endpoint
	router.GET("/ws", handleWebSocket)

	return router
}

func handleWebSocket(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[ERROR] WebSocket upgrade failed: %v", err)
		return
	}

	clientsMu.Lock()
	clients[conn] = true // ✅ Add client to active clients
	clientsMu.Unlock()

	defer func() {
		clientsMu.Lock()
		delete(clients, conn) // ✅ Remove on disconnect
		clientsMu.Unlock()
		conn.Close()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func analyzePacket(packet gopacket.Packet) {
	logPacketDetails(packet) // Log packet details for auditing
	classifyProtocol(packet) // Classify protocol type
	detectPatterns(packet)   // Detect attack patterns

	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	// Detect the protocol and use it
	protocol := detectProtocol(transportLayer)

	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}

	payload := string(appLayer.Payload())

	// Use protocol in matching
	for _, sig := range signatures {
		if sig.Protocol != "" && sig.Protocol != protocol {
			continue
		}
		if sig.Regex.MatchString(payload) {
			logThreat(packet, sig.Description, sig.Severity)
			return
		}
	}
}

// Detect packet protocol safely
func detectProtocol(transportLayer gopacket.Layer) string {
	if transportLayer == nil {
		return "UNKNOWN"
	}

	switch transportLayer.LayerType() {
	case layers.LayerTypeTCP:
		return "TCP"
	case layers.LayerTypeUDP:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

// 📝 Log packet details for debugging
func logPacketDetails(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()

	// Handle ARP packets gracefully
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		log.Printf("[DEBUG] ARP Packet: SrcMAC=%v, DstMAC=%v, SrcIP=%v, DstIP=%v",
			net.HardwareAddr(arp.SourceHwAddress),
			net.HardwareAddr(arp.DstHwAddress),
			net.IP(arp.SourceProtAddress),
			net.IP(arp.DstProtAddress),
		)
		return
	}

	if networkLayer == nil {
		log.Println("[WARN] No NetworkLayer found in the packet.")
		return
	}

	transportLayer := packet.TransportLayer()
	protocol := detectProtocol(transportLayer)
	packetSize := len(packet.Data())

	logMutex.Lock()
	attackLogs = append(attackLogs, gin.H{
		"timestamp":      time.Now().Format(time.RFC3339),
		"source_ip":      networkLayer.NetworkFlow().Src().String(),
		"destination_ip": networkLayer.NetworkFlow().Dst().String(),
		"protocol":       protocol,
		"packet_size":    packetSize,
		"attack_type":    "Normal Traffic", // Default for non-malicious packets
	})
	logMutex.Unlock()
}

// 📊 Classify protocol types for statistics
func classifyProtocol(packet gopacket.Packet) {
	transportLayer := packet.TransportLayer()

	protocolData.Lock()
	defer protocolData.Unlock()

	if transportLayer != nil {
		switch transportLayer.LayerType() {
		case layers.LayerTypeTCP:
			protocolData.TCP++
			threatSummaryData["TCP"]++
		case layers.LayerTypeUDP:
			protocolData.UDP++
			threatSummaryData["UDP"]++
		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			protocolData.ICMP++
			threatSummaryData["ICMP"]++
		}
	}
}

// Detect specific attack patterns in packets
func detectPatterns(packet gopacket.Packet) {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}

	payload := string(appLayer.Payload())

	for _, sig := range signatures {
		if matchSignature(payload) { // ✅ Uses matchSignature
			logThreat(packet, sig.Description, sig.Severity) // ✅ Logs the detected threat
			return
		}
	}
}

// ✅ Match payload with attack signatures
func matchSignature(payload string) bool {
	for _, sig := range signatures {
		if sig.Regex.MatchString(payload) {
			return true
		}
	}
	return false
}

// 🚨 Enhanced Logging with Protocol and Packet Size
func logThreat(packet gopacket.Packet, description, severity string) {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()
	srcIP, dstIP, protocol, packetSize := "N/A", "N/A", "UNKNOWN", 0

	if networkLayer != nil {
		srcIP = networkLayer.NetworkFlow().Src().String()
		dstIP = networkLayer.NetworkFlow().Dst().String()
	}

	if transportLayer != nil {
		protocol = detectProtocol(transportLayer)
		packetSize = len(packet.Data())
	}

	// ✅ Updated to 12-hour format with AM/PM
	logEntry := gin.H{
		"timestamp":      time.Now().Format("15:04:05"),
		"description":    description,
		"severity":       severity,
		"source_ip":      srcIP,
		"destination_ip": dstIP,
		"protocol":       protocol,
		"packet_size":    packetSize,
	}

	logMutex.Lock()
	attackLogs = append(attackLogs, logEntry)
	logMutex.Unlock()

	// Send log to WebSocket clients
	broadcastLog(logEntry)

	log.Printf("[ALERT] %s detected from %s to %s | Protocol: %s | Severity: %s",
		description, srcIP, dstIP, protocol, severity)
}

func broadcastLog(logEntry gin.H) {
	clientsMu.Lock()
	defer clientsMu.Unlock()

	for client := range clients {
		if err := client.WriteJSON(logEntry); err != nil {
			log.Printf("[ERROR] WebSocket write failed: %v", err)
			client.Close()
			delete(clients, client)
		}
	}
}

func broadcastThreatSummary() {
	protocolData.RLock()
	defer protocolData.RUnlock()

	totalCount := protocolData.TCP + protocolData.UDP + protocolData.ICMP

	// Calculate the average severity dynamically for the "Total" row
	totalSeverity := calculateSeverity(protocolData.TCP, protocolData.UDP, protocolData.ICMP)

	summary := []gin.H{
		{"protocol": "TCP", "count": protocolData.TCP, "severity": calculateSeverity(protocolData.TCP, 0, 0)},
		{"protocol": "UDP", "count": protocolData.UDP, "severity": calculateSeverity(0, protocolData.UDP, 0)},
		{"protocol": "ICMP", "count": protocolData.ICMP, "severity": calculateSeverity(0, 0, protocolData.ICMP)},
		{"protocol": "Total", "count": totalCount, "severity": totalSeverity},
	}

	// Broadcast the updated threat summary to all WebSocket clients
	clientsMu.Lock()
	defer clientsMu.Unlock()

	for client := range clients {
		if err := client.WriteJSON(gin.H{"summary": summary}); err != nil {
			log.Printf("[ERROR] Failed to send threat summary: %v", err)
			client.Close()
			delete(clients, client)
		}
	}
}

// ✅ Balanced Severity Calculation Based on Distribution and Severity Impact
func calculateSeverity(tcpCount, udpCount, icmpCount int) string {
	totalCount := tcpCount + udpCount + icmpCount

	if totalCount == 0 {
		return "N/A"
	}

	// Assign numerical severity values: High=3, Medium=2, Low=1
	severityScore := 0

	if tcpCount > 0 {
		severityScore += 1 * tcpCount
	}
	if udpCount > 0 {
		severityScore += 2 * udpCount
	}
	if icmpCount > 0 {
		severityScore += 3 * icmpCount
	}

	average := float64(severityScore) / float64(totalCount)

	switch {
	case average >= 2.5:
		return "High"
	case average >= 1.5:
		return "Medium"
	default:
		return "Low"
	}
}
