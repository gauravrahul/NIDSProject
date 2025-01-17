document.addEventListener("DOMContentLoaded", function () {
    const loginForm = document.getElementById("loginForm");

    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();  // ✅ Prevents form from submitting and refreshing the page

            const username = document.getElementById("username").value.trim();
            const password = document.getElementById("password").value.trim();

            if (!username || !password) {
                showError("Username and password are required.");
                return;
            }

            try {
                const response = await fetch("/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    body: new URLSearchParams({ username, password }),
                });

                const result = await response.json();

                if (response.ok && result.redirect) {
                    window.location.href = result.redirect;
                } else {
                    showError(result.error || "Invalid username or password.");
                }
            } catch (error) {
                console.error("[ERROR] Login failed:", error);
                showError("An error occurred. Please try again.");
            }
        });

        function showError(message) {
            const errorDiv = document.getElementById("error");
            errorDiv.textContent = message;
            errorDiv.classList.remove("hidden");
        }
    }
});
// ✅ Global WebSocket variable
let ws;

function setupWebSocket() {
    // ⚠️ Prevent multiple WebSocket instances
    if (ws && ws.readyState === WebSocket.OPEN) {
        console.warn('[WARN] WebSocket is already connected.');
        return;
    }

    ws = new WebSocket('ws://localhost:8080/ws');

    ws.onopen = () => {
        console.log('[INFO] WebSocket connected.');

        // ✅ Start keep-alive pings
        keepWebSocketAlive();
    };

    ws.onclose = () => {
        console.warn("[WARN] WebSocket closed. Reconnecting in 5 seconds...");
        setTimeout(connectWebSocket, 5000);
    };
    

    ws.onerror = (error) => {
        console.error('[ERROR] WebSocket error:', error);
        // ⚠️ Only close if it's not already closing/closed
        if (ws.readyState !== WebSocket.CLOSING && ws.readyState !== WebSocket.CLOSED) {
            ws.close();
        }
    };

    ws.onmessage = (event) => {
        console.log('[INFO] WebSocket Data:', event.data);

        try {
            const data = JSON.parse(event.data);

            if (data.timestamp && data.source_ip) {
                appendNewAlert(data);
            }

            if (data.summary) {
                updateThreatSummary(data.summary);
            }
        } catch (error) {
            console.error('[ERROR] Failed to process WebSocket data:', error);
        }
    };
}

// ✅ Keep WebSocket Alive with Pings
function keepWebSocketAlive() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "ping" }));
        setTimeout(keepWebSocketAlive, 30000);  // Ping every 30 seconds
    }
}

// ✅ Initialize WebSocket Connection
setupWebSocket();

document.getElementById("search-bar").addEventListener("input", function () {
    const filter = this.value.toLowerCase();
    const rows = document.querySelectorAll("#attackLogs tr");
    rows.forEach(row => {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(filter) ? "" : "none";
    });
});

// ✅ Update the attack logs table with all logs
function updateAttackLogs(logs) {
    const logsBody = document.getElementById('attackLogs');
    logsBody.innerHTML = '';  // Clear existing logs

    logs.forEach(log => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${log.timestamp || 'N/A'}</td>
            <td>${log.source_ip || 'N/A'}</td>
            <td>${log.destination_ip || 'N/A'}</td>
            <td>${log.protocol || 'N/A'}</td>
            <td>${log.description || 'N/A'}</td>
            <td class="${getSeverityClass(log.severity)}">${log.severity || 'N/A'}</td>
        `;
        logsBody.appendChild(row);
    });
}

// ✅ Append new attack log with severity to the table
function appendNewAlert(data) {
    const logsBody = document.getElementById('attackLogs');
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${data.timestamp || 'N/A'}</td>
        <td>${data.source_ip || 'N/A'}</td>
        <td>${data.destination_ip || 'N/A'}</td>
        <td>${data.protocol || 'N/A'}</td>
        <td>${data.description || 'N/A'}</td>
        <td class="${getSeverityClass(data.severity)}">${data.severity || 'N/A'}</td>  <!-- ✅ Severity Included -->
    `;
    logsBody.prepend(row);
}

// ✅ Severity Styling
function getSeverityClass(severity) {
    switch (severity) {
        case "High": return "text-red-500 font-bold";
        case "Medium": return "text-yellow-500 font-bold";
        case "Low": return "text-green-500 font-bold";
        default: return "text-gray-500";
    }
}

// ✅ Update the Threat Summary Table
function updateThreatSummary(summary) {
    const summaryTable = document.getElementById('threatSummary');
    summaryTable.innerHTML = '';  // Clear previous data

    summary.forEach(item => {
        const row = `<tr>
                        <td>${item.protocol || "N/A"}</td>
                        <td>${item.count || 0}</td>
                        <td class="${getSeverityClass(item.severity)}">${item.severity || "N/A"}</td>
                    </tr>`;
        summaryTable.innerHTML += row;
    });
}


// ✅ Severity Styling
function getSeverityClass(severity) {
    switch (severity) {
        case "High": return "text-red-500 font-bold";
        case "Medium": return "text-yellow-500 font-bold";
        case "Low": return "text-green-500 font-bold";
        default: return "text-gray-500";
    }
}

// ✅ Reset Filters for the logs
document.getElementById('reset-filters')?.addEventListener('click', () => {
    document.getElementById('search-input').value = '';
    document.getElementById('protocol-filter').value = '';
    document.getElementById('severity-filter').value = '';
    console.log('[INFO] Filters have been reset.');
});

// ✅ Handle Login Form Submission
document.getElementById('loginForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();

    if (!username || !password) {
        alert('Username and password are required.');
        return;
    }

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ username, password }),
        });

        const result = await response.json();
        if (response.ok) {
            console.log('[INFO] Login successful. Redirecting to dashboard...');
            window.location.href = result.redirect;
        } else {
            alert(result.error || 'Invalid credentials. Please try again.');
        }
    } catch (error) {
        console.error('[ERROR] Login failed:', error);
        alert('An error occurred during login. Please try again.');
    }
});

// ✅ Handle Logout Button Click
document.getElementById('logout-btn')?.addEventListener('click', async () => {
    try {
        const response = await fetch('/logout', { method: 'POST' });
        if (response.ok) {
            console.log('[INFO] Logged out successfully. Redirecting to login...');
            window.location.href = '/login';
        } else {
            alert('Failed to log out. Please try again.');
        }
    } catch (error) {
        console.error('[ERROR] Logout failed:', error);
        alert('An error occurred during logout. Please try again.');
    }
});

// Enhanced Search Functionality for Attack Logs
document.getElementById("search-bar").addEventListener("input", function () {
    const filter = this.value.toLowerCase().trim();
    const rows = document.querySelectorAll("#attackLogs tr");

    rows.forEach(row => {
        // Select the relevant columns: Source IP, Destination IP, Protocol Type, Attack Type
        const sourceIP = row.cells[1]?.textContent.toLowerCase();  // Source IP
        const destIP = row.cells[2]?.textContent.toLowerCase();    // Destination IP
        const protocol = row.cells[3]?.textContent.toLowerCase();  // Protocol Type
        const attackType = row.cells[4]?.textContent.toLowerCase(); // Attack Type

        // Check if the filter matches any of these columns
        if (
            (sourceIP && sourceIP.includes(filter)) ||
            (destIP && destIP.includes(filter)) ||
            (protocol && protocol.includes(filter)) ||
            (attackType && attackType.includes(filter))
        ) {
            row.style.display = "";  // Show the row if a match is found
        } else {
            row.style.display = "none";  // Hide the row if no match is found
        }
    });
});
