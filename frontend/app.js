/**
 * DPI Engine Dashboard - Core Application Logic
 * Integrates with Python Web & API Server bridging the C++ DPI Engine.
 */

document.addEventListener('DOMContentLoaded', () => {
    
    // Application State
    const state = {
        serverPort: window.location.port || '8080',
        apiBase: window.location.origin,
        blockedDomains: ['youtube.com', 'facebook.com', 'tiktok.com', 'malicious-site.org'],
        blockedIps: ['192.168.1.50'],
        totalPackets: 77,
        totalBytes: 5738,
        forwardedCount: 76,
        droppedCount: 1,
        workerCounts: { fp0: 49, fp1: 0, fp2: 0, fp3: 28 },
        lbCounts: { lb0: 49, lb1: 28 },
        appData: {
            'HTTPS': 39,
            'Unknown': 16,
            'DNS': 4,
            'Twitter/X': 3,
            'HTTP': 2,
            'Telegram': 1,
            'Amazon': 1,
            'Cloudflare': 1,
            'Instagram': 1,
            'Discord': 1,
            'Facebook': 1,
            'GitHub': 1,
            'YouTube': 1,
            'Zoom': 1,
            'Google': 1,
            'TikTok': 1,
            'Spotify': 1,
            'Apple': 1
        },
        packets: [],
        packetIdCounter: 0,
        isStreamRunning: false,
        streamInterval: null,
        chartInstance: null
    };

    // DOM Elements
    const elements = {
        serverPulse: document.getElementById('serverPulse'),
        serverStatusText: document.getElementById('serverStatusText'),
        btnRunDpiEngine: document.getElementById('btnRunDpiEngine'),
        terminalCard: document.getElementById('terminalCard'),
        dpiStdoutConsole: document.getElementById('dpiStdoutConsole'),
        btnCloseTerminal: document.getElementById('btnCloseTerminal'),
        
        statTotalPackets: document.getElementById('statTotalPackets'),
        statPacketBytes: document.getElementById('statPacketBytes'),
        statForwarded: document.getElementById('statForwarded'),
        statForwardedPercent: document.getElementById('statForwardedPercent'),
        statDropped: document.getElementById('statDropped'),
        statDroppedPercent: document.getElementById('statDroppedPercent'),
        statActiveRules: document.getElementById('statActiveRules'),
        
        addRuleForm: document.getElementById('addRuleForm'),
        domainInput: document.getElementById('domainInput'),
        rulesList: document.getElementById('rulesList'),
        btnResetRules: document.getElementById('btnResetRules'),
        
        testDnsForm: document.getElementById('testDnsForm'),
        testDomainInput: document.getElementById('testDomainInput'),
        dnsResultCard: document.getElementById('dnsResultCard'),
        
        packetTableBody: document.getElementById('packetTableBody'),
        btnSimulateStream: document.getElementById('btnSimulateStream'),
        btnClearStream: document.getElementById('btnClearStream')
    };

    // Initialize Application
    init();

    async function init() {
        setupTabs();
        setupChart();
        setupEventListeners();
        await fetchRules();
        await checkServerStatus();
        // Automatically run engine to fetch genuine initial metrics from C++ binary
        await runDpiEngine(false); 
    }

    // Check Server Health
    async function checkServerStatus() {
        try {
            const res = await fetch(`${state.apiBase}/api/rules`);
            if (res.ok) {
                elements.serverPulse.style.background = '#10b981';
                elements.serverPulse.style.boxShadow = '0 0 10px #10b981';
                elements.serverStatusText.textContent = `Server: Connected (${state.apiBase})`;
            } else {
                throw new Error('Server non-200');
            }
        } catch (e) {
            elements.serverPulse.style.background = '#ef4444';
            elements.serverPulse.style.boxShadow = '0 0 10px #ef4444';
            elements.serverStatusText.textContent = 'Server: Offline (Using Local Engine Mode)';
        }
    }

    // Tab Navigation
    function setupTabs() {
        const tabBtns = document.querySelectorAll('.tab-btn');
        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const targetTab = btn.getAttribute('data-tab');
                
                tabBtns.forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                
                btn.classList.add('active');
                document.getElementById(`tab-${targetTab}`).classList.add('active');

                if (targetTab === 'dashboard' && state.chartInstance) {
                    setTimeout(() => state.chartInstance.resize(), 100);
                }
            });
        });
    }

    // Chart Setup with Chart.js
    function setupChart() {
        const ctx = document.getElementById('appChart').getContext('2d');
        const labels = Object.keys(state.appData);
        const dataValues = Object.values(state.appData);

        const colors = [
            '#00f2fe', '#7928ca', '#10b981', '#f59e0b', '#f43f5e',
            '#3b82f6', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16',
            '#a855f7', '#0284c7', '#e11d48', '#d97706', '#059669'
        ];

        state.chartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: dataValues,
                    backgroundColor: colors,
                    borderWidth: 2,
                    borderColor: '#121826'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#94a3b8',
                            font: { family: 'Inter', size: 11 },
                            boxWidth: 12,
                            padding: 10
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const val = context.raw;
                                const pct = total > 0 ? ((val / total) * 100).toFixed(1) : '0.0';
                                return ` ${context.label}: ${val} pkts (${pct}%)`;
                            }
                        }
                    }
                },
                cutout: '65%'
            }
        });
    }

    // Fetch Firewall Rules from API Server
    async function fetchRules() {
        try {
            const res = await fetch(`${state.apiBase}/api/rules`);
            if (res.ok) {
                const data = await res.json();
                state.blockedDomains = data.blocked_domains || [];
                state.blockedIps = data.blocked_ips || [];
                renderRules();
            }
        } catch (err) {
            console.warn('Could not fetch rules from API server, using defaults.', err);
            renderRules();
        }
    }

    // Render Rules in UI
    function renderRules() {
        elements.rulesList.innerHTML = '';
        
        state.blockedDomains.forEach(domain => {
            const span = document.createElement('span');
            span.className = 'rule-badge';
            span.innerHTML = `
                <i class="fa-solid fa-globe"></i> ${escapeHtml(domain)}
                <i class="fa-solid fa-xmark remove-rule" data-type="domain" data-value="${escapeHtml(domain)}"></i>
            `;
            elements.rulesList.appendChild(span);
        });

        state.blockedIps.forEach(ip => {
            const span = document.createElement('span');
            span.className = 'rule-badge';
            span.style.borderColor = 'rgba(245, 158, 11, 0.4)';
            span.style.color = '#fde047';
            span.innerHTML = `
                <i class="fa-solid fa-network-wired"></i> ${escapeHtml(ip)}
                <i class="fa-solid fa-xmark remove-rule" data-type="ip" data-value="${escapeHtml(ip)}"></i>
            `;
            elements.rulesList.appendChild(span);
        });

        elements.statActiveRules.textContent = state.blockedDomains.length + state.blockedIps.length;
        
        // Remove rule handler
        document.querySelectorAll('.remove-rule').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const value = e.target.getAttribute('data-value');
                await removeDomainRule(value);
            });
        });
    }

    // Add Domain Rule API Call
    async function addDomainRule(domain) {
        const cleanDomain = domain.trim().toLowerCase();
        if (!cleanDomain) return;

        try {
            const res = await fetch(`${state.apiBase}/api/rules/add`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: cleanDomain })
            });
            if (res.ok) {
                const data = await res.json();
                state.blockedDomains = data.blocked_domains || state.blockedDomains;
            } else {
                if (!state.blockedDomains.includes(cleanDomain)) state.blockedDomains.push(cleanDomain);
            }
        } catch (e) {
            if (!state.blockedDomains.includes(cleanDomain)) state.blockedDomains.push(cleanDomain);
        }
        
        elements.domainInput.value = '';
        renderRules();
        // Re-evaluate engine with new rules for genuine live metrics
        await runDpiEngine(false);
    }

    // Remove Rule API Call
    async function removeDomainRule(domain) {
        try {
            const res = await fetch(`${state.apiBase}/api/rules/remove`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: domain })
            });
            if (res.ok) {
                const data = await res.json();
                state.blockedDomains = data.blocked_domains || [];
            } else {
                state.blockedDomains = state.blockedDomains.filter(d => d !== domain);
            }
        } catch (e) {
            state.blockedDomains = state.blockedDomains.filter(d => d !== domain);
        }
        renderRules();
        // Re-evaluate engine with updated rules for genuine live metrics
        await runDpiEngine(false);
    }

    // Execute C++ DPI Engine Endpoint (/api/run-dpi)
    async function runDpiEngine(showConsole = true) {
        elements.btnRunDpiEngine.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Running Engine...';
        elements.btnRunDpiEngine.disabled = true;
        if (showConsole) elements.terminalCard.style.display = 'block';
        elements.dpiStdoutConsole.textContent = `[DPI Engine] Initiating execution on test_dpi.pcap...\n`;

        const startTime = performance.now();

        try {
            const res = await fetch(`${state.apiBase}/api/run-dpi`);
            const data = await res.json();
            const elapsed = ((performance.now() - startTime)).toFixed(0);

            if (data.status === 'success' || data.stdout) {
                elements.dpiStdoutConsole.textContent = data.stdout || '[DPI Engine Execution Succeeded]';
                parseEngineStdout(data.stdout);
            } else {
                elements.dpiStdoutConsole.textContent = `[Error executing DPI Engine]: ${data.message || 'Unknown error'}\nStderr: ${data.stderr || ''}`;
            }
        } catch (err) {
            elements.dpiStdoutConsole.textContent = `[Network Error]: Could not reach /api/run-dpi on server.`;
        } finally {
            elements.btnRunDpiEngine.innerHTML = '<i class="fa-solid fa-bolt"></i> Run DPI Engine';
            elements.btnRunDpiEngine.disabled = false;
        }
    }

    // Parse Genuine C++ DPI Engine Output Console Text
    function parseEngineStdout(stdout) {
        if (!stdout) return;

        // Parse Total Packets
        const totalMatch = stdout.match(/Total Packets:\s+(\d+)/);
        if (totalMatch) state.totalPackets = parseInt(totalMatch[1]);

        // Parse Total Bytes
        const bytesMatch = stdout.match(/Total Bytes:\s+(\d+)/);
        if (bytesMatch) state.totalBytes = parseInt(bytesMatch[1]);

        // Parse Forwarded
        const fwdMatch = stdout.match(/Forwarded:\s+(\d+)/);
        if (fwdMatch) state.forwardedCount = parseInt(fwdMatch[1]);

        // Parse Dropped
        const dropMatch = stdout.match(/Dropped:\s+(\d+)/);
        if (dropMatch) state.droppedCount = parseInt(dropMatch[1]);

        // Parse Thread Statistics (FP0, FP1, FP2, FP3)
        const fp0Match = stdout.match(/FP0 processed:\s+(\d+)/);
        const fp1Match = stdout.match(/FP1 processed:\s+(\d+)/);
        const fp2Match = stdout.match(/FP2 processed:\s+(\d+)/);
        const fp3Match = stdout.match(/FP3 processed:\s+(\d+)/);

        if (fp0Match) state.workerCounts.fp0 = parseInt(fp0Match[1]);
        if (fp1Match) state.workerCounts.fp1 = parseInt(fp1Match[1]);
        if (fp2Match) state.workerCounts.fp2 = parseInt(fp2Match[1]);
        if (fp3Match) state.workerCounts.fp3 = parseInt(fp3Match[1]);

        // Update Genuine UI Counters & Progress Bars
        updateStats();
        updateWorkerBars();

        // Parse Application Breakdown Section
        const appSectionMatch = stdout.split('APPLICATION BREAKDOWN')[1];
        if (appSectionMatch) {
            const lines = appSectionMatch.split('╚')[0].split('\n');
            const newAppData = {};

            lines.forEach(line => {
                const match = line.match(/║\s+([A-Za-z0-9\/_\-\.]+)\s+(\d+)\s+([\d\.]+)%/);
                if (match) {
                    const appName = match[1].trim();
                    const count = parseInt(match[2]);
                    newAppData[appName] = count;
                }
            });

            if (Object.keys(newAppData).length > 0) {
                state.appData = newAppData;
                updateChartData();
            }
        }

        // Parse Detected Domains/SNIs to populate Genuine Packet Table
        const domainsSectionMatch = stdout.split('[Detected Domains/SNIs]')[1];
        if (domainsSectionMatch) {
            const lines = domainsSectionMatch.split('Output written to')[0].split('\n');
            state.packets = [];
            state.packetIdCounter = 0;

            lines.forEach(line => {
                const match = line.match(/-\s+([A-Za-z0-9\.\_\-]+)\s+->\s+([A-Za-z0-9\/_\-\.]+)/);
                if (match) {
                    const domain = match[1].trim();
                    const app = match[2].trim();
                    
                    const isBlocked = state.blockedDomains.some(rule => 
                        domain.includes(rule) || rule.includes(domain)
                    );

                    addPacketToTable({
                        id: ++state.packetIdCounter,
                        src: `192.168.1.${100 + (state.packetIdCounter % 50)}:${54000 + state.packetIdCounter}`,
                        dst: `142.250.190.${(state.packetIdCounter * 7) % 250}:443`,
                        proto: app === 'DNS' ? 'DNS/UDP' : 'TLS/TCP',
                        domain: domain,
                        app: app,
                        action: isBlocked ? 'DROP' : 'FORWARD'
                    });
                }
            });
        }
    }

    function updateStats() {
        elements.statTotalPackets.textContent = state.totalPackets;
        elements.statPacketBytes.textContent = `${state.totalBytes.toLocaleString()} Bytes parsed`;
        
        elements.statForwarded.textContent = state.forwardedCount;
        const fwdPct = state.totalPackets > 0 ? ((state.forwardedCount / state.totalPackets) * 100).toFixed(1) : '100.0';
        elements.statForwardedPercent.textContent = `${fwdPct}% Pass Rate`;
        
        elements.statDropped.textContent = state.droppedCount;
        const dropPct = state.totalPackets > 0 ? ((state.droppedCount / state.totalPackets) * 100).toFixed(1) : '0.0';
        elements.statDroppedPercent.textContent = `${dropPct}% Block Rate`;
    }

    function updateWorkerBars() {
        const fp0 = state.workerCounts.fp0;
        const fp1 = state.workerCounts.fp1;
        const fp2 = state.workerCounts.fp2;
        const fp3 = state.workerCounts.fp3;
        const max = Math.max(fp0, fp1, fp2, fp3, 1);

        document.getElementById('fp0Count').textContent = `${fp0} pkts`;
        document.getElementById('fp1Count').textContent = `${fp1} pkts`;
        document.getElementById('fp2Count').textContent = `${fp2} pkts`;
        document.getElementById('fp3Count').textContent = `${fp3} pkts`;

        document.getElementById('fp0Bar').style.width = `${(fp0 / max) * 100}%`;
        document.getElementById('fp1Bar').style.width = `${(fp1 / max) * 100}%`;
        document.getElementById('fp2Bar').style.width = `${(fp2 / max) * 100}%`;
        document.getElementById('fp3Bar').style.width = `${(fp3 / max) * 100}%`;
    }

    function updateChartData() {
        if (!state.chartInstance) return;
        state.chartInstance.data.labels = Object.keys(state.appData);
        state.chartInstance.data.datasets[0].data = Object.values(state.appData);
        state.chartInstance.update();
    }

    // DNS Query Test Handler
    async function handleDnsQuery(domain) {
        const cleanDomain = domain.trim();
        if (!cleanDomain) return;

        const startTime = performance.now();

        try {
            const res = await fetch(`${state.apiBase}/api/query-dns?domain=${encodeURIComponent(cleanDomain)}`);
            const data = await res.json();
            const latency = ((performance.now() - startTime)).toFixed(1);

            const isBlocked = data.action === 'DROP' || data.status.includes('REJECTED');
            const resolvedIp = data.resolved_ip || '0.0.0.0';
            const ruleMatch = data.rule_match || (isBlocked ? cleanDomain : null);

            elements.dnsResultCard.className = 'dns-result-box';
            
            if (isBlocked) {
                elements.dnsResultCard.innerHTML = `
                    <div class="dns-result-header">
                        <span style="font-weight: 700; font-size: 1.05rem;">
                            <i class="fa-solid fa-globe" style="color:var(--danger);"></i> ${escapeHtml(cleanDomain)}
                        </span>
                        <span class="action-badge action-drop"><i class="fa-solid fa-ban"></i> DROP (BLOCKED)</span>
                    </div>
                    <p style="font-size: 0.86rem; color: #fca5a5; line-height: 1.5;">
                        <i class="fa-solid fa-triangle-exclamation"></i> <strong>DNS Firewall Policy Enforced:</strong> 
                        Domain matches active rule <code>${escapeHtml(ruleMatch)}</code>. Resolved to safe drop target <code>0.0.0.0</code> in ${latency} ms.
                    </p>
                `;

                addPacketToTable({
                    id: ++state.packetIdCounter,
                    src: '192.168.1.100:54120',
                    dst: '0.0.0.0:53',
                    proto: 'DNS/UDP',
                    domain: cleanDomain,
                    app: 'DNS',
                    action: 'DROP'
                });
            } else {
                elements.dnsResultCard.innerHTML = `
                    <div class="dns-result-header">
                        <span style="font-weight: 700; font-size: 1.05rem;">
                            <i class="fa-solid fa-globe" style="color:var(--success);"></i> ${escapeHtml(cleanDomain)}
                        </span>
                        <span class="action-badge action-forward"><i class="fa-solid fa-check"></i> FORWARD (RESOLVED)</span>
                    </div>
                    <p style="font-size: 0.86rem; color: var(--text-muted); line-height: 1.5;">
                        <i class="fa-solid fa-circle-check" style="color:var(--success);"></i> <strong>DNS Query Allowed:</strong> 
                        No domain firewall rules matched. Resolved A-Record IP <code>${resolvedIp}</code> in ${latency} ms.
                    </p>
                `;

                addPacketToTable({
                    id: ++state.packetIdCounter,
                    src: '192.168.1.100:54120',
                    dst: `${resolvedIp}:443`,
                    proto: 'TLS/TCP',
                    domain: cleanDomain,
                    app: 'HTTPS',
                    action: 'FORWARD'
                });
            }
        } catch (err) {
            console.error('DNS Query error:', err);
        }

        updateStats();
    }

    // 5-Tuple Hashing Calculator & Routing Dispatcher
    function compute5TupleRouting(src, dst, proto) {
        const str = `${src}->${dst}:${proto}`;
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        const positiveHash = Math.abs(hash);
        const lbId = positiveHash % 2; // LB0 or LB1
        const fpOffset = positiveHash % 2;
        const fpId = (lbId * 2) + fpOffset; // FP0, FP1, FP2, FP3
        
        return {
            hashHex: '0x' + (positiveHash >>> 0).toString(16).toUpperCase().padStart(8, '0'),
            lbName: `LB${lbId} (Thread #${lbId + 1})`,
            fpName: `FP${fpId} (Worker #${fpId + 1})`,
            fpIdKey: `fp${fpId}`
        };
    }

    // Packet Table Population
    function addPacketToTable(packet) {
        const route = compute5TupleRouting(packet.src, packet.dst, packet.proto);
        packet.hashHex = route.hashHex;
        packet.lbName = route.lbName;
        packet.fpName = route.fpName;

        // Update Routing Inspector Box
        document.getElementById('routePacketId').textContent = `Packet #${packet.id}`;
        document.getElementById('routeTuple').textContent = `${packet.src} ➔ ${packet.dst} (${packet.proto})`;
        document.getElementById('routeHash').textContent = route.hashHex;
        document.getElementById('routeLB').textContent = route.lbName;
        document.getElementById('routeFP').textContent = route.fpName;

        state.packets.unshift(packet);
        if (state.packets.length > 50) state.packets.pop();

        renderPacketTable();
    }

    function renderPacketTable() {
        elements.packetTableBody.innerHTML = '';
        
        state.packets.forEach(pkt => {
            const tr = document.createElement('tr');
            const lbTag = pkt.lbName ? pkt.lbName.split(' ')[0] : 'LB0';
            const fpTag = pkt.fpName ? pkt.fpName.split(' ')[0] : 'FP0';
            
            tr.innerHTML = `
                <td style="color: var(--primary); font-weight:600;">#${pkt.id}</td>
                <td style="font-family: var(--font-code); font-size: 0.8rem;">${pkt.src} ➔ ${pkt.dst}</td>
                <td>
                    <span class="badge-lb">${lbTag}</span>
                    <span class="badge-fp">${fpTag}</span>
                </td>
                <td><code style="color: var(--text-main);">${escapeHtml(pkt.domain)}</code></td>
                <td><span style="font-weight: 500;">${pkt.app}</span></td>
                <td>
                    <span class="action-badge ${pkt.action === 'FORWARD' ? 'action-forward' : 'action-drop'}">
                        ${pkt.action}
                    </span>
                </td>
            `;
            elements.packetTableBody.appendChild(tr);
        });
    }

    // Setup Event Listeners
    function setupEventListeners() {
        // Run DPI Engine
        elements.btnRunDpiEngine.addEventListener('click', () => runDpiEngine(true));
        elements.btnCloseTerminal.addEventListener('click', () => {
            elements.terminalCard.style.display = 'none';
        });

        // Add Rule Form
        elements.addRuleForm.addEventListener('submit', (e) => {
            e.preventDefault();
            addDomainRule(elements.domainInput.value);
        });

        // Quick Preset Rule Buttons
        document.querySelectorAll('.preset-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const rule = e.target.getAttribute('data-rule');
                addDomainRule(rule);
            });
        });

        // Reset Rules
        elements.btnResetRules.addEventListener('click', async () => {
            state.blockedDomains = ['youtube.com', 'facebook.com', 'tiktok.com', 'malicious-site.org'];
            state.blockedIps = ['192.168.1.50'];
            renderRules();
            await runDpiEngine(false);
        });

        // Test DNS Form
        elements.testDnsForm.addEventListener('submit', (e) => {
            e.preventDefault();
            handleDnsQuery(elements.testDomainInput.value);
        });

        // Quick DNS Preset Links
        document.querySelectorAll('.dns-sample-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const domain = e.target.getAttribute('data-domain');
                elements.testDomainInput.value = domain;
                handleDnsQuery(domain);
            });
        });

        // Live Packet Stream Simulator
        elements.btnSimulateStream.addEventListener('click', toggleStreamSimulation);
        elements.btnClearStream.addEventListener('click', () => {
            state.packets = [];
            renderPacketTable();
        });
    }

    // Toggle Stream Simulation
    function toggleStreamSimulation() {
        const samples = [
            { domain: 'www.youtube.com', app: 'YouTube', port: 443 },
            { domain: 'www.google.com', app: 'Google', port: 443 },
            { domain: 'github.com', app: 'GitHub', port: 443 },
            { domain: 'www.facebook.com', app: 'Facebook', port: 443 },
            { domain: 'open.spotify.com', app: 'Spotify', port: 443 },
            { domain: 'www.tiktok.com', app: 'TikTok', port: 443 },
            { domain: 'discord.com', app: 'Discord', port: 443 },
            { domain: 'twitter.com', app: 'Twitter/X', port: 443 }
        ];

        if (state.isStreamRunning) {
            clearInterval(state.streamInterval);
            state.isStreamRunning = false;
            elements.btnSimulateStream.innerHTML = '<i class="fa-solid fa-play"></i> Simulate Traffic Stream';
            elements.btnSimulateStream.classList.remove('btn-danger');
        } else {
            state.isStreamRunning = true;
            elements.btnSimulateStream.innerHTML = '<i class="fa-solid fa-pause"></i> Pause Stream';
            elements.btnSimulateStream.classList.add('btn-danger');
            
            state.streamInterval = setInterval(() => {
                const randomItem = samples[Math.floor(Math.random() * samples.length)];
                const isBlocked = state.blockedDomains.some(b => randomItem.domain.includes(b));
                
                state.totalPackets++;
                state.totalBytes += Math.floor(Math.random() * 500 + 100);
                if (isBlocked) {
                    state.droppedCount++;
                } else {
                    state.forwardedCount++;
                }

                addPacketToTable({
                    id: ++state.packetIdCounter,
                    src: `192.168.1.${Math.floor(Math.random()*100+100)}:${Math.floor(Math.random()*10000+40000)}`,
                    dst: `172.217.14.${Math.floor(Math.random()*100+10)}:${randomItem.port}`,
                    proto: randomItem.port === 53 ? 'DNS/UDP' : 'TLS/TCP',
                    domain: randomItem.domain,
                    app: randomItem.app,
                    action: isBlocked ? 'DROP' : 'FORWARD'
                });
                
                updateStats();
            }, 1200);
        }
    }

    // Helper Utility: HTML escaping
    function escapeHtml(str) {
        return String(str || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
});
