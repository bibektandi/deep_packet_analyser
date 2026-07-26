/**
 * Deep Packet Inspection & DNS Firewall Frontend Application
 * Interactively manages domain blocking rules and simulates DNS query resolution.
 */

document.addEventListener('DOMContentLoaded', () => {
    
    // State management
    const state = {
        blockedDomains: ['youtube.com', 'facebook.com', 'tiktok.com', 'malicious-site.org'],
        totalRequests: 0,
        blockedCount: 4,
        forwardedCount: 0,
        workerCounts: { fp0: 0, fp1: 0, fp2: 0, fp3: 0 },
        packets: [],
        packetIdCounter: 100,
        isStreamRunning: false,
        streamInterval: null
    };

    // Sample IP pool for mock DNS resolution
    const mockIpDatabase = {
        'google.com': '142.250.190.46',
        'github.com': '140.82.121.4',
        'microsoft.com': '20.112.52.29',
        'apple.com': '17.253.144.10',
        'amazon.com': '205.251.242.103',
        'wikipedia.org': '185.15.59.20',
        'stackoverflow.com': '151.101.1.69',
        'reddit.com': '151.101.65.140'
    };

    // Sample traffic templates for stream simulation
    const sampleDomains = [
        { domain: 'google.com', app: 'Google', port: 443 },
        { domain: 'youtube.com', app: 'YouTube', port: 443 },
        { domain: 'facebook.com', app: 'Facebook', port: 443 },
        { domain: 'github.com', app: 'GitHub', port: 443 },
        { domain: 'twitter.com', app: 'Twitter/X', port: 443 },
        { domain: 'instagram.com', app: 'Instagram', port: 443 },
        { domain: 'tiktok.com', app: 'TikTok', port: 443 },
        { domain: 'open.spotify.com', app: 'Spotify', port: 443 },
        { domain: 'discord.com', app: 'Discord', port: 443 },
        { domain: 'zoom.us', app: 'Zoom', port: 443 }
    ];

    // DOM Element References
    const elements = {
        rulesList: document.getElementById('rulesList'),
        addRuleForm: document.getElementById('addRuleForm'),
        domainInput: document.getElementById('domainInput'),
        resetRulesBtn: document.getElementById('resetRulesBtn'),
        
        testDnsForm: document.getElementById('testDnsForm'),
        testDomainInput: document.getElementById('testDomainInput'),
        dnsResultBox: document.getElementById('dnsResultBox'),
        resDomain: document.getElementById('resDomain'),
        resBadge: document.getElementById('resBadge'),
        resIP: document.getElementById('resIP'),
        resAction: document.getElementById('resAction'),
        resLatency: document.getElementById('resLatency'),
        resMessage: document.getElementById('resMessage'),
        
        statTotalRequests: document.getElementById('statTotalRequests'),
        statBlockedCount: document.getElementById('statBlockedCount'),
        statForwarded: document.getElementById('statForwarded'),
        
        packetTableBody: document.getElementById('packetTableBody'),
        btnSimulateStream: document.getElementById('btnSimulateStream'),
        btnClearStream: document.getElementById('btnClearStream'),
        
        tabBtns: document.querySelectorAll('.tab-btn'),
        tabContents: document.querySelectorAll('.tab-content')
    };

    // Initialize UI
    init();

    function init() {
        setupTabNavigation();
        renderRules();
        updateStats();
        setupEventListeners();
        generateInitialPackets();
    }

    // Tab Switching Logic
    function setupTabNavigation() {
        elements.tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const targetTab = btn.getAttribute('data-tab');
                
                elements.tabBtns.forEach(b => b.classList.remove('active'));
                elements.tabContents.forEach(c => c.classList.remove('active'));
                
                btn.classList.add('active');
                document.getElementById(targetTab).classList.add('active');
            });
        });
    }

    // Render Blocked Domain Chips
    function renderRules() {
        elements.rulesList.innerHTML = '';
        
        if (state.blockedDomains.length === 0) {
            elements.rulesList.innerHTML = `
                <span style="color: var(--text-dim); font-size: 0.85rem; padding: 0.4rem;">
                    No domains blocked. All DNS queries will be allowed.
                </span>`;
            return;
        }

        state.blockedDomains.forEach(domain => {
            const chip = document.createElement('div');
            chip.className = 'rule-chip';
            chip.innerHTML = `
                <i class="fa-solid fa-shield-cat"></i>
                <span>${escapeHtml(domain)}</span>
                <i class="fa-solid fa-xmark remove-btn" title="Remove Block Rule"></i>
            `;
            
            chip.querySelector('.remove-btn').addEventListener('click', () => {
                removeDomainRule(domain);
            });
            
            elements.rulesList.appendChild(chip);
        });

        state.blockedCount = state.blockedDomains.length;
        updateStats();
    }

    // Add Domain Block Rule
    function addDomainRule(domain) {
        let cleanDomain = domain.trim().toLowerCase();
        cleanDomain = cleanDomain.replace(/^(https?:\/\/)?(www\.)?/, '');
        
        if (!cleanDomain) return;
        
        if (!state.blockedDomains.includes(cleanDomain)) {
            state.blockedDomains.push(cleanDomain);
            renderRules();
        }
        elements.domainInput.value = '';
    }

    // Remove Domain Block Rule
    function removeDomainRule(domain) {
        state.blockedDomains = state.blockedDomains.filter(d => d !== domain);
        renderRules();
    }

    // Reset Rules to Default
    function resetRules() {
        state.blockedDomains = ['youtube.com', 'facebook.com', 'tiktok.com', 'malicious-site.org'];
        renderRules();
    }

    // Update Top Summary Cards
    function updateStats() {
        elements.statTotalRequests.textContent = state.totalRequests;
        elements.statBlockedCount.textContent = state.blockedDomains.length;
        elements.statForwarded.textContent = state.forwardedCount;
        
        const percentAllowed = state.totalRequests > 0 
            ? ((state.forwardedCount / state.totalRequests) * 100).toFixed(1) 
            : 0;
            
        const percentElem = document.getElementById('statForwardedPercent');
        if (percentElem) {
            percentElem.innerHTML = `<i class="fa-solid fa-check"></i> ${percentAllowed}% Allowed`;
        }
    }

    // Test DNS Query Engine Logic with REAL Live DNS Resolution
    async function handleDnsTest(domainName) {
        let rawInput = domainName.trim().toLowerCase();
        let cleanDomain = rawInput.replace(/^(https?:\/\/)?(www\.)?/, '');
        if (!cleanDomain) return;

        state.totalRequests++;
        elements.resDomain.textContent = `Target: ${rawInput}`;
        elements.resBadge.className = 'result-badge';
        elements.resBadge.textContent = 'RESOLVING...';
        
        const startTime = performance.now();

        try {
            const response = await fetch(`/api/query-dns?domain=${encodeURIComponent(rawInput)}`);
            const data = await response.json();
            const latency = (performance.now() - startTime).toFixed(1);

            const isBlocked = data.action === 'DROP';
            const displayDomain = data.clean_domain || cleanDomain;
            const resolvedIp = data.resolved_ip || '0.0.0.0';

            if (isBlocked) {
                elements.resBadge.className = 'result-badge badge-blocked';
                elements.resBadge.textContent = 'BLOCKED / REJECTED';
                elements.resIP.textContent = '0.0.0.0 (Sinkholed)';
                elements.resIP.style.color = 'var(--danger)';
                elements.resAction.textContent = 'DROP (Rule Match)';
                elements.resAction.style.color = 'var(--danger)';
                elements.resLatency.textContent = `${latency} ms`;
                
                elements.resMessage.innerHTML = `
                    <strong style="color: var(--danger);">🚫 DNS Firewall Action Triggered!</strong><br>
                    The query for <code>${escapeHtml(displayDomain)}</code> matched active rule pattern 
                    <span style="color:#ff8a80;">[${escapeHtml(data.rule_match || displayDomain)}]</span>. 
                    The DPI engine dropped the packet to prevent connections.
                `;

                addPacketToTable({
                    id: ++state.packetIdCounter,
                    src: '192.168.1.100:53412',
                    dst: '8.8.8.8:53',
                    proto: 'DNS/UDP',
                    domain: displayDomain,
                    app: 'DNS Query',
                    action: 'DROP'
                });

            } else {
                state.forwardedCount++;

                elements.resBadge.className = 'result-badge badge-allowed';
                elements.resBadge.textContent = 'ALLOWED / RESOLVED';
                elements.resIP.textContent = resolvedIp;
                elements.resIP.style.color = 'var(--success)';
                elements.resAction.textContent = 'FORWARD';
                elements.resAction.style.color = 'var(--success)';
                elements.resLatency.textContent = `${latency} ms`;

                elements.resMessage.innerHTML = `
                    <strong style="color: var(--success);">✅ DNS Query Fulfilled Successfully!</strong><br>
                    No domain firewall rule blocked <code>${escapeHtml(displayDomain)}</code>. 
                    DNS A-record resolved real IP address <code>${resolvedIp}</code> in ${latency} ms.
                `;

                addPacketToTable({
                    id: ++state.packetIdCounter,
                    src: '192.168.1.100:54120',
                    dst: `${resolvedIp}:443`,
                    proto: 'TLS/TCP',
                    domain: displayDomain,
                    app: 'HTTPS',
                    action: 'FORWARD'
                });
            }
        } catch (err) {
            console.error('DNS Query error:', err);
        }

        updateStats();
    }

    // Compute 5-Tuple Hash and determine assigned Load Balancer & Fast Path Worker Thread
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

    // Packet Table Population & Thread Dispatch Update
    function addPacketToTable(packet) {
        // Calculate Thread Routing
        const route = compute5TupleRouting(packet.src, packet.dst, packet.proto);
        packet.hashHex = route.hashHex;
        packet.lbName = route.lbName;
        packet.fpName = route.fpName;

        // Update Worker Thread Stats & Progress Bars
        if (state.workerCounts[route.fpIdKey] !== undefined) {
            state.workerCounts[route.fpIdKey]++;
            updateWorkerThreadUI(route, packet);
        }

        state.packets.unshift(packet);
        if (state.packets.length > 50) state.packets.pop();

        renderPacketTable();
    }

    function updateWorkerThreadUI(route, packet) {
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

        // Update Inspector Box
        document.getElementById('routePacketId').textContent = `Packet #${packet.id}`;
        document.getElementById('routeTuple').textContent = `${packet.src} ➔ ${packet.dst} (${packet.proto})`;
        document.getElementById('routeHash').textContent = route.hashHex;
        document.getElementById('routeLB').textContent = route.lbName;
        document.getElementById('routeFP').textContent = route.fpName;
    }

    function renderPacketTable() {
        elements.packetTableBody.innerHTML = '';
        
        state.packets.forEach(pkt => {
            const tr = document.createElement('tr');
            const lbTag = pkt.lbName ? pkt.lbName.split(' ')[0] : 'LB0';
            const fpTag = pkt.fpName ? pkt.fpName.split(' ')[0] : 'FP0';
            
            tr.innerHTML = `
                <td style="color: var(--primary); font-weight:600;">#${pkt.id}</td>
                <td>${pkt.src} ➔ ${pkt.dst}</td>
                <td>
                    <span class="badge-lb">${lbTag}</span>
                    <span class="badge-fp">${fpTag}</span>
                </td>
                <td><code>${escapeHtml(pkt.domain)}</code></td>
                <td>${pkt.app}</td>
                <td>
                    <span class="action-tag ${pkt.action === 'FORWARD' ? 'action-forward' : 'action-drop'}">
                        ${pkt.action}
                    </span>
                </td>
            `;
            elements.packetTableBody.appendChild(tr);
        });
    }

    function generateInitialPackets() {
        for (let i = 0; i < 6; i++) {
            const template = sampleDomains[i % sampleDomains.length];
            const isBlocked = state.blockedDomains.some(b => template.domain.includes(b));
            
            addPacketToTable({
                id: ++state.packetIdCounter,
                src: `192.168.1.${101 + i}:${49150 + i}`,
                dst: `104.16.249.${10 + i}:${template.port}`,
                proto: 'TLS/TCP',
                domain: template.domain,
                app: template.app,
                action: isBlocked ? 'DROP' : 'FORWARD'
            });
        }
    }

    // Event Listeners
    function setupEventListeners() {
        // Add Rule Form
        elements.addRuleForm.addEventListener('submit', (e) => {
            e.preventDefault();
            addDomainRule(elements.domainInput.value);
        });

        // Reset Rules
        elements.resetRulesBtn.addEventListener('click', () => {
            resetRules();
        });

        // Test DNS Form
        elements.testDnsForm.addEventListener('submit', (e) => {
            e.preventDefault();
            handleDnsTest(elements.testDomainInput.value);
        });

        // Stream Simulation
        elements.btnSimulateStream.addEventListener('click', () => {
            toggleStreamSimulation();
        });

        elements.btnClearStream.addEventListener('click', () => {
            state.packets = [];
            renderPacketTable();
        });
    }

    function toggleStreamSimulation() {
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
                const randomItem = sampleDomains[Math.floor(Math.random() * sampleDomains.length)];
                const isBlocked = state.blockedDomains.some(b => randomItem.domain.includes(b));
                
                state.totalRequests++;
                if (isBlocked) {
                    // Blocked
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

    // Helper Utility: XSS escape
    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
});
