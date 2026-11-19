// Initialize Chart.js
const ctx = document.getElementById('cspi-chart').getContext('2d');
let cspiChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['CSPI', 'Gap'],
        datasets: [{
            data: [0, 100],
            backgroundColor: ['#4B5563', '#1F2937'],
            borderWidth: 0,
            cutout: '80%'
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        animation: { animateScale: true, animateRotate: true }
    }
});

function updateGauge(score) {
    let color = '#3B82F6'; // Blue
    let status = 'COMPLIANT';
    if (score >= 90) { color = '#10B981'; status = 'HARDENED'; } // Green
    else if (score < 50) { color = '#EF4444'; status = 'CRITICAL'; } // Red
    else if (score < 75) { color = '#F59E0B'; status = 'MODERATE'; } // Yellow

    cspiChart.data.datasets[0].data = [score, 100 - score];
    cspiChart.data.datasets[0].backgroundColor = [color, '#1F2937'];
    cspiChart.update();

    document.getElementById('cspi-score-text').innerText = score;
    document.getElementById('cspi-status-text').innerText = status;
    document.getElementById('cspi-score-text').style.color = color;
}

function updateTable(sessions) {
    const tbody = document.getElementById('telemetry-table');
    tbody.innerHTML = '';
    
    document.getElementById('session-count').innerText = `${sessions.length} Sessions Monitored`;
    
    let strippingAlert = false;

    sessions.forEach(s => {
        const tr = document.createElement('tr');
        tr.className = 'border-b border-gray-700 bg-gray-800';
        
        let statusHtml = '<span class="px-2 py-1 bg-green-900 text-green-300 rounded text-xs">SECURE</span>';
        if (s.stripping_detected) {
            statusHtml = '<span class="px-2 py-1 bg-red-900 text-red-300 rounded text-xs flash-alert">STRIPPED</span>';
            strippingAlert = true;
        } else if (s.weak_cipher || s.weak_cert) {
            statusHtml = '<span class="px-2 py-1 bg-yellow-900 text-yellow-300 rounded text-xs">VULNERABLE</span>';
        } else if (s.is_anomalous) {
            statusHtml = '<span class="px-2 py-1 bg-purple-900 text-purple-300 rounded text-xs">ANOMALOUS</span>';
        } else if (!s.tls_established) {
             statusHtml = '<span class="px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs">PLAINTEXT</span>';
        }

        tr.innerHTML = `
            <td class="px-4 py-3 font-mono">${s.src_ip}</td>
            <td class="px-4 py-3 font-mono">${s.dst_ip}:${s.dst_port}</td>
            <td class="px-4 py-3">${s.protocol}</td>
            <td class="px-4 py-3">${s.tls_version || 'N/A'}</td>
            <td class="px-4 py-3 truncate max-w-[150px]" title="${s.cipher_suite || 'N/A'}">${s.cipher_suite || 'N/A'}</td>
            <td class="px-4 py-3">${statusHtml}</td>
        `;
        tbody.appendChild(tr);
    });

    const banner = document.getElementById('alert-banner');
    if (strippingAlert) {
        banner.classList.remove('hidden');
    } else {
        banner.classList.add('hidden');
    }
}

// Handle File Upload
const fileInput = document.getElementById('file-input');
fileInput.addEventListener('change', async (e) => {
    if (e.target.files.length > 0) {
        await uploadFile(e.target.files[0]);
    }
});

async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    // UI Loading state
    document.getElementById('cspi-score-text').innerText = '...';
    document.getElementById('cspi-status-text').innerText = 'ANALYZING';
    
    try {
        const response = await fetch('/api/v1/analyze', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        updateGauge(data.cspi_score);
        updateTable(data.sessions);
    } catch (err) {
        console.error("Upload failed", err);
        alert("Analysis failed. See console.");
    }
}

// Handle Demo Buttons
document.querySelectorAll('.demo-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
        const filename = e.target.getAttribute('data-file');
        
        document.getElementById('cspi-score-text').innerText = '...';
        document.getElementById('cspi-status-text').innerText = 'ANALYZING';
        
        try {
            const response = await fetch(`/api/v1/analyze/demo/${filename}`);
            if (!response.ok) throw new Error("Failed to load demo");
            const data = await response.json();
            updateGauge(data.cspi_score);
            updateTable(data.sessions);
        } catch (err) {
            console.error("Demo load failed", err);
            alert("Analysis failed. See console.");
        }
    });
});
