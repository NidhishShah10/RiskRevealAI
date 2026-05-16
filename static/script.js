async function analyzeEmail() {
    const message = document.getElementById("emailInput").value;

    if (!message.trim()) {
        alert("Please paste an email or message first.");
        return;
    }

    document.getElementById("result").innerHTML = `
        <p style="margin-top: 20px; color: #888;">Analyzing...</p>
    `;

    const response = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: message })
    });

    const data = await response.json();
    renderResults(data, message);

    document.getElementById("page-input").classList.remove("active");
    document.getElementById("page-results").classList.add("active");
    window.scrollTo(0, 0);
}

function goBack() {
    document.getElementById("page-results").classList.remove("active");
    document.getElementById("page-input").classList.add("active");
    document.getElementById("result").innerHTML = "";
    window.scrollTo(0, 0);
}

function renderResults(data, message) {
    const isPhishing = data.risk_score >= 40;
    const scoreColor = data.risk_score >= 70 ? "#ff4d4d"
                     : data.risk_score >= 40 ? "#ffb347"
                     : "#00e5a0";

    const patternChips = data.detected_patterns.length > 0
        ? `<div class="chips">${data.detected_patterns.map(p =>
            `<span class="chip chip-danger">${p.category.toUpperCase()}: "${p.phrase}"</span>`
          ).join("")}</div>`
        : `<span style="color:var(--text-muted); font-size:13px;">None detected</span>`;

    const urlBlocks = data.urls_found.length > 0
        ? data.urls_found.map(u =>
            `<div class="url-block">
                <div class="url-text">🔗 ${u.url}</div>
                <div class="chips">${u.flags.map(f =>
                    `<span class="chip chip-warn">${f}</span>`
                ).join("")}</div>
            </div>`
          ).join("")
        : `<span style="color:var(--text-muted); font-size:13px;">No URLs found</span>`;

    const senderChips = data.sender_domain
        ? `<div class="sender-domain">${data.sender_domain}</div>
           <div class="chips">${data.sender_flags.map(f =>
               `<span class="chip chip-danger">${f}</span>`
           ).join("")}</div>`
        : `<span style="color:var(--text-muted); font-size:13px;">No sender domain found</span>`;

    const highlightedHtml = data.highlighted_message
        ? data.highlighted_message.replace(/\n/g, "<br>")
        : message.replace(/\n/g, "<br>");

    document.getElementById("result").innerHTML = `
        <div class="score-hero" style="color: ${scoreColor};">
            <div class="score-number" style="color: ${scoreColor};">${data.risk_score}%</div>
            <div class="score-verdict" style="color: ${scoreColor};">
                ${isPhishing ? "🚨" : "✅"} ${data.verdict}
            </div>
            <div class="score-level">${data.risk_level} Risk</div>
        </div>

        <div class="card">
            <div class="card-title">🤖 AI Explanation</div>
            <div class="explanation-text">${data.explanation}</div>
        </div>

        <div class="card">
            <div class="card-title">⚠️ Detected Threat Indicators</div>
            ${patternChips}
        </div>

        <div class="card">
            <div class="card-title">🔗 URLs Detected (${data.url_count})</div>
            ${urlBlocks}
        </div>

        <div class="card">
            <div class="card-title">👤 Sender Analysis</div>
            ${senderChips}
        </div>

        <div class="card">
            <div class="card-title">📧 Highlighted Message</div>
            <div class="highlighted-msg">${highlightedHtml}</div>
        </div>

        <div class="card">
            <div class="card-title">📊 Score Breakdown</div>
            <div class="bar-row">
                <span class="bar-label">Language</span>
                <div class="bar-track">
                    <div class="bar-fill" style="width:${data.score_breakdown.language}%"></div>
                </div>
                <span class="bar-val">${data.score_breakdown.language}%</span>
            </div>
            <div class="bar-row">
                <span class="bar-label">Links</span>
                <div class="bar-track">
                    <div class="bar-fill" style="width:${data.score_breakdown.links}%"></div>
                </div>
                <span class="bar-val">${data.score_breakdown.links}%</span>
            </div>
            <div class="bar-row">
                <span class="bar-label">Sender</span>
                <div class="bar-track">
                    <div class="bar-fill" style="width:${data.score_breakdown.sender}%"></div>
                </div>
                <span class="bar-val">${data.score_breakdown.sender}%</span>
            </div>
        </div>
    `;
}