window.addEventListener("load", () => {

    const intro = document.getElementById("intro-screen");
    const inputPage = document.getElementById("page-input");

    setTimeout(() => {

        intro.classList.add("hidden");

        setTimeout(() => {
            inputPage.classList.add("active");
        }, 500);

    }, 2200);

});

function clearInput() {
    document.getElementById("emailInput").value = "";
    document.getElementById("emailInput").focus();
}

/* =========================
   SMOOTH LOADER
========================= */

function showLoader() {

    const overlay = document.getElementById("loading-overlay");
    const robot = document.getElementById("robot");
    const bar = document.getElementById("loading-bar");

    overlay.classList.add("active");

    let progress = 0;

    robot.style.left = "5%";
    bar.style.width = "0%";

    const interval = setInterval(() => {

        // Fast beginning
        if (progress < 80) {
            progress += 2.8;
        }

        // Slow premium finish
        else if (progress < 97) {
            progress += 0.18;
        }

        if (progress > 97) {
            progress = 97;
        }

        robot.style.left =
            (5 + (progress / 100) * 83) + "%";

        bar.style.width = progress + "%";

    }, 35);

    return interval;
}

function hideLoader(interval) {

    const overlay = document.getElementById("loading-overlay");
    const bar = document.getElementById("loading-bar");
    const robot = document.getElementById("robot");

    clearInterval(interval);

    // smooth finish
    bar.style.transition = "width 0.28s ease";
    robot.style.transition = "left 0.28s ease";

    bar.style.width = "100%";
    robot.style.left = "88%";

    setTimeout(() => {

        overlay.classList.remove("active");

        // reset
        bar.style.width = "0%";
        robot.style.left = "5%";

    }, 300);
}

/* =========================
   ANALYZE EMAIL
========================= */

async function analyzeEmail() {

    const message =
        document.getElementById("emailInput").value;

    if (!message.trim()) {
        alert("Please paste an email or message first.");
        return;
    }

    const loaderInterval = showLoader();

    try {

        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: message
            })
        });

        const data = await response.json();

        renderResults(data, message);

        hideLoader(loaderInterval);

        setTimeout(() => {

            document
                .getElementById("page-input")
                .classList.remove("active");

            document
                .getElementById("page-results")
                .classList.add("active");

            window.scrollTo(0, 0);

        }, 320);

    } catch (e) {

        hideLoader(loaderInterval);

        alert("Something went wrong. Please try again.");

        console.error(e);
    }
}

/* =========================
   BACK BUTTON
========================= */

function goBack() {

    document
        .getElementById("page-results")
        .classList.remove("active");

    document
        .getElementById("page-input")
        .classList.add("active");

    document.getElementById("result").innerHTML = "";

    window.scrollTo(0, 0);
}

/* =========================
   RENDER RESULTS
========================= */

function renderResults(data, message) {

    const isPhishing = data.risk_score >= 40;

    const scoreColor =
        data.risk_score >= 70
            ? "#ff4d4d"
            : data.risk_score >= 40
            ? "#ffb347"
            : "#00e5a0";

    const patternChips =
        data.detected_patterns.length > 0
            ? `
            <div class="chips">
                ${data.detected_patterns.map(p => `
                    <span class="chip chip-danger">
                        ${p.category.toUpperCase()}: "${p.phrase}"
                    </span>
                `).join("")}
            </div>
        `
            : `
            <span style="color:var(--text-muted); font-size:13px;">
                None detected
            </span>
        `;

    const urlBlocks =
        data.urls_found.length > 0
            ? data.urls_found.map(u => {

                const isFraud = u.flags.length > 0;

                const statusClass =
                    isFraud ? "fraud" : "legit";

                const statusLabel =
                    isFraud ? "🔴 Fraud" : "🟢 Legit";

                return `
                    <div class="url-block">

                        <div class="url-row">

                            <span class="url-text">
                                🔗 ${u.url}
                            </span>

                            <span class="url-status ${statusClass}">
                                ${statusLabel}
                            </span>

                        </div>

                        <div class="chips">
                            ${u.flags.map(f => `
                                <span class="chip chip-warn">
                                    ${f}
                                </span>
                            `).join("")}
                        </div>

                    </div>
                `;

            }).join("")
            : `
            <span style="color:var(--text-muted); font-size:13px;">
                No URLs found
            </span>
        `;

    const senderChips =
        data.sender_domain
            ? `
            <div class="sender-domain">
                ${data.sender_domain}
            </div>

            <div class="chips">
                ${data.sender_flags.map(f => `
                    <span class="chip chip-danger">
                        ${f}
                    </span>
                `).join("")}
            </div>
        `
            : `
            <span style="color:var(--text-muted); font-size:13px;">
                No sender domain found
            </span>
        `;

    const highlightedHtml =
        data.highlighted_message
            ? data.highlighted_message.replace(/\n/g, "<br>")
            : message.replace(/\n/g, "<br>");

    document.getElementById("result").innerHTML = `

        <div class="score-hero"
             style="color:${scoreColor};">

            <div class="score-number"
                 style="color:${scoreColor};">
                ${data.risk_score}%
            </div>

            <div class="score-verdict"
                 style="color:${scoreColor};">

                ${isPhishing ? "🚨" : "✅"}
                ${data.verdict}

            </div>

            <div class="score-level">
                ${data.risk_level} Risk
            </div>

        </div>

        <div class="card">

            <div class="card-title">
                🤖 AI Explanation
            </div>

            <div class="explanation-text">
                ${data.explanation}
            </div>

        </div>

        <div class="card">

            <div class="card-title">
                ⚠️ Detected Threat Indicators
            </div>

            ${patternChips}

        </div>

        <div class="card">

            <div class="card-title">
                🔗 URLs Detected (${data.url_count})
            </div>

            ${urlBlocks}

        </div>

        <div class="card">

            <div class="card-title">
                👤 Sender Analysis
            </div>

            ${senderChips}

        </div>

        <div class="card">

            <div class="card-title">
                📧 Highlighted Message
            </div>

            <div class="highlighted-msg">
                ${highlightedHtml}
            </div>

        </div>

        <div class="card">

            <div class="card-title">
                📊 Score Breakdown
            </div>

            <div class="bar-row">

                <span class="bar-label">
                    Language
                </span>

                <div class="bar-track">
                    <div class="bar-fill"
                         style="width:${data.score_breakdown.language}%">
                    </div>
                </div>

                <span class="bar-val">
                    ${data.score_breakdown.language}%
                </span>

            </div>

            <div class="bar-row">

                <span class="bar-label">
                    Links
                </span>

                <div class="bar-track">
                    <div class="bar-fill"
                         style="width:${data.score_breakdown.links}%">
                    </div>
                </div>

                <span class="bar-val">
                    ${data.score_breakdown.links}%
                </span>

            </div>

            <div class="bar-row">

                <span class="bar-label">
                    Sender
                </span>

                <div class="bar-track">
                    <div class="bar-fill"
                         style="width:${data.score_breakdown.sender}%">
                    </div>
                </div>

                <span class="bar-val">
                    ${data.score_breakdown.sender}%
                </span>

            </div>

        </div>
    `;
}