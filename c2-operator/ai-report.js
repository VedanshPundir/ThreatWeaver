#!/usr/bin/env node
/**
 * ai-report.js - AI-Powered Automated Report Generator with PDF & Telegram
 * Uses GPT to analyze attack data and generate dynamic reports with charts
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import https from 'https';
import http from 'http';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const C2_BASE_URL = process.env.C2_BASE_URL || 'http://localhost:8000';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';
const MEMORY_DIR = path.join(os.homedir(), '.openclaw', 'memory');
const REPORTS_DIR = path.join(__dirname, 'reports');

// Try to import puppeteer if available
let puppeteer = null;
try {
    puppeteer = await import('puppeteer');
    console.log('✅ Puppeteer loaded for PDF generation');
} catch (e) {
    console.log('⚠️  Puppeteer not installed. PDF generation will use HTML fallback');
}

class AIReportGenerator {
    constructor() {
        this.rawData = {
            techniques: [],
            alerts: [],
            logs: [],
            apt_matches: [],
            victim_profile: {},
            session_metrics: {}
        };
        this.aiAnalysis = {};
        this.chartData = {};
    }

    async generate() {
        console.log('\n🤖 AI-Powered Automated Report Generator');
        console.log('════════════════════════════════════════════════════════');
        
        if (!OPENAI_API_KEY || OPENAI_API_KEY === 'YOUR_OPENAI_API_KEY') {
            console.log('❌ OpenAI API key not configured. Set OPENAI_API_KEY in .env');
            process.exit(1);
        }
        
        // Step 1: Collect raw data
        await this.collectRawData();
        
        // Step 2: Generate charts
        console.log('\n📊 Generating charts and visualizations...');
        await this.generateCharts();
        
        // Step 3: AI Analysis of findings
        console.log('\n🧠 AI Analyzing Attack Data...');
        await this.analyzeWithAI();
        
        // Step 4: Generate report sections
        console.log('\n📝 Generating AI-Powered Report...');
        await this.generateReportSections();
        
        // Step 5: Create PDF report
        console.log('\n📄 Creating PDF Report...');
        await this.createPDFReport();
        
        // Step 6: Send to Telegram
        if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
            console.log('\n📱 Sending report to Telegram...');
            await this.sendToTelegram();
        } else {
            console.log('\n⚠️  Telegram not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env');
        }
        
        console.log('\n✅ AI Report Generation Complete!');
    }
    
    async collectRawData() {
        console.log('📊 Collecting attack data...');
        
        // Load knowledge base
        const kbPath = path.join(MEMORY_DIR, 'knowledge_base.json');
        if (fs.existsSync(kbPath)) {
            const kb = JSON.parse(fs.readFileSync(kbPath, 'utf8'));
            for (const [id, tech] of Object.entries(kb.techniques || {})) {
                this.rawData.techniques.push({
                    id: id,
                    name: tech.name || id,
                    tactic: tech.tactic,
                    success_rate: ((tech.success_rate || 0) * 100).toFixed(1),
                    attempts: tech.attempts || 0,
                    successes: tech.successes || 0,
                    detection_rate: ((tech.detection_rate || 0) * 100).toFixed(1),
                    commands: (tech.commands || []).slice(0, 3).map(c => c.command),
                    first_seen: tech.first_seen,
                    last_seen: tech.last_seen
                });
            }
        }
        
        // Load victim profile
        const profilePath = path.join(MEMORY_DIR, 'victim_profile.json');
        if (fs.existsSync(profilePath)) {
            this.rawData.victim_profile = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
        }
        
        // Load session metrics
        const sessionPath = path.join(MEMORY_DIR, 'session_metrics.json');
        if (fs.existsSync(sessionPath)) {
            this.rawData.session_metrics = JSON.parse(fs.readFileSync(sessionPath, 'utf8'));
        }
        
        // Fetch live C2 data
        await this.fetchLiveData();
        
        // Calculate statistics
        this.rawData.stats = {
            total_techniques: this.rawData.techniques.length,
            successful: this.rawData.techniques.filter(t => t.successes > 0).length,
            failed: this.rawData.techniques.filter(t => t.successes === 0).length,
            critical_alerts: this.rawData.alerts.filter(a => a.level === 'critical').length,
            total_alerts: this.rawData.alerts.length,
            total_sessions: this.rawData.session_metrics?.total_sessions || 0
        };
        
        // Group by tactic
        this.rawData.tactics_grouped = {};
        for (const tech of this.rawData.techniques) {
            const tactic = tech.tactic || 'unknown';
            if (!this.rawData.tactics_grouped[tactic]) {
                this.rawData.tactics_grouped[tactic] = [];
            }
            this.rawData.tactics_grouped[tactic].push(tech);
        }
    }
    
    async fetchLiveData() {
        try {
            // Fetch APT correlation
            const aptRes = await fetch(`${C2_BASE_URL}/api/apt/correlate?top_n=10`);
            if (aptRes.ok) {
                this.rawData.apt_matches = (await aptRes.json()).top_matches || [];
            }
            
            // Fetch logs
            const logsRes = await fetch(`${C2_BASE_URL}/api/logs?limit=200`);
            if (logsRes.ok) {
                const logsData = await logsRes.json();
                this.rawData.logs = logsData.logs || [];
                this.rawData.alerts = this.rawData.logs.filter(l => 
                    l.level === 'alert' || l.level === 'critical'
                );
            }
        } catch (e) {
            console.log('⚠️  Could not fetch live C2 data');
        }
    }
    
    async generateCharts() {
        // Prepare chart data
        this.chartData = {
            successRate: {
                labels: ['Successful', 'Failed'],
                data: [this.rawData.stats.successful, this.rawData.stats.failed],
                colors: ['#28a745', '#dc3545']
            },
            tacticsDistribution: {},
            aptCorrelation: {},
            detectionRate: {}
        };
        
        // Tactics distribution
        for (const [tactic, techs] of Object.entries(this.rawData.tactics_grouped)) {
            const successful = techs.filter(t => t.successes > 0).length;
            this.chartData.tacticsDistribution[tactic] = {
                total: techs.length,
                successful: successful,
                rate: (successful / techs.length * 100).toFixed(1)
            };
        }
        
        // APT correlation
        for (const apt of this.rawData.apt_matches.slice(0, 5)) {
            this.chartData.aptCorrelation[apt.name] = parseFloat(apt.score_pct);
        }
        
        // Detection rate for top techniques
        const topTechs = this.rawData.techniques
            .filter(t => t.successes > 0)
            .sort((a, b) => b.success_rate - a.success_rate)
            .slice(0, 5);
        
        for (const tech of topTechs) {
            this.chartData.detectionRate[tech.id] = {
                name: tech.name,
                detection: parseFloat(tech.detection_rate)
            };
        }
        
        // Create HTML chart template
        this.chartHTML = `
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin: 20px 0;">
            <div>
                <canvas id="successRateChart" style="max-height: 300px;"></canvas>
            </div>
            <div>
                <canvas id="aptChart" style="max-height: 300px;"></canvas>
            </div>
            <div>
                <canvas id="tacticsChart" style="max-height: 300px;"></canvas>
            </div>
            <div>
                <canvas id="detectionChart" style="max-height: 300px;"></canvas>
            </div>
        </div>
        <script>
        setTimeout(() => {
            try {
                // Success Rate Chart
                new Chart(document.getElementById('successRateChart'), {
                    type: 'pie',
                    data: {
                        labels: ${JSON.stringify(this.chartData.successRate.labels)},
                        datasets: [{
                            data: ${JSON.stringify(this.chartData.successRate.data)},
                            backgroundColor: ${JSON.stringify(this.chartData.successRate.colors)},
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: { display: true, text: 'Overall Success Rate' },
                            legend: { position: 'bottom' }
                        }
                    }
                });
                
                // APT Correlation Chart
                new Chart(document.getElementById('aptChart'), {
                    type: 'bar',
                    data: {
                        labels: ${JSON.stringify(Object.keys(this.chartData.aptCorrelation))},
                        datasets: [{
                            label: 'Match Percentage',
                            data: ${JSON.stringify(Object.values(this.chartData.aptCorrelation))},
                            backgroundColor: '#667eea',
                            borderColor: '#764ba2',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: { display: true, text: 'APT Group Correlation' },
                            legend: { display: false }
                        },
                        scales: {
                            y: { beginAtZero: true, max: 100, title: { display: true, text: 'Match %' } }
                        }
                    }
                });
                
                // Tactics Distribution Chart
                new Chart(document.getElementById('tacticsChart'), {
                    type: 'radar',
                    data: {
                        labels: ${JSON.stringify(Object.keys(this.chartData.tacticsDistribution))},
                        datasets: [{
                            label: 'Success Rate %',
                            data: ${JSON.stringify(Object.values(this.chartData.tacticsDistribution).map(t => t.rate))},
                            backgroundColor: 'rgba(102, 126, 234, 0.2)',
                            borderColor: '#667eea',
                            pointBackgroundColor: '#764ba2',
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: { display: true, text: 'Tactics Success Rate' },
                            legend: { position: 'bottom' }
                        },
                        scales: {
                            r: { beginAtZero: true, max: 100, ticks: { stepSize: 20 } }
                        }
                    }
                });
                
                // Detection Rate Chart
                new Chart(document.getElementById('detectionChart'), {
                    type: 'bar',
                    data: {
                        labels: ${JSON.stringify(Object.values(this.chartData.detectionRate).map(t => t.name))},
                        datasets: [{
                            label: 'Detection Rate %',
                            data: ${JSON.stringify(Object.values(this.chartData.detectionRate).map(t => t.detection))},
                            backgroundColor: '#ed8936',
                            borderColor: '#c05621',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        indexAxis: 'y',
                        plugins: {
                            title: { display: true, text: 'Top Techniques - Detection Rate' },
                            legend: { display: false }
                        },
                        scales: {
                            x: { beginAtZero: true, max: 100, title: { display: true, text: 'Detection Rate %' } }
                        }
                    }
                });
            } catch(e) {
                console.log('Chart error:', e);
            }
        }, 1000);
        </script>
        `;
    }
    
    async analyzeWithAI() {
        const successTechs = this.rawData.techniques.filter(t => t.successes > 0);
        const failedTechs = this.rawData.techniques.filter(t => t.successes === 0);
        
        const attackSummary = `
Attack Summary:
- Total Techniques Attempted: ${this.rawData.stats.total_techniques}
- Successful: ${this.rawData.stats.successful}
- Failed: ${this.rawData.stats.failed}
- Critical Alerts: ${this.rawData.stats.critical_alerts}
- Total Alerts: ${this.rawData.stats.total_alerts}
- Total Sessions: ${this.rawData.stats.total_sessions}

Successful Techniques:
${successTechs.map(t => `  - ${t.id}: ${t.name} (${t.success_rate}% success, detection: ${t.detection_rate}%)`).join('\n')}

Failed Techniques:
${failedTechs.map(t => `  - ${t.id}: ${t.name}`).join('\n')}

Top Tactics Used:
${Object.entries(this.rawData.tactics_grouped).map(([tactic, techs]) => 
    `  - ${tactic}: ${techs.length} techniques (${techs.filter(t => t.successes > 0).length} successful)`
).join('\n')}

APT Group Correlation:
${this.rawData.apt_matches.slice(0, 5).map(apt => 
    `  - ${apt.name}: ${apt.score_pct}% match (${apt.overlap_count}/${apt.group_total} techniques)`
).join('\n')}

Victim Environment:
${JSON.stringify(this.rawData.victim_profile?.interpreted || { os: 'Unknown' }, null, 2)}
`;
        
        // AI Analysis calls
        this.aiAnalysis.executive_summary = await this.callGPT(
            "You are a senior security consultant. Write a concise executive summary (2-3 paragraphs) with overall risk level, key findings, and recommended next steps. Be professional but accessible.",
            attackSummary
        );
        
        this.aiAnalysis.key_findings = await this.callGPT(
            "Identify the 5 most critical findings. Format as JSON array with: Title, Severity, Description, Evidence, MITRE_Techniques.",
            attackSummary
        );
        
        this.aiAnalysis.technical_details = await this.callGPT(
            "Provide detailed technical analysis including attack chain, most effective techniques, defensive gaps, and detection evasion success.",
            attackSummary
        );
        
        this.aiAnalysis.recommendations = await this.callGPT(
            "Provide specific, actionable recommendations. Format as JSON array with: Priority, Title, ActionSteps, ExpectedImpact.",
            attackSummary
        );
        
        this.aiAnalysis.risk_assessment = await this.callGPT(
            "Assess overall risk. Provide: Overall Risk Rating, Likelihood, Business Impact, Key Risk Factors.",
            attackSummary
        );
        
        if (this.rawData.apt_matches.length > 0) {
            this.aiAnalysis.apt_analysis = await this.callGPT(
                "Analyze APT group correlations. Provide: most likely threat actor, known TTPs that match, and threat hunting queries.",
                `APT Matches: ${JSON.stringify(this.rawData.apt_matches.slice(0, 5), null, 2)}`
            );
        }
        
        // Parse JSON responses
        try {
            this.aiAnalysis.key_findings = JSON.parse(this.aiAnalysis.key_findings);
        } catch(e) {
            this.aiAnalysis.key_findings = [{ Title: "Analysis Error", Description: this.aiAnalysis.key_findings }];
        }
        
        try {
            this.aiAnalysis.recommendations = JSON.parse(this.aiAnalysis.recommendations);
        } catch(e) {
            this.aiAnalysis.recommendations = [{ Title: "Recommendations", ActionSteps: [this.aiAnalysis.recommendations] }];
        }
    }
    
    async callGPT(systemPrompt, userData) {
        const payload = {
            model: "gpt-4o-mini",
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: userData }
            ],
            temperature: 0.7,
            max_tokens: 1500
        };
        
        return new Promise((resolve, reject) => {
            const data = JSON.stringify(payload);
            const options = {
                hostname: 'api.openai.com',
                path: '/v1/chat/completions',
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${OPENAI_API_KEY}`,
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(data)
                }
            };
            
            const req = https.request(options, (res) => {
                let responseData = '';
                res.on('data', chunk => responseData += chunk);
                res.on('end', () => {
                    try {
                        const json = JSON.parse(responseData);
                        resolve(json.choices[0].message.content);
                    } catch(e) {
                        reject(e);
                    }
                });
            });
            
            req.on('error', reject);
            req.write(data);
            req.end();
        });
    }
    
    async generateReportSections() {
        this.reportSections = {
            executive_summary: this.aiAnalysis.executive_summary,
            risk_assessment: this.aiAnalysis.risk_assessment,
            key_findings: this.aiAnalysis.key_findings,
            technical_details: this.aiAnalysis.technical_details,
            recommendations: this.aiAnalysis.recommendations,
            apt_analysis: this.aiAnalysis.apt_analysis,
            raw_stats: this.rawData.stats,
            chart_html: this.chartHTML
        };
    }
    
    async createPDFReport() {
        if (!fs.existsSync(REPORTS_DIR)) {
            fs.mkdirSync(REPORTS_DIR, { recursive: true });
        }
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const htmlPath = `${REPORTS_DIR}/report_${timestamp}.html`;
        const pdfPath = `${REPORTS_DIR}/report_${timestamp}.pdf`;
        
        // Generate HTML with charts
        const html = this.generateFullHTML();
        fs.writeFileSync(htmlPath, html);
        console.log(`✅ HTML report generated: ${htmlPath}`);
        
        // Try to generate PDF using puppeteer
        let pdfGenerated = false;
        
        if (puppeteer) {
            try {
                console.log('📄 Generating PDF with Puppeteer...');
                const browser = await puppeteer.launch({
                    headless: 'new',
                    args: ['--no-sandbox', '--disable-setuid-sandbox']
                });
                const page = await browser.newPage();
                await page.goto(`file://${htmlPath}`, { waitUntil: 'networkidle0' });
                await page.waitForTimeout(3000); // Wait for charts to render
                await page.pdf({
                    path: pdfPath,
                    format: 'A4',
                    printBackground: true,
                    margin: { top: '20mm', bottom: '20mm', left: '15mm', right: '15mm' }
                });
                await browser.close();
                console.log(`✅ PDF report generated: ${pdfPath}`);
                this.pdfPath = pdfPath;
                pdfGenerated = true;
            } catch (err) {
                console.log('⚠️  Puppeteer PDF generation failed:', err.message);
            }
        }
        
        // Try alternative with chromium headless
        if (!pdfGenerated) {
            try {
                const chromium = execSync('which chromium-browser || which chromium || which google-chrome', { encoding: 'utf8' }).trim();
                if (chromium) {
                    console.log('📄 Generating PDF with Chromium headless...');
                    execSync(`"${chromium}" --headless --disable-gpu --print-to-pdf="${pdfPath}" --no-pdf-header-footer "${htmlPath}"`, { stdio: 'inherit' });
                    console.log(`✅ PDF report generated: ${pdfPath}`);
                    this.pdfPath = pdfPath;
                    pdfGenerated = true;
                }
            } catch (err) {
                console.log('⚠️  Chromium PDF generation failed');
            }
        }
        
        if (!pdfGenerated) {
            console.log('⚠️  PDF generation failed. HTML report available at:', htmlPath);
            this.pdfPath = htmlPath;
        }
    }
    
    generateFullHTML() {
        const findingsHtml = (this.reportSections.key_findings || []).map(f => `
            <div class="finding-card ${(f.Severity || 'Medium').toLowerCase()}">
                <span class="severity-badge severity-${(f.Severity || 'Medium').toLowerCase()}">${f.Severity || 'Medium'}</span>
                <h4>${f.Title || 'Finding'}</h4>
                <p>${f.Description || ''}</p>
                ${f.Evidence ? `<p><strong>Evidence:</strong> ${f.Evidence}</p>` : ''}
                ${f.MITRE_Techniques ? `<p><strong>MITRE ATT&CK:</strong> ${f.MITRE_Techniques}</p>` : ''}
            </div>
        `).join('');
        
        const recommendationsHtml = (this.reportSections.recommendations || []).map(r => `
            <div class="recommendation">
                <h4>${r.Priority || 'Medium'} Priority: ${r.Title || 'Recommendation'}</h4>
                <p><strong>Action Steps:</strong></p>
                <ul>
                    ${(r.ActionSteps || r.actions || []).map(a => `<li>${a}</li>`).join('')}
                </ul>
                <p><strong>Expected Impact:</strong> ${r.ExpectedImpact || ''}</p>
            </div>
        `).join('');
        
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSecSim AI-Powered Penetration Test Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
            background: white;
            padding: 40px 20px;
            color: #1a2a3a;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 50px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .badge {
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            display: inline-block;
            margin-top: 15px;
            font-family: monospace;
        }
        .content { padding: 40px; }
        .section {
            margin-bottom: 40px;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 30px;
        }
        .section h2 {
            color: #4a5568;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-left: 4px solid #667eea;
            padding-left: 15px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
        }
        .stat-card .number { font-size: 2em; font-weight: bold; }
        .finding-card {
            background: #f7fafc;
            border-left: 4px solid;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        .finding-card.critical { border-left-color: #e53e3e; }
        .finding-card.high { border-left-color: #ed8936; }
        .finding-card.medium { border-left-color: #ecc94b; }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .severity-critical { background: #e53e3e; color: white; }
        .severity-high { background: #ed8936; color: white; }
        .severity-medium { background: #ecc94b; color: #1a2a3a; }
        .recommendation {
            background: #ebf8ff;
            border-left: 4px solid #3182ce;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        .recommendation h4 { color: #2c5282; margin-bottom: 10px; }
        .recommendation ul { margin-left: 20px; margin-top: 10px; }
        .footer {
            background: #f7fafc;
            padding: 20px;
            text-align: center;
            color: #718096;
            font-size: 0.85em;
        }
        pre {
            background: #f7fafc;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: monospace;
            font-size: 0.9em;
        }
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
        }
    </style>
    ${this.reportSections.chart_html}
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 WebSecSim Penetration Test Report</h1>
            <p>AI-Powered Security Assessment</p>
            <div class="badge">Report ID: WSS-${Date.now()}</div>
            <div>Generated: ${new Date().toLocaleString()}</div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="stats-grid">
                    <div class="stat-card"><div class="number">${this.rawData.stats.total_techniques}</div><div class="label">Techniques Attempted</div></div>
                    <div class="stat-card"><div class="number">${this.rawData.stats.successful}</div><div class="label">Successful</div></div>
                    <div class="stat-card"><div class="number">${this.rawData.stats.critical_alerts}</div><div class="label">Critical Alerts</div></div>
                    <div class="stat-card"><div class="number">${this.rawData.apt_matches.length || 0}</div><div class="label">APT Matches</div></div>
                </div>
                <pre>${this.reportSections.executive_summary || 'Analysis in progress...'}</pre>
            </div>
            
            <div class="section">
                <h2>⚠️ Key Findings</h2>
                ${findingsHtml || '<p>No findings generated.</p>'}
            </div>
            
            <div class="section">
                <h2>🎯 Risk Assessment</h2>
                <pre>${this.reportSections.risk_assessment || 'No risk assessment generated.'}</pre>
            </div>
            
            <div class="section">
                <h2>📈 Performance Metrics</h2>
                ${this.reportSections.chart_html}
            </div>
            
            <div class="section">
                <h2>🔧 Technical Analysis</h2>
                <pre>${this.reportSections.technical_details || 'No technical analysis generated.'}</pre>
            </div>
            
            ${this.reportSections.apt_analysis ? `
            <div class="section">
                <h2>🕵️ Threat Actor Attribution</h2>
                <pre>${this.reportSections.apt_analysis}</pre>
            </div>
            ` : ''}
            
            <div class="section">
                <h2>💡 Recommendations</h2>
                ${recommendationsHtml || '<p>No recommendations generated.</p>'}
            </div>
        </div>
        
        <div class="footer">
            <p>This report was generated automatically using GPT-4o-mini AI analysis based on actual attack data from WebSecSim C2.</p>
            <p>Report generated: ${new Date().toISOString()}</p>
        </div>
    </div>
</body>
</html>`;
    }
    
    async sendToTelegram() {
        try {
            // Read file as buffer
            const fileBuffer = fs.readFileSync(this.pdfPath);
            
            // Prepare form data
            const formData = new FormData();
            formData.append('chat_id', TELEGRAM_CHAT_ID);
            formData.append('document', new Blob([fileBuffer]), path.basename(this.pdfPath));
            formData.append('caption', `📊 WebSecSim Penetration Test Report\n\nReport ID: WSS-${Date.now()}\nGenerated: ${new Date().toLocaleString()}\n\n📈 Statistics:\n• Techniques Attempted: ${this.rawData.stats.total_techniques}\n• Successful: ${this.rawData.stats.successful}\n• Critical Alerts: ${this.rawData.stats.critical_alerts}\n• APT Matches: ${this.rawData.apt_matches.length || 0}\n\n#WebSecSim #PenetrationTest #SecurityReport`);
            
            const response = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument`, {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            if (result.ok) {
                console.log('✅ PDF report sent to Telegram successfully!');
            } else {
                console.log('❌ Failed to send to Telegram:', result.description);
            }
        } catch (error) {
            console.log('❌ Error sending to Telegram:', error.message);
        }
    }
}

// Run the generator
const generator = new AIReportGenerator();
generator.generate().catch(console.error);
