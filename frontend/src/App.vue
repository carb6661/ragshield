<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from './api'
import type { Dashboard, Finding, Rule, Scan } from './types'

const dashboard = ref<Dashboard | null>(null)
const scans = ref<Scan[]>([])
const rules = ref<Rule[]>([])
const selectedScan = ref<Scan | null>(null)
const selectedFinding = ref<Finding | null>(null)
const targetProfile = ref('demo-vulnerable')
const running = ref(false)
const loading = ref(true)
const error = ref('')
const view = ref<'dashboard' | 'controls' | 'history'>('dashboard')

const latest = computed(() => selectedScan.value ?? dashboard.value?.latest_scan ?? null)
const failedFindings = computed(() => latest.value?.findings.filter((item) => !item.passed) ?? [])
const allCategories = computed(() => {
  const source = latest.value?.findings ?? rules.value
  return [...new Set(source.map((item) => item.category))]
})

async function loadData() {
  const [stats, history, ruleSet] = await Promise.all([
    api.dashboard(),
    api.scans(),
    api.rules(),
  ])
  dashboard.value = stats
  scans.value = history
  rules.value = ruleSet
  if (!selectedScan.value) selectedScan.value = history[0] ?? stats.latest_scan
}

async function launchScan() {
  running.value = true
  error.value = ''
  try {
    const name = targetProfile.value === 'demo-hardened' ? 'Hardened RAG Baseline' : 'Vulnerable RAG Lab'
    selectedScan.value = await api.createScan(name, targetProfile.value)
    await loadData()
    view.value = 'dashboard'
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'Unable to run the evaluation.'
  } finally {
    running.value = false
  }
}

function selectScan(scan: Scan) {
  selectedScan.value = scan
  view.value = 'dashboard'
}

function severityWidth(category: string) {
  const count = latest.value?.findings.filter((item) => item.category === category && !item.passed).length ?? 0
  const total = latest.value?.findings.filter((item) => item.category === category).length || 1
  return `${Math.max(4, Math.round((count / total) * 100))}%`
}

function shortDate(value: string) {
  return new Intl.DateTimeFormat('en', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(value))
}

onMounted(async () => {
  try {
    await loadData()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'The API is unavailable.'
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark"><span></span></div>
        <div><strong>RAGShield</strong><small>SECURITY CONSOLE</small></div>
      </div>
      <nav>
        <button :class="{ active: view === 'dashboard' }" @click="view = 'dashboard'"><span>⌁</span> Overview</button>
        <button :class="{ active: view === 'controls' }" @click="view = 'controls'"><span>◇</span> Control library</button>
        <button :class="{ active: view === 'history' }" @click="view = 'history'"><span>◷</span> Scan history</button>
      </nav>
      <div class="side-label">TARGET LAB</div>
      <div class="target-status">
        <div class="pulse-dot"></div>
        <div><strong>Local demo target</strong><small>Network scanning disabled</small></div>
      </div>
      <div class="sidebar-spacer"></div>
      <div class="frameworks"><span>MITRE ATLAS</span><span>OWASP LLM</span></div>
      <div class="operator"><div class="avatar">RS</div><div><strong>Security operator</strong><small>Authorized lab mode</small></div></div>
    </aside>

    <main>
      <header>
        <div>
          <p class="eyebrow">DEFENSIVE AI SECURITY</p>
          <h1>{{ view === 'controls' ? 'Control library' : view === 'history' ? 'Evaluation history' : 'Security posture' }}</h1>
        </div>
        <div class="header-actions">
          <div class="live-chip"><span></span> ENGINE ONLINE</div>
          <button class="primary" @click="launchScan" :disabled="running">
            {{ running ? 'Evaluating…' : 'Run evaluation' }}
          </button>
        </div>
      </header>

      <div v-if="error" class="error-banner">{{ error }}</div>
      <div v-if="loading" class="loading-state"><div class="spinner"></div><span>Loading security telemetry…</span></div>

      <template v-else-if="view === 'dashboard'">
        <section class="scan-config panel">
          <div>
            <span class="panel-kicker">EVALUATION TARGET</span>
            <strong>{{ targetProfile === 'demo-vulnerable' ? 'Vulnerable RAG Lab' : 'Hardened RAG Baseline' }}</strong>
          </div>
          <div class="profile-switch">
            <button :class="{ selected: targetProfile === 'demo-vulnerable' }" @click="targetProfile = 'demo-vulnerable'">Vulnerable</button>
            <button :class="{ selected: targetProfile === 'demo-hardened' }" @click="targetProfile = 'demo-hardened'">Hardened</button>
          </div>
          <div class="scope"><span>6</span><small>CONTROLS</small></div>
          <div class="scope"><span>5</span><small>CATEGORIES</small></div>
          <div class="scope"><span>0</span><small>NETWORK CALLS</small></div>
        </section>

        <section class="metrics-grid">
          <article class="metric panel"><span>AVERAGE SCORE</span><strong>{{ dashboard?.average_score ?? 0 }}<small>/100</small></strong><em :class="(dashboard?.average_score ?? 0) >= 80 ? 'good' : 'bad'">{{ (dashboard?.average_score ?? 0) >= 80 ? 'CONTROLLED' : 'EXPOSED' }}</em></article>
          <article class="metric panel"><span>PASS RATE</span><strong>{{ dashboard?.pass_rate ?? 0 }}<small>%</small></strong><em>ALL CONTROLS</em></article>
          <article class="metric panel"><span>HIGH RISK</span><strong>{{ dashboard?.high_risk_findings ?? 0 }}</strong><em class="bad">OPEN FINDINGS</em></article>
          <article class="metric panel"><span>TOTAL SCANS</span><strong>{{ dashboard?.total_scans ?? 0 }}</strong><em>LOCAL HISTORY</em></article>
        </section>

        <section v-if="latest" class="main-grid">
          <article class="panel posture-card">
            <div class="panel-head"><div><span class="panel-kicker">LATEST ASSESSMENT</span><h2>Posture score</h2></div><span class="timestamp">{{ shortDate(latest.created_at) }}</span></div>
            <div class="score-wrap">
              <div class="score-ring" :style="{ '--score': `${latest.score * 3.6}deg` }">
                <div><strong>{{ latest.score }}</strong><small>OUT OF 100</small></div>
              </div>
              <div class="score-summary">
                <span :class="['risk-badge', latest.risk_level]">{{ latest.risk_level }} risk</span>
                <h3>{{ latest.failed ? `${latest.failed} controls require attention` : 'All controls are holding' }}</h3>
                <p>{{ latest.target_name }} completed in {{ latest.duration_ms }} ms with {{ latest.passed }} passes.</p>
              </div>
            </div>
          </article>

          <article class="panel category-card">
            <div class="panel-head"><div><span class="panel-kicker">ATTACK SURFACE</span><h2>Risk by category</h2></div></div>
            <div class="risk-bars">
              <div v-for="category in allCategories" :key="category" class="risk-row">
                <div><span>{{ category }}</span><small>{{ latest.findings.filter(f => f.category === category && !f.passed).length }} open</small></div>
                <div class="bar"><i :style="{ width: severityWidth(category) }"></i></div>
              </div>
            </div>
          </article>
        </section>

        <section v-if="latest" class="panel findings-panel">
          <div class="panel-head"><div><span class="panel-kicker">EVIDENCE</span><h2>Control results</h2></div><a :href="api.reportUrl(latest.id)" class="text-link">Export report ↓</a></div>
          <div class="finding-table">
            <div class="table-head"><span>CONTROL</span><span>CATEGORY</span><span>SEVERITY</span><span>RESULT</span><span>LATENCY</span></div>
            <button v-for="finding in latest.findings" :key="finding.rule_id" class="finding-row" @click="selectedFinding = finding">
              <span><b>{{ finding.rule_id }}</b>{{ finding.title }}</span>
              <span>{{ finding.category }}</span>
              <span><i :class="['severity-dot', finding.severity]"></i>{{ finding.severity }}</span>
              <span :class="finding.passed ? 'pass' : 'fail'">{{ finding.passed ? 'PASS' : 'FAIL' }}</span>
              <span>{{ finding.latency_ms }} ms</span>
            </button>
          </div>
        </section>

        <section v-else class="empty panel"><div class="empty-icon">⌁</div><h2>No evaluations yet</h2><p>Run the deterministic local target to establish a security baseline.</p><button class="primary" @click="launchScan">Run first evaluation</button></section>
      </template>

      <section v-else-if="view === 'controls'" class="control-grid">
        <article v-for="rule in rules" :key="rule.id" class="panel control-card">
          <div class="control-top"><span>{{ rule.id }}</span><i :class="['severity-label', rule.severity]">{{ rule.severity }}</i></div>
          <h2>{{ rule.title }}</h2><p>{{ rule.description }}</p>
          <div class="mapping"><small>FRAMEWORK MAPPING</small><span>{{ rule.owasp_mapping }}</span><span v-if="rule.atlas_technique">{{ rule.atlas_technique }}</span></div>
          <div class="mitigation"><small>RECOMMENDED CONTROL</small><p>{{ rule.mitigation }}</p></div>
        </article>
      </section>

      <section v-else class="panel history-panel">
        <div class="panel-head"><div><span class="panel-kicker">AUDIT TRAIL</span><h2>Completed evaluations</h2></div><span class="timestamp">{{ scans.length }} records</span></div>
        <button v-for="scan in scans" :key="scan.id" class="history-row" @click="selectScan(scan)">
          <span :class="['history-score', scan.risk_level]">{{ scan.score }}</span>
          <span><strong>{{ scan.target_name }}</strong><small>{{ scan.target_profile }} · {{ scan.id.slice(0, 8) }}</small></span>
          <span>{{ scan.passed }} passed</span><span>{{ scan.failed }} failed</span><time>{{ shortDate(scan.created_at) }}</time><b>→</b>
        </button>
        <div v-if="!scans.length" class="empty compact"><p>No scan history available.</p></div>
      </section>
    </main>

    <div v-if="selectedFinding" class="drawer-backdrop" @click.self="selectedFinding = null">
      <aside class="finding-drawer">
        <button class="close" @click="selectedFinding = null">×</button>
        <span class="panel-kicker">{{ selectedFinding.rule_id }} · {{ selectedFinding.category }}</span>
        <h2>{{ selectedFinding.title }}</h2>
        <span :class="['risk-badge', selectedFinding.severity]">{{ selectedFinding.severity }} severity</span>
        <div class="drawer-section"><small>OBSERVED EVIDENCE</small><p>{{ selectedFinding.evidence }}</p></div>
        <div class="drawer-section"><small>FRAMEWORK MAPPING</small><p>{{ selectedFinding.mapping }}</p></div>
        <div class="drawer-section"><small>REMEDIATION</small><p>{{ selectedFinding.remediation }}</p></div>
      </aside>
    </div>
  </div>
</template>

