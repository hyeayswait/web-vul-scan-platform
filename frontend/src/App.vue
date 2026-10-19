<template>
  <div class="page">
    <!-- 未登录：登录 / 注册 -->
    <div v-if="!token" class="auth-wrap">
      <el-card class="auth-card">
        <h2 style="text-align:center">Web 资产探测与漏洞巡检平台</h2>
        <el-tabs v-model="tab">
          <el-tab-pane label="登录" name="login">
            <el-form :model="loginForm" label-width="60px">
              <el-form-item label="账号">
                <el-input v-model="loginForm.username" placeholder="请输入用户名" />
              </el-form-item>
              <el-form-item label="密码">
                <el-input v-model="loginForm.password" type="password" placeholder="请输入密码" @keyup.enter="onLogin" />
              </el-form-item>
              <el-button type="primary" style="width:100%" @click="onLogin">登 录</el-button>
            </el-form>
          </el-tab-pane>
          <el-tab-pane label="注册" name="reg">
            <el-form :model="regForm" label-width="60px">
              <el-form-item label="账号">
                <el-input v-model="regForm.username" placeholder="设置用户名" />
              </el-form-item>
              <el-form-item label="密码">
                <el-input v-model="regForm.password" type="password" placeholder="设置密码" />
              </el-form-item>
              <el-button type="success" style="width:100%" @click="onRegister">注 册</el-button>
            </el-form>
          </el-tab-pane>
        </el-tabs>
        <p class="warn">⚠️ 本平台仅用于授权靶机自测，禁止扫描未授权资产。</p>
      </el-card>
    </div>

    <!-- 已登录：主界面 -->
    <div v-else>
      <el-header class="header">
        <span>Web 资产探测与漏洞巡检平台</span>
        <span>
          <el-button link @click="openAiConfig">🤖 AI 设置</el-button>
          {{ username }}
          <el-button link @click="logout">退出</el-button>
        </span>
      </el-header>

      <el-container class="main">
        <!-- 资产 -->
        <el-card shadow="never">
          <template #header><b>资产管理</b></template>
          <el-form :model="assetForm" inline>
            <el-form-item label="资产名称">
              <el-input v-model="assetForm.name" placeholder="如：本地 DVWA" />
            </el-form-item>
            <el-form-item label="目标地址">
              <el-input v-model="assetForm.target" style="width:320px"
                        placeholder="如：http://127.0.0.1:8080" />
            </el-form-item>
            <el-button type="primary" @click="addAsset">添加资产</el-button>
          </el-form>
          <el-table :data="assets" border size="small">
            <el-table-column prop="id" label="ID" width="60" />
            <el-table-column prop="name" label="资产名称" />
            <el-table-column prop="target" label="目标地址" />
            <el-table-column label="操作" width="220">
              <template #default="scope">
                <el-button size="small" type="success" @click="startScan(scope.row.id)">启动扫描</el-button>
                <el-button size="small" type="danger" @click="delAsset(scope.row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- 任务 -->
        <el-card shadow="never" style="margin-top:16px">
          <template #header><b>扫描任务</b></template>
          <el-table :data="tasks" border size="small">
            <el-table-column prop="id" label="任务ID" width="80" />
            <el-table-column prop="asset_target" label="目标" />
            <el-table-column prop="asset_name" label="资产名称" />
            <el-table-column prop="create_time" label="创建时间" width="170" />
            <el-table-column label="状态" width="100">
              <template #default="scope">
                <el-tag :type="statusType(scope.row.status)">{{ statusText(scope.row.status) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="进度" width="180">
              <template #default="scope">
                <el-progress :percentage="scope.row.progress" />
              </template>
            </el-table-column>
            <el-table-column label="操作" width="220">
              <template #default="scope">
                <el-button size="small" @click="showVul(scope.row.id)">查看漏洞</el-button>
                <el-button size="small" type="primary" @click="exportReport(scope.row.id)">导出PDF</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-container>

      <!-- 漏洞详情弹窗 -->
      <el-dialog v-model="vulDialog" title="漏洞详情" width="75%">
        <el-table :data="vuls" border size="small">
          <el-table-column prop="vul_name" label="漏洞名称" width="200" />
          <el-table-column prop="level" label="等级" width="100">
            <template #default="scope">
              <el-tag :type="levelType(scope.row.level)">{{ levelText(scope.row.level) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="desc" label="描述" />
        </el-table>

        <div style="margin-top:16px">
          <el-alert :closable="false" type="info" style="margin-bottom:10px"
                    :title="`AI 引擎：${aiStatus.engine}（${aiStatus.enabled ? '已配置大模型' : '未配置 Key，使用本地规则模板'}）`" />
          <el-button type="primary" :loading="aiLoading" @click="askAiExplain">
            🤖 AI 解读漏洞 & 修复建议
          </el-button>
          <el-button :loading="aiLoading" @click="askAiSuggest">
            🧭 AI 下一步巡检建议
          </el-button>
          <el-card v-if="aiResult" shadow="never" style="margin-top:12px;background:#f6f9fc">
            <pre style="white-space:pre-wrap;font-family:inherit;margin:0">{{ aiResult }}</pre>
          </el-card>
        </div>

        <div ref="chartRef" style="width:100%;height:300px;margin-top:20px"></div>
      </el-dialog>

      <!-- AI 设置弹窗 -->
      <el-dialog v-model="aiConfigDialog" title="AI 辅助分析设置" width="560px">
        <el-alert type="info" :closable="false" style="margin-bottom:12px"
                  title="兼容任何 OpenAI 接口（DeepSeek / 通义 / 智谱 / Kimi / 本地 Ollama）。Key 仅保存在你自己的账号下，不在前端回显完整内容。留空则使用本地规则模板。" />
        <el-form :model="aiConfigForm" label-width="100px">
          <el-form-item label="API Key">
            <el-input v-model="aiConfigForm.ai_key" type="password"
                      :placeholder="aiConfigForm.has_key ? '已配置，输入新 Key 覆盖；填 KEEP 保留原值' : 'sk-...'" />
          </el-form-item>
          <el-form-item label="Base URL">
            <el-input v-model="aiConfigForm.ai_base_url"
                      placeholder="https://api.deepseek.com/v1" />
          </el-form-item>
          <el-form-item label="模型名">
            <el-input v-model="aiConfigForm.ai_model"
                      placeholder="deepseek-chat / qwen-plus / gpt-3.5-turbo" />
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="aiConfigDialog = false">取消</el-button>
          <el-button type="primary" @click="saveAiConfig">保存</el-button>
        </template>
      </el-dialog>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, nextTick } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import * as echarts from 'echarts'

const token = ref(localStorage.getItem('token') || '')
const username = ref(localStorage.getItem('username') || '')
const tab = ref('login')

const loginForm = ref({ username: '', password: '' })
const regForm = ref({ username: '', password: '' })
const assetForm = ref({ name: '', target: '' })
const assets = ref([])
const tasks = ref([])
const vuls = ref([])
const vulDialog = ref(false)
const chartRef = ref(null)
const currentTaskId = ref(null)
const aiResult = ref("")
const aiLoading = ref(false)
const aiStatus = ref({ enabled: false, engine: "local-rules" })
const aiConfigDialog = ref(false)
const aiConfigForm = ref({ ai_key: "", ai_base_url: "", ai_model: "", has_key: false })

let timer = null

// ---------- 认证 ----------
const onLogin = async () => {
  try {
    const { data } = await axios.post('/auth/login', loginForm.value)
    token.value = data.token
    username.value = data.username
    localStorage.setItem('token', data.token)
    localStorage.setItem('username', data.username)
    ElMessage.success('登录成功')
    await refreshAll()
  } catch (e) {
    ElMessage.error(e.response?.data?.msg || '登录失败')
  }
}

const onRegister = async () => {
  try {
    await axios.post('/auth/register', regForm.value)
    ElMessage.success('注册成功，请登录')
    tab.value = 'login'
    loginForm.value.username = regForm.value.username
  } catch (e) {
    ElMessage.error(e.response?.data?.msg || '注册失败')
  }
}

const logout = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('username')
  token.value = ''
  username.value = ''
}

// ---------- 资产 ----------
const loadAssets = async () => {
  const { data } = await axios.get('/asset/list')
  assets.value = data
}
const addAsset = async () => {
  if (!assetForm.value.target) return ElMessage.warning('请填写目标地址')
  await axios.post('/asset/add', assetForm.value)
  ElMessage.success('资产已添加')
  assetForm.value = { name: '', target: '' }
  loadAssets()
}
const delAsset = async (id) => {
  await axios.delete(`/asset/del/${id}`)
  ElMessage.success('已删除')
  loadAssets()
}

// ---------- 任务 ----------
const loadTasks = async () => {
  const { data } = await axios.get('/task/list')
  tasks.value = data
}
const startScan = async (aid) => {
  await axios.post('/task/start', { asset_id: aid })
  ElMessage.success('扫描任务已启动')
  loadTasks()
}

// ---------- 漏洞 & 报告 ----------
const showVul = async (taskId) => {
  currentTaskId.value = taskId
  aiResult.value = ""
  const { data } = await axios.get(`/vul/list/${taskId}`)
  vuls.value = data
  vulDialog.value = true
  await nextTick()
  renderChart()
}

const renderChart = () => {
  if (!chartRef.value) return
  const chart = echarts.init(chartRef.value)
  const c = { high: 0, medium: 0, low: 0 }
  vuls.value.forEach((v) => { if (c[v.level] !== undefined) c[v.level]++ })
  chart.setOption({
    title: { text: '漏洞等级统计', left: 'center' },
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [{
      type: 'pie', radius: '55%',
      data: [
        { name: '高危', value: c.high },
        { name: '中危', value: c.medium },
        { name: '低危', value: c.low },
      ]
    }]
  })
}

const exportReport = async (taskId) => {
  const res = await axios.get(`/report/export/${taskId}`, { responseType: 'blob' })
  const url = URL.createObjectURL(new Blob([res.data]))
  const a = document.createElement('a')
  a.href = url
  a.download = `vul_report_task_${taskId}.pdf`
  a.click()
  URL.revokeObjectURL(url)
  ElMessage.success('报告已导出')
}

// ---------- AI 辅助 ----------
const askAiExplain = async () => {
  aiLoading.value = true
  try {
    const { data } = await axios.post(`/ai/explain/${currentTaskId.value}`)
    aiResult.value = `【${data.engine}】\n\n${data.text}`
  } catch (e) {
    ElMessage.error('AI 解读失败')
  } finally {
    aiLoading.value = false
  }
}
const askAiSuggest = async () => {
  aiLoading.value = true
  try {
    const { data } = await axios.post(`/ai/suggest/${currentTaskId.value}`)
    aiResult.value = `【${data.engine}】\n\n${data.text}`
  } catch (e) {
    ElMessage.error('AI 建议获取失败')
  } finally {
    aiLoading.value = false
  }
}
const loadAiStatus = async () => {
  try {
    const { data } = await axios.get('/ai/status')
    aiStatus.value = data
  } catch (e) { /* 未登录时忽略 */ }
}

const openAiConfig = async () => {
  const { data } = await axios.get('/ai/config')
  aiConfigForm.value = {
    ai_key: "",
    ai_base_url: data.ai_base_url || "",
    ai_model: data.ai_model || "",
    has_key: data.has_key,
  }
  aiConfigDialog.value = true
}

const saveAiConfig = async () => {
  const payload = {
    ai_base_url: aiConfigForm.value.ai_base_url,
    ai_model: aiConfigForm.value.ai_model,
  }
  // 如果用户没动 Key 输入框但已有 Key，传 KEEP 保留
  if (aiConfigForm.has_key && !aiConfigForm.ai_key) {
    payload.ai_key = "KEEP"
  } else {
    payload.ai_key = aiConfigForm.value.ai_key
  }
  await axios.post('/ai/config', payload)
  ElMessage.success('AI 配置已保存')
  aiConfigDialog.value = false
  await loadAiStatus()
}

// ---------- 工具 ----------
const statusType = (s) => ({ pending: 'info', running: 'warning', finish: 'success', failed: 'danger' }[s] || '')
const statusText = (s) => ({ pending: '排队中', running: '扫描中', finish: '已完成', failed: '失败' }[s] || s)
const levelType = (l) => ({ high: 'danger', medium: 'warning', low: 'info' }[l] || '')
const levelText = (l) => ({ high: '高危', medium: '中危', low: '低危' }[l] || l)

const refreshAll = async () => {
  await Promise.all([loadAssets(), loadTasks()])
}

onMounted(() => {
  if (token.value) {
    refreshAll()
    loadAiStatus()
    // 每 3 秒刷新任务进度
    timer = setInterval(loadTasks, 3000)
  }
})
onBeforeUnmount(() => timer && clearInterval(timer))
</script>

<style>
body { margin: 0; background: #f0f2f5; }
.header {
  display: flex; justify-content: space-between; align-items: center;
  background: #1f2d3d; color: #fff; padding: 0 24px; font-size: 16px;
}
.header .el-button { color: #fff; }
.main { padding: 16px 24px; }
.auth-wrap { display: flex; justify-content: center; padding-top: 8vh; }
.auth-card { width: 420px; }
.warn { color: #e6a23c; font-size: 12px; text-align: center; margin-top: 12px; }
</style>
