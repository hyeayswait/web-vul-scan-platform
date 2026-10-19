import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import axios from 'axios'
import App from './App.vue'

const app = createApp(App)

// 通过 Vite 代理走 /api，避免跨域；开发期 target 在 vite.config.js 里
axios.defaults.baseURL = '/api'

// 请求拦截器：自动带上 JWT
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// 响应拦截器：401 时清掉 token 回到登录态
axios.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response && err.response.status === 401) {
      localStorage.removeItem('token')
      location.reload()
    }
    return Promise.reject(err)
  }
)

app.use(ElementPlus, { locale: zhCn })
app.mount('#app')
