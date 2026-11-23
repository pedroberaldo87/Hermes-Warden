/**
 * Hermes Warden: desktop half.
 *
 * - A lock tab (sidebar row + full page at /warden): is the Bitwarden CLI installed, is it
 *   logged in, is the vault unlocked, every setup step with a button, a link to the site,
 *   settings, a vault browser that copies secrets straight to the clipboard, and a generator.
 * - A lock chip in the status bar that also runs the dialog host: it polls the plugin backend
 *   for masked dialogs the agent opened (unlock, login with 2FA, "type a secret", confirm)
 *   and for secrets the agent delivered (clipboard / masked reveal). Values typed here go to
 *   the plugin backend and from there to `bw`; they never enter the conversation.
 *
 * Backend: dashboard/plugin_api.py, reached with ctx.rest (namespaced /api/plugins/hermes-warden).
 */
import {
  Badge,
  Button,
  Codicon,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  PALETTE_AREA,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  STATUSBAR_AREAS,
  TITLEBAR_AREAS,
  SearchField,
  SegmentedControl,
  StatusDot,
  host,
  useQuery,
  useQueryClient,
  writeClipboardText
} from '@hermes/plugin-sdk'
import { jsx, jsxs, Fragment } from 'react/jsx-runtime'
import { useEffect, useRef, useState } from 'react'

const ID = 'hermes-warden'
const ROUTE = '/warden'
const STATE_KEY = [ID, 'state']
const ITEMS_KEY = [ID, 'items']
/* One id per window, kept across reloads of that window, so a dialog it opened is not orphaned. */
const SURFACE = (() => {
  const fresh = 'desktop-' + Math.random().toString(36).slice(2, 12)
  try {
    const kept = window.sessionStorage.getItem('hermes-warden.surface')
    if (kept && /^desktop-[a-z0-9]{6,20}$/.test(kept)) return kept
    window.sessionStorage.setItem('hermes-warden.surface', fresh)
  } catch {
    /* storage unavailable: per-load id */
  }
  return fresh
})()
const OFFICIAL_SERVERS = ['https://vault.bitwarden.com', 'https://vault.bitwarden.eu']

let rest = null

/* ------------------------------------------------------------------ i18n
   Strings for every Hermes display language, registered with the Desktop's plugin i18n: the
   language follows Hermes (display.language), and a missing key falls back to English. */

const STRINGS = {
  en: {
    title: 'Hermes Warden',
    subtitle: 'Bitwarden for Hermes. Secrets never enter the conversation.',
    s_not_installed: 'Not installed', s_unauthenticated: 'Logged out', s_locked: 'Locked', s_unlocked: 'Unlocked',
    s_unknown: 'Unknown',
    step_install: 'Install the Bitwarden CLI', step_install_d: 'The `bw` command, on the machine running Hermes.',
    step_server: 'Choose the server', step_server_d: 'bitwarden.com (US), bitwarden.eu or your self-hosted URL.',
    step_login: 'Log in', step_login_d: 'E-mail, master password and two-step code, in a masked dialog.',
    step_unlock: 'Unlock the vault', step_unlock_d: 'The session key stays in memory and locks itself when idle.',
    install: 'Install Bitwarden CLI', installing: 'Installing…', via: 'via', no_installer: 'No installer for this system: use the download page.', official_build: 'official Bitwarden build',
    download: 'Download page', docs: 'CLI docs', site: 'bitwarden.com',
    login: 'Log in', unlock: 'Unlock', lock: 'Lock', logout: 'Log out', sync: 'Sync', set: 'Set',
    done: 'Done', account: 'Account', server: 'Server', last_sync: 'Last sync', version: 'Version',
    autolock_in: 'Auto-lock in', settings: 'Settings', autolock: 'Auto-lock', clip_clear: 'Clear clipboard',
    dialogs: 'Dialogs', d_auto: 'Auto', d_desktop: 'This app', d_host: 'Host dialog (macOS)', off: 'Off',
    vault: 'Vault', search: 'Search items', no_items: 'Nothing found', locked_hint: 'Unlock to browse the vault.', loading_vault: 'Loading vault…',
    copy_user: 'Copy username', username: 'Username', copy_pass: 'Copy password', btn_user: 'User', btn_pass: 'Password', copy_totp: 'Copy TOTP code', reveal: 'Show',
    copied: (label, s) => `${label} copied${s ? ` · clears in ${s}s` : ''}`, copy_failed: 'Could not write the clipboard', copied_noclear: label => `${label} copied · clear the clipboard yourself when done`,
    generator: 'Generator', generate: 'Generate', copy: 'Copy', length: 'Length', passphrase: 'Passphrase', password: 'Password',
    serve: 'Local REST API (bw serve)', serve_d: 'On 127.0.0.1 only. While it runs, any program on this computer can read your vault. Stops when the vault locks.', start: 'Start', stop: 'Stop',
    agent: 'Ask the agent', agent_d: 'Try: "unlock Bitwarden", "copy my GitHub password", "create a login for example.com with a strong password", "which passwords are weak or reused?", "export the vault encrypted".',
    // dialogs
    d_unlock: 'Unlock Bitwarden', d_login: 'Log in to Bitwarden', d_secret: 'Type a secret', d_confirm: 'Confirm',
    master: 'Master password', email: 'E-mail', code2fa: 'Two-step login code', code_device: 'New device code (sent by e-mail)',
    apikey: 'Use API key instead', client_id: 'client_id', client_secret: 'client_secret',
    value: 'Value', cancel: 'Cancel', confirm: 'Confirm', ok: 'OK', send: 'Continue',
    safe_note: 'Typed here, sent only to Bitwarden on the Hermes host. The agent never sees it.',
    secret_note: 'The agent will not see this value, but it can use it in steps you approve. Never type your master password here.',
    asked_by: 'Requested by the agent', reveal_title: 'Secret from your vault', hide: 'Hide',
    reveal_note: 'Close this window when done. It is not stored anywhere.', attempts: n => `Attempt ${n} failed`,
    method: 'Two-step method', m_auth: 'Authenticator', m_email: 'E-mail', m_yubi: 'YubiKey',
    open: 'Open Hermes Warden', err: 'Error', working_unlock: 'Unlocking…', working_login: 'Logging in…'
  },
  zh: {
    title: "Hermes Warden",
    subtitle: "Hermes 的 Bitwarden。机密绝不会进入对话。",
    s_not_installed: "未安装",
    s_unauthenticated: "已登出",
    s_locked: "已锁定",
    s_unlocked: "已解锁",
    s_unknown: "未知",
    step_install: "安装 Bitwarden CLI",
    step_install_d: "运行 Hermes 的设备上的 `bw` 命令。",
    step_server: "选择服务器",
    step_server_d: "bitwarden.com(美国)、bitwarden.eu 或您自托管的网址。",
    step_login: "登录",
    step_login_d: "在遮蔽的对话框中输入电子邮件、主密码和两步登录验证码。",
    step_unlock: "解锁密码库",
    step_unlock_d: "会话密钥仅保存在内存中,闲置时自动锁定。",
    install: "安装 Bitwarden CLI",
    installing: "正在安装…",
    via: "通过",
    no_installer: "此系统没有可用的安装程序:请使用下载页面。",
    official_build: "Bitwarden 官方版本",
    download: "下载页面",
    docs: "CLI 文档",
    site: "bitwarden.com",
    login: "登录",
    unlock: "解锁",
    lock: "锁定",
    logout: "退出登录",
    sync: "同步",
    set: "设置",
    done: "完成",
    account: "账户",
    server: "服务器",
    last_sync: "上次同步",
    version: "版本",
    autolock_in: "自动锁定倒计时",
    settings: "设置",
    autolock: "自动锁定",
    clip_clear: "清除剪贴板",
    dialogs: "对话框",
    d_auto: "自动",
    d_desktop: "本应用",
    d_host: "主机对话框 (macOS)",
    off: "关闭",
    vault: "密码库",
    search: "搜索项目",
    no_items: "未找到任何内容",
    locked_hint: "解锁后即可浏览密码库。",
    loading_vault: "正在加载密码库…",
    copy_user: "复制用户名",
    username: "用户名",
    copy_pass: "复制密码",
    btn_user: "用户名",
    btn_pass: "密码",
    copy_totp: "复制 TOTP 代码",
    reveal: "显示",
    copied: (label, s) => (s ? `${label}已复制 · ${s} 秒后清除` : `${label}已复制`),
    copy_failed: "无法写入剪贴板",
    copied_noclear: label => `${label}已复制 · 用完后请自行清除剪贴板`,
    generator: "生成器",
    generate: "生成",
    copy: "复制",
    length: "长度",
    passphrase: "密码短语",
    password: "密码",
    serve: "本地 REST API (bw serve)",
    serve_d: "仅限 127.0.0.1。运行期间,此电脑上的任何程序都能读取您的密码库。密码库锁定时自动停止。",
    start: "启动",
    stop: "停止",
    agent: "询问智能体",
    agent_d: "试试:“解锁 Bitwarden”、“复制我的 GitHub 密码”、“为 example.com 创建登录项并使用强密码”、“哪些密码太弱或重复使用?”、“导出加密的密码库”。",
    d_unlock: "解锁 Bitwarden",
    d_login: "登录 Bitwarden",
    d_secret: "输入机密",
    d_confirm: "确认",
    master: "主密码",
    email: "电子邮件",
    code2fa: "两步登录验证码",
    code_device: "新设备验证码(通过电子邮件发送)",
    apikey: "改用 API 密钥",
    client_id: "client_id",
    client_secret: "client_secret",
    value: "值",
    cancel: "取消",
    confirm: "确认",
    ok: "确定",
    send: "继续",
    safe_note: "在此输入,仅发送给 Hermes 主机上的 Bitwarden。智能体不会看到。",
    secret_note: "智能体看不到此值,但可在您批准的步骤中使用。切勿在此输入主密码。",
    asked_by: "由智能体请求",
    reveal_title: "来自密码库的机密",
    hide: "隐藏",
    reveal_note: "完成后请关闭此窗口。内容不会存储在任何位置。",
    attempts: n => `第 ${n} 次尝试失败`,
    method: "两步登录方式",
    m_auth: "验证器",
    m_email: "电子邮件",
    m_yubi: "YubiKey",
    open: "打开 Hermes Warden",
    err: "错误",
    working_unlock: "正在解锁…",
    working_login: "正在登录…"
  },
  'zh-hant': {
    title: "Hermes Warden",
    subtitle: "Hermes 專用的 Bitwarden。機密絕不會進入對話。",
    s_not_installed: "未安裝",
    s_unauthenticated: "已登出",
    s_locked: "已鎖定",
    s_unlocked: "已解鎖",
    s_unknown: "未知",
    step_install: "安裝 Bitwarden CLI",
    step_install_d: "執行 Hermes 的電腦上的 `bw` 指令。",
    step_server: "選擇伺服器",
    step_server_d: "bitwarden.com(美國)、bitwarden.eu 或您自行架設的網址。",
    step_login: "登入",
    step_login_d: "在遮蔽的對話框中輸入電子郵件、主密碼和兩步驟登入驗證碼。",
    step_unlock: "解鎖密碼庫",
    step_unlock_d: "工作階段金鑰僅保留在記憶體中,閒置時自動鎖定。",
    install: "安裝 Bitwarden CLI",
    installing: "安裝中…",
    via: "透過",
    no_installer: "此系統沒有可用的安裝程式:請使用下載頁面。",
    official_build: "Bitwarden 官方版本",
    download: "下載頁面",
    docs: "CLI 文件",
    site: "bitwarden.com",
    login: "登入",
    unlock: "解鎖",
    lock: "鎖定",
    logout: "登出",
    sync: "同步",
    set: "設定",
    done: "完成",
    account: "帳戶",
    server: "伺服器",
    last_sync: "上次同步",
    version: "版本",
    autolock_in: "自動鎖定倒數",
    settings: "設定",
    autolock: "自動鎖定",
    clip_clear: "清除剪貼簿",
    dialogs: "對話框",
    d_auto: "自動",
    d_desktop: "此應用程式",
    d_host: "主機對話框 (macOS)",
    off: "關閉",
    vault: "密碼庫",
    search: "搜尋項目",
    no_items: "找不到任何內容",
    locked_hint: "解鎖後即可瀏覽密碼庫。",
    loading_vault: "正在載入密碼庫…",
    copy_user: "複製使用者名稱",
    username: "使用者名稱",
    copy_pass: "複製密碼",
    btn_user: "使用者",
    btn_pass: "密碼",
    copy_totp: "複製 TOTP 代碼",
    reveal: "顯示",
    copied: (label, s) => (s ? `已複製${label} · ${s} 秒後清除` : `已複製${label}`),
    copy_failed: "無法寫入剪貼簿",
    copied_noclear: label => `已複製${label} · 用完後請自行清除剪貼簿`,
    generator: "產生器",
    generate: "產生",
    copy: "複製",
    length: "長度",
    passphrase: "密碼短語",
    password: "密碼",
    serve: "本機 REST API (bw serve)",
    serve_d: "僅限 127.0.0.1。執行期間,這台電腦上的任何程式都能讀取您的密碼庫。密碼庫鎖定時自動停止。",
    start: "啟動",
    stop: "停止",
    agent: "詢問代理程式",
    agent_d: "試試:「解鎖 Bitwarden」、「複製我的 GitHub 密碼」、「為 example.com 建立登入項目並使用強式密碼」、「哪些密碼太弱或重複使用?」、「匯出加密的密碼庫」。",
    d_unlock: "解鎖 Bitwarden",
    d_login: "登入 Bitwarden",
    d_secret: "輸入機密",
    d_confirm: "確認",
    master: "主密碼",
    email: "電子郵件",
    code2fa: "兩步驟登入驗證碼",
    code_device: "新裝置驗證碼(透過電子郵件傳送)",
    apikey: "改用 API 金鑰",
    client_id: "client_id",
    client_secret: "client_secret",
    value: "值",
    cancel: "取消",
    confirm: "確認",
    ok: "確定",
    send: "繼續",
    safe_note: "在此輸入,僅傳送給 Hermes 主機上的 Bitwarden。代理程式不會看到。",
    secret_note: "代理程式看不到此值,但可在您核准的步驟中使用。請勿在此輸入主密碼。",
    asked_by: "由代理程式要求",
    reveal_title: "來自密碼庫的機密",
    hide: "隱藏",
    reveal_note: "完成後請關閉此視窗。內容不會儲存在任何地方。",
    attempts: n => `第 ${n} 次嘗試失敗`,
    method: "兩步驟登入方式",
    m_auth: "驗證器",
    m_email: "電子郵件",
    m_yubi: "YubiKey",
    open: "開啟 Hermes Warden",
    err: "錯誤",
    working_unlock: "解鎖中…",
    working_login: "登入中…"
  },
  ja: {
    title: "Hermes Warden",
    subtitle: "Hermes のための Bitwarden。シークレットが会話に入ることはありません。",
    s_not_installed: "未インストール",
    s_unauthenticated: "ログアウト済み",
    s_locked: "ロック中",
    s_unlocked: "ロック解除済み",
    s_unknown: "不明",
    step_install: "Bitwarden CLI をインストール",
    step_install_d: "Hermes を実行しているマシン上の `bw` コマンド。",
    step_server: "サーバーを選択",
    step_server_d: "bitwarden.com(米国)、bitwarden.eu、またはセルフホストの URL。",
    step_login: "ログイン",
    step_login_d: "メールアドレス、マスターパスワード、2段階認証コードをマスクされたダイアログで入力します。",
    step_unlock: "保管庫のロックを解除",
    step_unlock_d: "セッションキーはメモリ内にのみ保持され、アイドル時に自動でロックされます。",
    install: "Bitwarden CLI をインストール",
    installing: "インストール中…",
    via: "方法:",
    no_installer: "このシステム用のインストーラーはありません。ダウンロードページをご利用ください。",
    official_build: "Bitwarden 公式ビルド",
    download: "ダウンロードページ",
    docs: "CLI ドキュメント",
    site: "bitwarden.com",
    login: "ログイン",
    unlock: "ロック解除",
    lock: "ロック",
    logout: "ログアウト",
    sync: "同期",
    set: "設定",
    done: "完了",
    account: "アカウント",
    server: "サーバー",
    last_sync: "最終同期",
    version: "バージョン",
    autolock_in: "自動ロックまで",
    settings: "設定",
    autolock: "自動ロック",
    clip_clear: "クリップボードをクリア",
    dialogs: "ダイアログ",
    d_auto: "自動",
    d_desktop: "このアプリ",
    d_host: "ホストのダイアログ (macOS)",
    off: "オフ",
    vault: "保管庫",
    search: "アイテムを検索",
    no_items: "見つかりません",
    locked_hint: "ロックを解除すると保管庫を閲覧できます。",
    loading_vault: "保管庫を読み込み中…",
    copy_user: "ユーザー名をコピー",
    username: "ユーザー名",
    copy_pass: "パスワードをコピー",
    btn_user: "ユーザー",
    btn_pass: "パスワード",
    copy_totp: "TOTP コードをコピー",
    reveal: "表示",
    copied: (label, s) => (s ? `${label}をコピーしました · ${s}秒後にクリア` : `${label}をコピーしました`),
    copy_failed: "クリップボードに書き込めませんでした",
    copied_noclear: label => `${label}をコピーしました · 使い終わったらクリップボードを自分でクリアしてください`,
    generator: "ジェネレーター",
    generate: "生成",
    copy: "コピー",
    length: "長さ",
    passphrase: "パスフレーズ",
    password: "パスワード",
    serve: "ローカル REST API (bw serve)",
    serve_d: "127.0.0.1 のみ。実行中は、このコンピューター上のどのプログラムからも保管庫を読み取れます。保管庫がロックされると停止します。",
    start: "開始",
    stop: "停止",
    agent: "エージェントに頼む",
    agent_d: "例:「Bitwarden のロックを解除して」「GitHub のパスワードをコピーして」「example.com のログインを強力なパスワードで作成して」「弱い、または使い回しのパスワードはどれ?」「保管庫を暗号化してエクスポートして」",
    d_unlock: "Bitwarden のロックを解除",
    d_login: "Bitwarden にログイン",
    d_secret: "シークレットを入力",
    d_confirm: "確認",
    master: "マスターパスワード",
    email: "メールアドレス",
    code2fa: "2段階認証コード",
    code_device: "新しいデバイスのコード(メールで送信)",
    apikey: "API キーを使用",
    client_id: "client_id",
    client_secret: "client_secret",
    value: "値",
    cancel: "キャンセル",
    confirm: "確認",
    ok: "OK",
    send: "続行",
    safe_note: "ここに入力した内容は、Hermes ホスト上の Bitwarden にのみ送信されます。エージェントには表示されません。",
    secret_note: "エージェントにはこの値は見えませんが、承認した手順で使用できます。マスターパスワードはここに入力しないでください。",
    asked_by: "エージェントからのリクエスト",
    reveal_title: "保管庫のシークレット",
    hide: "非表示",
    reveal_note: "終わったらこのウィンドウを閉じてください。どこにも保存されません。",
    attempts: n => `${n} 回目の試行に失敗しました`,
    method: "2段階認証の方法",
    m_auth: "認証アプリ",
    m_email: "メール",
    m_yubi: "YubiKey",
    open: "Hermes Warden を開く",
    err: "エラー",
    working_unlock: "ロック解除中…",
    working_login: "ログイン中…"
  },
  ar: {
    title: "Hermes Warden",
    subtitle: "Bitwarden لـ Hermes. لا تدخل الأسرار المحادثة أبدًا.",
    s_not_installed: "غير مثبّت",
    s_unauthenticated: "تم تسجيل الخروج",
    s_locked: "مقفل",
    s_unlocked: "غير مقفل",
    s_unknown: "غير معروف",
    step_install: "تثبيت Bitwarden CLI",
    step_install_d: "الأمر `bw` على الجهاز الذي يشغّل Hermes.",
    step_server: "اختر الخادم",
    step_server_d: "bitwarden.com (الولايات المتحدة) أو bitwarden.eu أو عنوان URL الخاص بك المستضاف ذاتيًا.",
    step_login: "تسجيل الدخول",
    step_login_d: "البريد الإلكتروني وكلمة المرور الرئيسية ورمز الخطوتين، في نافذة محجوبة.",
    step_unlock: "فتح قفل الخزنة",
    step_unlock_d: "يبقى مفتاح الجلسة في الذاكرة فقط ويُقفل تلقائيًا عند الخمول.",
    install: "تثبيت Bitwarden CLI",
    installing: "جارٍ التثبيت…",
    via: "عبر",
    no_installer: "لا يوجد مثبّت لهذا النظام: استخدم صفحة التنزيل.",
    official_build: "إصدار Bitwarden الرسمي",
    download: "صفحة التنزيل",
    docs: "وثائق CLI",
    site: "bitwarden.com",
    login: "تسجيل الدخول",
    unlock: "فتح القفل",
    lock: "قفل",
    logout: "تسجيل الخروج",
    sync: "مزامنة",
    set: "تعيين",
    done: "تم",
    account: "الحساب",
    server: "الخادم",
    last_sync: "آخر مزامنة",
    version: "الإصدار",
    autolock_in: "القفل التلقائي خلال",
    settings: "الإعدادات",
    autolock: "القفل التلقائي",
    clip_clear: "مسح الحافظة",
    dialogs: "النوافذ",
    d_auto: "تلقائي",
    d_desktop: "هذا التطبيق",
    d_host: "نافذة المضيف (macOS)",
    off: "إيقاف",
    vault: "الخزنة",
    search: "بحث في العناصر",
    no_items: "لم يتم العثور على شيء",
    locked_hint: "افتح القفل لتصفح الخزنة.",
    loading_vault: "جارٍ تحميل الخزنة…",
    copy_user: "نسخ اسم المستخدم",
    username: "اسم المستخدم",
    copy_pass: "نسخ كلمة المرور",
    btn_user: "المستخدم",
    btn_pass: "كلمة المرور",
    copy_totp: "نسخ رمز TOTP",
    reveal: "إظهار",
    copied: (label, s) => (s ? `تم نسخ ${label} · يُمسح خلال ${s} ث` : `تم نسخ ${label}`),
    copy_failed: "تعذّرت الكتابة إلى الحافظة",
    copied_noclear: label => `تم نسخ ${label} · امسح الحافظة بنفسك عند الانتهاء`,
    generator: "المولّد",
    generate: "إنشاء",
    copy: "نسخ",
    length: "الطول",
    passphrase: "عبارة المرور",
    password: "كلمة المرور",
    serve: "REST API محلي (bw serve)",
    serve_d: "على 127.0.0.1 فقط. أثناء التشغيل، يمكن لأي برنامج على هذا الكمبيوتر قراءة خزنتك. يتوقف عند قفل الخزنة.",
    start: "بدء",
    stop: "إيقاف",
    agent: "اسأل الوكيل",
    agent_d: "جرّب: «افتح قفل Bitwarden»، «انسخ كلمة مرور GitHub الخاصة بي»، «أنشئ تسجيل دخول لـ example.com بكلمة مرور قوية»، «ما كلمات المرور الضعيفة أو المكررة؟»، «صدّر الخزنة مشفّرة».",
    d_unlock: "فتح قفل Bitwarden",
    d_login: "تسجيل الدخول إلى Bitwarden",
    d_secret: "اكتب سرًا",
    d_confirm: "تأكيد",
    master: "كلمة المرور الرئيسية",
    email: "البريد الإلكتروني",
    code2fa: "رمز تسجيل الدخول بخطوتين",
    code_device: "رمز الجهاز الجديد (يُرسل بالبريد الإلكتروني)",
    apikey: "استخدام مفتاح API بدلًا من ذلك",
    client_id: "client_id",
    client_secret: "client_secret",
    value: "القيمة",
    cancel: "إلغاء",
    confirm: "تأكيد",
    ok: "حسنًا",
    send: "متابعة",
    safe_note: "يُكتب هنا ويُرسل فقط إلى Bitwarden على مضيف Hermes. لا يراه الوكيل أبدًا.",
    secret_note: "لن يرى الوكيل هذه القيمة، لكن يمكنه استخدامها في الخطوات التي توافق عليها. لا تكتب كلمة المرور الرئيسية هنا أبدًا.",
    asked_by: "طلب من الوكيل",
    reveal_title: "سر من خزنتك",
    hide: "إخفاء",
    reveal_note: "أغلق هذه النافذة عند الانتهاء. لا يتم تخزينه في أي مكان.",
    attempts: n => `فشلت المحاولة ${n}`,
    method: "طريقة الخطوتين",
    m_auth: "المصادق",
    m_email: "البريد الإلكتروني",
    m_yubi: "YubiKey",
    open: "فتح Hermes Warden",
    err: "خطأ",
    working_unlock: "جارٍ فتح القفل…",
    working_login: "جارٍ تسجيل الدخول…"
  },
  ru: {
    title: "Hermes Warden",
    subtitle: "Bitwarden для Hermes. Секреты никогда не попадают в беседу.",
    s_not_installed: "Не установлено",
    s_unauthenticated: "Выход выполнен",
    s_locked: "Заблокировано",
    s_unlocked: "Разблокировано",
    s_unknown: "Неизвестно",
    step_install: "Установка Bitwarden CLI",
    step_install_d: "Команда `bw` на компьютере, где запущен Hermes.",
    step_server: "Выбор сервера",
    step_server_d: "bitwarden.com (США), bitwarden.eu или ваш собственный URL.",
    step_login: "Вход",
    step_login_d: "Адрес эл. почты, мастер-пароль и код двухэтапной аутентификации в защищённом окне.",
    step_unlock: "Разблокировка хранилища",
    step_unlock_d: "Ключ сеанса хранится только в памяти и блокируется при простое.",
    install: "Установить Bitwarden CLI",
    installing: "Установка…",
    via: "через",
    no_installer: "Для этой системы нет установщика: используйте страницу загрузки.",
    official_build: "официальная сборка Bitwarden",
    download: "Страница загрузки",
    docs: "Документация CLI",
    site: "bitwarden.com",
    login: "Войти",
    unlock: "Разблокировать",
    lock: "Заблокировать",
    logout: "Выйти",
    sync: "Синхронизировать",
    set: "Задать",
    done: "Готово",
    account: "Аккаунт",
    server: "Сервер",
    last_sync: "Последняя синхронизация",
    version: "Версия",
    autolock_in: "Автоблокировка через",
    settings: "Настройки",
    autolock: "Автоблокировка",
    clip_clear: "Очищать буфер обмена",
    dialogs: "Диалоги",
    d_auto: "Авто",
    d_desktop: "Это приложение",
    d_host: "Диалог хоста (macOS)",
    off: "Выкл.",
    vault: "Хранилище",
    search: "Поиск элементов",
    no_items: "Ничего не найдено",
    locked_hint: "Разблокируйте, чтобы просмотреть хранилище.",
    loading_vault: "Загрузка хранилища…",
    copy_user: "Копировать имя пользователя",
    username: "Имя пользователя",
    copy_pass: "Копировать пароль",
    btn_user: "Логин",
    btn_pass: "Пароль",
    copy_totp: "Копировать код TOTP",
    reveal: "Показать",
    copied: (label, s) => (s ? `${label}: скопировано · очистка через ${s} с` : `${label}: скопировано`),
    copy_failed: "Не удалось записать в буфер обмена",
    copied_noclear: label => `${label}: скопировано · очистите буфер обмена сами, когда закончите`,
    generator: "Генератор",
    generate: "Сгенерировать",
    copy: "Копировать",
    length: "Длина",
    passphrase: "Парольная фраза",
    password: "Пароль",
    serve: "Локальный REST API (bw serve)",
    serve_d: "Только на 127.0.0.1. Пока он запущен, любая программа на этом компьютере может читать ваше хранилище. Останавливается при блокировке хранилища.",
    start: "Запустить",
    stop: "Остановить",
    agent: "Спросить агента",
    agent_d: "Попробуйте: «разблокируй Bitwarden», «скопируй мой пароль от GitHub», «создай логин для example.com с надёжным паролем», «какие пароли слабые или повторяются?», «экспортируй хранилище в зашифрованном виде».",
    d_unlock: "Разблокировать Bitwarden",
    d_login: "Вход в Bitwarden",
    d_secret: "Введите секрет",
    d_confirm: "Подтверждение",
    master: "Мастер-пароль",
    email: "Эл. почта",
    code2fa: "Код двухэтапной аутентификации",
    code_device: "Код нового устройства (отправлен по эл. почте)",
    apikey: "Использовать ключ API",
    client_id: "client_id",
    client_secret: "client_secret",
    value: "Значение",
    cancel: "Отмена",
    confirm: "Подтвердить",
    ok: "ОК",
    send: "Продолжить",
    safe_note: "Вводится здесь и отправляется только в Bitwarden на хосте Hermes. Агент этого не видит.",
    secret_note: "Агент не увидит это значение, но сможет использовать его в одобренных вами шагах. Никогда не вводите здесь мастер-пароль.",
    asked_by: "Запрошено агентом",
    reveal_title: "Секрет из вашего хранилища",
    hide: "Скрыть",
    reveal_note: "Закройте это окно, когда закончите. Нигде не сохраняется.",
    attempts: n => `Попытка ${n} не удалась`,
    method: "Способ двухэтапной аутентификации",
    m_auth: "Приложение-аутентификатор",
    m_email: "Эл. почта",
    m_yubi: "YubiKey",
    open: "Открыть Hermes Warden",
    err: "Ошибка",
    working_unlock: "Разблокировка…",
    working_login: "Вход…"
  },
  fr: {
    title: "Hermes Warden",
    subtitle: "Bitwarden pour Hermes. Les secrets n’entrent jamais dans la conversation.",
    s_not_installed: "Non installé",
    s_unauthenticated: "Déconnecté",
    s_locked: "Verrouillé",
    s_unlocked: "Déverrouillé",
    s_unknown: "Inconnu",
    step_install: "Installer la CLI Bitwarden",
    step_install_d: "La commande `bw`, sur la machine qui exécute Hermes.",
    step_server: "Choisir le serveur",
    step_server_d: "bitwarden.com (États-Unis), bitwarden.eu ou votre URL auto-hébergée.",
    step_login: "Se connecter",
    step_login_d: "E-mail, mot de passe principal et code de connexion en deux étapes, dans une boîte de dialogue masquée.",
    step_unlock: "Déverrouiller le coffre",
    step_unlock_d: "La clé de session reste en mémoire et se verrouille d’elle-même en cas d’inactivité.",
    install: "Installer la CLI Bitwarden",
    installing: "Installation…",
    via: "via",
    no_installer: "Aucun installateur pour ce système : utilisez la page de téléchargement.",
    official_build: "version officielle de Bitwarden",
    download: "Page de téléchargement",
    docs: "Documentation CLI",
    site: "bitwarden.com",
    login: "Se connecter",
    unlock: "Déverrouiller",
    lock: "Verrouiller",
    logout: "Se déconnecter",
    sync: "Synchroniser",
    set: "Définir",
    done: "Terminé",
    account: "Compte",
    server: "Serveur",
    last_sync: "Dernière synchro.",
    version: "Version",
    autolock_in: "Verrouillage auto dans",
    settings: "Paramètres",
    autolock: "Verrouillage auto",
    clip_clear: "Vider le presse-papiers",
    dialogs: "Boîtes de dialogue",
    d_auto: "Auto",
    d_desktop: "Cette appli",
    d_host: "Dialogue de l’hôte (macOS)",
    off: "Désactivé",
    vault: "Coffre",
    search: "Rechercher des éléments",
    no_items: "Aucun résultat",
    locked_hint: "Déverrouillez pour parcourir le coffre.",
    loading_vault: "Chargement du coffre…",
    copy_user: "Copier le nom d’utilisateur",
    username: "Nom d’utilisateur",
    copy_pass: "Copier le mot de passe",
    btn_user: "Identifiant",
    btn_pass: "Mot de passe",
    copy_totp: "Copier le code TOTP",
    reveal: "Afficher",
    copied: (label, s) => (s ? `${label} copié · effacement dans ${s} s` : `${label} copié`),
    copy_failed: "Impossible d’écrire dans le presse-papiers",
    copied_noclear: label => `${label} copié · videz le presse-papiers vous-même une fois terminé`,
    generator: "Générateur",
    generate: "Générer",
    copy: "Copier",
    length: "Longueur",
    passphrase: "Phrase secrète",
    password: "Mot de passe",
    serve: "API REST locale (bw serve)",
    serve_d: "Sur 127.0.0.1 uniquement. Tant qu’elle tourne, n’importe quel programme de cet ordinateur peut lire votre coffre. S’arrête au verrouillage du coffre.",
    start: "Démarrer",
    stop: "Arrêter",
    agent: "Demander à l’agent",
    agent_d: "Essayez : « déverrouille Bitwarden », « copie mon mot de passe GitHub », « crée un identifiant pour example.com avec un mot de passe fort », « quels mots de passe sont faibles ou réutilisés ? », « exporte le coffre chiffré ».",
    d_unlock: "Déverrouiller Bitwarden",
    d_login: "Se connecter à Bitwarden",
    d_secret: "Saisir un secret",
    d_confirm: "Confirmer",
    master: "Mot de passe principal",
    email: "E-mail",
    code2fa: "Code de connexion en deux étapes",
    code_device: "Code du nouvel appareil (envoyé par e-mail)",
    apikey: "Utiliser une clé d’API à la place",
    client_id: "client_id",
    client_secret: "client_secret",
    value: "Valeur",
    cancel: "Annuler",
    confirm: "Confirmer",
    ok: "OK",
    send: "Continuer",
    safe_note: "Saisi ici, envoyé uniquement à Bitwarden sur l’hôte Hermes. L’agent ne le voit jamais.",
    secret_note: "L’agent ne verra pas cette valeur, mais pourra l’utiliser dans les étapes que vous approuvez. Ne saisissez jamais votre mot de passe principal ici.",
    asked_by: "Demandé par l’agent",
    reveal_title: "Secret de votre coffre",
    hide: "Masquer",
    reveal_note: "Fermez cette fenêtre une fois terminé. Rien n’est stocké.",
    attempts: n => `Échec de la tentative ${n}`,
    method: "Méthode en deux étapes",
    m_auth: "Authentificateur",
    m_email: "E-mail",
    m_yubi: "YubiKey",
    open: "Ouvrir Hermes Warden",
    err: "Erreur",
    working_unlock: "Déverrouillage…",
    working_login: "Connexion…"
  },
  de: {
    title: "Hermes Warden",
    subtitle: "Bitwarden für Hermes. Geheimnisse gelangen nie in die Unterhaltung.",
    s_not_installed: "Nicht installiert",
    s_unauthenticated: "Abgemeldet",
    s_locked: "Gesperrt",
    s_unlocked: "Entsperrt",
    s_unknown: "Unbekannt",
    step_install: "Bitwarden CLI installieren",
    step_install_d: "Der Befehl `bw` auf dem Rechner, auf dem Hermes läuft.",
    step_server: "Server wählen",
    step_server_d: "bitwarden.com (USA), bitwarden.eu oder Ihre selbst gehostete URL.",
    step_login: "Anmelden",
    step_login_d: "E-Mail, Master-Passwort und Zwei-Schritt-Code in einem maskierten Dialog.",
    step_unlock: "Tresor entsperren",
    step_unlock_d: "Der Sitzungsschlüssel bleibt im Arbeitsspeicher und sperrt sich bei Inaktivität selbst.",
    install: "Bitwarden CLI installieren",
    installing: "Wird installiert…",
    via: "über",
    no_installer: "Kein Installationsprogramm für dieses System: Nutzen Sie die Download-Seite.",
    official_build: "offizieller Bitwarden-Build",
    download: "Download-Seite",
    docs: "CLI-Dokumentation",
    site: "bitwarden.com",
    login: "Anmelden",
    unlock: "Entsperren",
    lock: "Sperren",
    logout: "Abmelden",
    sync: "Synchronisieren",
    set: "Festlegen",
    done: "Fertig",
    account: "Konto",
    server: "Server",
    last_sync: "Letzte Synchronisierung",
    version: "Version",
    autolock_in: "Automatische Sperre in",
    settings: "Einstellungen",
    autolock: "Automatische Sperre",
    clip_clear: "Zwischenablage leeren",
    dialogs: "Dialoge",
    d_auto: "Automatisch",
    d_desktop: "Diese App",
    d_host: "Host-Dialog (macOS)",
    off: "Aus",
    vault: "Tresor",
    search: "Einträge durchsuchen",
    no_items: "Nichts gefunden",
    locked_hint: "Entsperren, um den Tresor zu durchsuchen.",
    loading_vault: "Tresor wird geladen…",
    copy_user: "Benutzernamen kopieren",
    username: "Benutzername",
    copy_pass: "Passwort kopieren",
    btn_user: "Benutzer",
    btn_pass: "Passwort",
    copy_totp: "TOTP-Code kopieren",
    reveal: "Anzeigen",
    copied: (label, s) => (s ? `${label} kopiert · wird in ${s} s gelöscht` : `${label} kopiert`),
    copy_failed: "Zwischenablage konnte nicht beschrieben werden",
    copied_noclear: label => `${label} kopiert · leeren Sie die Zwischenablage danach selbst`,
    generator: "Generator",
    generate: "Generieren",
    copy: "Kopieren",
    length: "Länge",
    passphrase: "Passphrase",
    password: "Passwort",
    serve: "Lokale REST API (bw serve)",
    serve_d: "Nur auf 127.0.0.1. Solange sie läuft, kann jedes Programm auf diesem Computer Ihren Tresor lesen. Wird beim Sperren des Tresors beendet.",
    start: "Starten",
    stop: "Beenden",
    agent: "Agent fragen",
    agent_d: "Probieren Sie: „Bitwarden entsperren“, „mein GitHub-Passwort kopieren“, „einen Login für example.com mit starkem Passwort anlegen“, „welche Passwörter sind schwach oder mehrfach verwendet?“, „den Tresor verschlüsselt exportieren“.",
    d_unlock: "Bitwarden entsperren",
    d_login: "Bei Bitwarden anmelden",
    d_secret: "Geheimnis eingeben",
    d_confirm: "Bestätigen",
    master: "Master-Passwort",
    email: "E-Mail",
    code2fa: "Zwei-Schritt-Anmeldecode",
    code_device: "Code für neues Gerät (per E-Mail gesendet)",
    apikey: "Stattdessen API-Schlüssel verwenden",
    client_id: "client_id",
    client_secret: "client_secret",
    value: "Wert",
    cancel: "Abbrechen",
    confirm: "Bestätigen",
    ok: "OK",
    send: "Weiter",
    safe_note: "Hier eingegeben und nur an Bitwarden auf dem Hermes-Host gesendet. Der Agent sieht es nie.",
    secret_note: "Der Agent sieht diesen Wert nicht, kann ihn aber in Schritten verwenden, die Sie freigeben. Geben Sie hier niemals Ihr Master-Passwort ein.",
    asked_by: "Vom Agent angefordert",
    reveal_title: "Geheimnis aus Ihrem Tresor",
    hide: "Verbergen",
    reveal_note: "Schließen Sie dieses Fenster, wenn Sie fertig sind. Nichts wird gespeichert.",
    attempts: n => `Versuch ${n} fehlgeschlagen`,
    method: "Zwei-Schritt-Methode",
    m_auth: "Authenticator",
    m_email: "E-Mail",
    m_yubi: "YubiKey",
    open: "Hermes Warden öffnen",
    err: "Fehler",
    working_unlock: "Wird entsperrt…",
    working_login: "Anmeldung läuft…"
  },
  es: {
    title: "Hermes Warden",
    subtitle: "Bitwarden para Hermes. Los secretos nunca entran en la conversación.",
    s_not_installed: "No instalado",
    s_unauthenticated: "Sesión cerrada",
    s_locked: "Bloqueado",
    s_unlocked: "Desbloqueado",
    s_unknown: "Desconocido",
    step_install: "Instalar la CLI de Bitwarden",
    step_install_d: "El comando `bw`, en el equipo donde se ejecuta Hermes.",
    step_server: "Elegir el servidor",
    step_server_d: "bitwarden.com (EE. UU.), bitwarden.eu o tu URL autoalojada.",
    step_login: "Iniciar sesión",
    step_login_d: "Correo electrónico, contraseña maestra y código de inicio de sesión en dos pasos, en un cuadro de diálogo enmascarado.",
    step_unlock: "Desbloquear la caja fuerte",
    step_unlock_d: "La clave de sesión permanece en memoria y se bloquea sola al estar inactiva.",
    install: "Instalar la CLI de Bitwarden",
    installing: "Instalando…",
    via: "con",
    no_installer: "No hay instalador para este sistema: usa la página de descarga.",
    official_build: "versión oficial de Bitwarden",
    download: "Página de descarga",
    docs: "Documentación de la CLI",
    site: "bitwarden.com",
    login: "Iniciar sesión",
    unlock: "Desbloquear",
    lock: "Bloquear",
    logout: "Cerrar sesión",
    sync: "Sincronizar",
    set: "Definir",
    done: "Hecho",
    account: "Cuenta",
    server: "Servidor",
    last_sync: "Última sincronización",
    version: "Versión",
    autolock_in: "Bloqueo automático en",
    settings: "Ajustes",
    autolock: "Bloqueo automático",
    clip_clear: "Borrar portapapeles",
    dialogs: "Diálogos",
    d_auto: "Auto",
    d_desktop: "Esta app",
    d_host: "Diálogo del host (macOS)",
    off: "Desactivado",
    vault: "Caja fuerte",
    search: "Buscar elementos",
    no_items: "No se encontró nada",
    locked_hint: "Desbloquea para explorar la caja fuerte.",
    loading_vault: "Cargando la caja fuerte…",
    copy_user: "Copiar usuario",
    username: "Usuario",
    copy_pass: "Copiar contraseña",
    btn_user: "Usuario",
    btn_pass: "Contraseña",
    copy_totp: "Copiar código TOTP",
    reveal: "Mostrar",
    copied: (label, s) => (s ? `${label} copiado · se borra en ${s} s` : `${label} copiado`),
    copy_failed: "No se pudo escribir en el portapapeles",
    copied_noclear: label => `${label} copiado · borra el portapapeles tú mismo al terminar`,
    generator: "Generador",
    generate: "Generar",
    copy: "Copiar",
    length: "Longitud",
    passphrase: "Frase de contraseña",
    password: "Contraseña",
    serve: "API REST local (bw serve)",
    serve_d: "Solo en 127.0.0.1. Mientras está activa, cualquier programa de este equipo puede leer tu caja fuerte. Se detiene al bloquear la caja fuerte.",
    start: "Iniciar",
    stop: "Detener",
    agent: "Preguntar al agente",
    agent_d: "Prueba: “desbloquea Bitwarden”, “copia mi contraseña de GitHub”, “crea un inicio de sesión para example.com con una contraseña segura”, “¿qué contraseñas son débiles o están repetidas?”, “exporta la caja fuerte cifrada”.",
    d_unlock: "Desbloquear Bitwarden",
    d_login: "Iniciar sesión en Bitwarden",
    d_secret: "Escribe un secreto",
    d_confirm: "Confirmar",
    master: "Contraseña maestra",
    email: "Correo electrónico",
    code2fa: "Código de inicio de sesión en dos pasos",
    code_device: "Código de dispositivo nuevo (enviado por correo)",
    apikey: "Usar clave de API en su lugar",
    client_id: "client_id",
    client_secret: "client_secret",
    value: "Valor",
    cancel: "Cancelar",
    confirm: "Confirmar",
    ok: "Aceptar",
    send: "Continuar",
    safe_note: "Se escribe aquí y se envía solo a Bitwarden en el host de Hermes. El agente nunca lo ve.",
    secret_note: "El agente no verá este valor, pero puede usarlo en los pasos que apruebes. Nunca escribas aquí tu contraseña maestra.",
    asked_by: "Solicitado por el agente",
    reveal_title: "Secreto de tu caja fuerte",
    hide: "Ocultar",
    reveal_note: "Cierra esta ventana al terminar. No se guarda en ningún sitio.",
    attempts: n => `Intento ${n} fallido`,
    method: "Método de dos pasos",
    m_auth: "Autenticador",
    m_email: "Correo electrónico",
    m_yubi: "YubiKey",
    open: "Abrir Hermes Warden",
    err: "Error",
    working_unlock: "Desbloqueando…",
    working_login: "Iniciando sesión…"
  }
}

let i18n = null

function t(key, ...args) {
  if (i18n && typeof i18n.t === 'function') {
    try {
      const v = i18n.t(key, ...args)
      if (typeof v === 'string' && v !== key) return v
    } catch {
      /* fall back to English */
    }
  }
  const v = STRINGS.en[key] ?? key
  return typeof v === 'function' ? v(...args) : v
}

/* ------------------------------------------------------------------ backend */

async function api(path, opts) {
  if (!rest) throw new Error('backend unavailable')
  const res = await rest(path, { timeoutMs: 60000, ...(opts || {}) })
  return res && typeof res === 'object' && 'data' in res && 'status' in res && !('ok' in res) ? res.data : res
}

function post(path, body, timeoutMs) {
  return api(path, { method: 'POST', body: body || {}, timeoutMs: timeoutMs || 60000 })
}

function toast(kind, message) {
  try {
    host.notify({ kind, message })
  } catch {
    /* ignore */
  }
}

/* Read the system clipboard with the Clipboard API (null when the window may not, e.g. it is in
   the background). The SDK offers no read; the raw desktop bridge is off limits for plugins. */
async function readClipboard() {
  try {
    const cb = navigator.clipboard
    if (cb && cb.readText) return await cb.readText()
  } catch {
    /* not allowed right now */
  }
  return null
}

/* Copy, then clear after `seconds` if the clipboard still holds our value. */
async function copySecret(value, label, seconds) {
  try {
    await writeClipboardText(value)
  } catch {
    toast('error', t('copy_failed'))
    return false
  }
  toast('success', seconds > 0 ? t('copied', label, seconds) : t('copied_noclear', label))
  if (seconds > 0) {
    setTimeout(async () => {
      try {
        // Keep something the user copied since; when the clipboard cannot be read (window in the
        // background), clear it anyway: a secret left behind is worse than a lost clipboard.
        const now = await readClipboard()
        if (now === null || now === value) await writeClipboardText(' ')
      } catch {
        toast('warning', t('copied_noclear', label))
      }
    }, seconds * 1000)
  }
  return true
}

function useWardenState(fast) {
  return useQuery({
    queryKey: STATE_KEY,
    queryFn: () => api('/state'),
    refetchInterval: fast ? 3000 : 15000,
    refetchOnWindowFocus: true,
    staleTime: 1000
  })
}

const STATUS_TONE = { unlocked: 'good', locked: 'warn', unauthenticated: 'muted', not_installed: 'bad' }

function statusLabel(s) {
  return t('s_' + (s || 'unknown'))
}

/* ------------------------------------------------------------------ dialog host */

function Field({ label, children, hint }) {
  return jsxs('label', {
    className: 'flex flex-col gap-1 text-xs',
    children: [
      jsx('span', { className: 'text-(--ui-text-secondary)', children: label }),
      children,
      hint ? jsx('span', { className: 'text-[0.6875rem] text-(--ui-text-quaternary)', children: hint }) : null
    ]
  })
}

function PromptDialog({ prompt, onClose }) {
  const [values, setValues] = useState({})
  const [sending, setSending] = useState(false)
  const [error, setError] = useState(null)
  const [apikey, setApikey] = useState(false)
  const busy = sending || !!prompt.working
  const firstRef = useRef(null)
  const qc = useQueryClient()

  useEffect(() => {
    setValues(prompt.email ? { email: prompt.email, method: '0' } : { method: '0' })
    setError(prompt.error || null)
    setTimeout(() => firstRef.current && firstRef.current.focus(), 50)
  }, [prompt.id, prompt.need])

  // A background attempt ended: show its error (the field was cleared when it was sent).
  useEffect(() => {
    if (!prompt.working && prompt.error) setError(prompt.error)
  }, [prompt.working, prompt.error, prompt.attempts])

  const set = (k, v) => setValues(prev => ({ ...prev, [k]: v }))

  async function answer(cancel) {
    setSending(true)
    setError(null)
    const payload = cancel ? { cancel: true, surface: SURFACE } : { values: { ...values }, surface: SURFACE }
    // unlock / login: the backend answers at once and runs bw in the background (see `working`).
    if (!cancel && (prompt.kind === 'unlock' || prompt.kind === 'login')) payload.background = true
    if (!cancel && prompt.kind === 'login' && apikey && !prompt.need) payload.values.mode = 'apikey'
    if (!cancel && prompt.kind === 'confirm') payload.values = { confirmed: true }
    setValues(prev => ({ email: prev.email, method: prev.method || '0' }))
    try {
      const res = await post(`/prompts/${encodeURIComponent(prompt.id)}/answer`, payload, 180000)
      qc.invalidateQueries({ queryKey: STATE_KEY })
      if (res && res.ok && res.working) {
        onClose(prompt.id, 'next', res)
        return
      }
      if (res && res.ok && (res.status === 'done' || res.status === 'cancelled')) {
        onClose(prompt.id, res.status)
        return
      }
      if (res && res.ok && res.need) {
        onClose(prompt.id, 'next', res)
        return
      }
      setError((res && res.error) || t('err'))
      if (res && (res.code === 'expired' || res.code === 'taken')) onClose(prompt.id, 'gone')
    } catch (e) {
      setError(String((e && e.message) || e))
    } finally {
      setSending(false)
    }
  }

  function decline() {
    if (prompt.kind === 'confirm') {
      setSending(true)
      post(`/prompts/${encodeURIComponent(prompt.id)}/answer`, { values: { confirmed: false }, surface: SURFACE })
        .finally(() => onClose(prompt.id, 'done'))
      return
    }
    answer(true)
  }

  const pw = (key, label, opts) =>
    jsx(Field, {
      label,
      children: jsx(Input, {
        ref: opts && opts.first ? firstRef : undefined,
        type: opts && opts.visible ? 'text' : 'password',
        autoComplete: opts && opts.ac ? opts.ac : 'off',
        spellCheck: false,
        inputMode: opts && opts.numeric ? 'numeric' : undefined,
        value: values[key] || '',
        disabled: busy,
        onChange: e => set(key, e.target.value),
        onKeyDown: e => {
          if (e.key === 'Enter' && !busy) {
            e.preventDefault()
            answer(false)
          }
        }
      })
    })

  let title = prompt.title
  let body = []
  let primary = t('ok')
  let danger = false
  if (prompt.kind === 'unlock') {
    title = title || t('d_unlock')
    primary = t('unlock')
    body = [pw('password', t('master'), { first: true, ac: 'current-password' })]
  } else if (prompt.kind === 'secret') {
    title = title || t('d_secret')
    // The agent wrote the label: say so once. When the description already carries the
    // "Requested by the agent" attribution, the field shows the label alone.
    const label = !prompt.label ? t('value') : prompt.reason ? prompt.label : `${t('asked_by')}: ${prompt.label}`
    body = [pw('value', label, { first: true, ac: 'new-password' })]
  } else if (prompt.kind === 'confirm') {
    title = title || t('d_confirm')
    primary = t('confirm')
    danger = !!prompt.danger
    body = [jsx('p', { className: 'whitespace-pre-wrap text-sm', style: { overflowWrap: 'anywhere' }, children: prompt.message })]
  } else if (prompt.kind === 'login') {
    title = title || t('d_login')
    primary = prompt.need ? t('send') : t('login')
    if (prompt.need === 'two_factor') {
      body = [pw('code', t('code2fa'), { first: true, visible: true, numeric: true, ac: 'one-time-code' })]
    } else if (prompt.need === 'new_device') {
      body = [pw('code', t('code_device'), { first: true, visible: true, ac: 'one-time-code' })]
    } else if (apikey) {
      body = [
        pw('client_id', t('client_id'), { first: true }),
        pw('client_secret', t('client_secret')),
        pw('password', t('master'), { ac: 'current-password' })
      ]
    } else {
      body = [
        jsx(Field, {
          label: t('email'),
          children: jsx(Input, {
            ref: prompt.email ? undefined : firstRef,
            type: 'email',
            autoComplete: 'username',
            value: values.email || '',
            disabled: busy,
            onChange: e => set('email', e.target.value)
          })
        }),
        pw('password', t('master'), { first: !!prompt.email, ac: 'current-password' }),
        jsx(Field, {
          label: t('method'),
          children: jsx(SegmentedControl, {
            options: [
              { id: '0', label: t('m_auth') },
              { id: '1', label: t('m_email') },
              { id: '3', label: t('m_yubi') }
            ],
            value: String(values.method ?? '0'),
            onChange: v => set('method', v)
          })
        }),
        jsx(Button, { type: 'button', variant: 'link', size: 'xs', className: 'self-start px-0', onClick: () => setApikey(true), children: t('apikey') })
      ]
    }
  }

  return jsx(Dialog, {
    open: true,
    onOpenChange: open => {
      if (!open && !busy) decline()
    },
    children: jsxs(DialogContent, {
      className: 'sm:max-w-[26rem]',
      onInteractOutside: e => e.preventDefault(),
      children: [
        jsxs(DialogHeader, {
          children: [
            jsxs(DialogTitle, {
              className: 'flex items-center gap-2',
              children: [jsx(Codicon, { name: prompt.kind === 'confirm' ? 'shield' : 'lock' }), title]
            }),
            jsx(DialogDescription, {
              children: prompt.reason
                ? `${t('asked_by')}: ${prompt.reason}`
                : prompt.kind === 'secret' ? t('secret_note') : prompt.kind === 'confirm' ? '' : t('safe_note')
            })
          ]
        }),
        jsxs('form', {
          className: 'flex flex-col gap-3',
          autoComplete: 'off',
          onSubmit: e => {
            e.preventDefault()
            if (!busy) answer(false)
          },
          children: [
            prompt.kind === 'login' && prompt.server
              ? jsxs('div', {
                  className:
                    'flex items-center gap-1.5 rounded-[4px] border px-2 py-1 text-xs ' +
                    (OFFICIAL_SERVERS.includes(String(prompt.server).replace(/\/$/, ''))
                      ? 'border-(--ui-stroke-secondary) text-(--ui-text-secondary)'
                      : 'border-(--ui-red,var(--destructive)) text-(--ui-red,var(--destructive))'),
                  children: [jsx(Codicon, { name: 'server', size: 12 }), `${t('server')}: ${prompt.server}`]
                })
              : null,
            ...body,
            prompt.working
              ? jsx('div', {
                  // The primary button already spins; this line only names what is happening.
                  role: 'status',
                  className: 'text-xs text-(--ui-text-secondary)',
                  children: t(prompt.kind === 'login' ? 'working_login' : 'working_unlock')
                })
              : error || prompt.attempts
              ? jsx('div', {
                  role: 'alert',
                  className: 'text-xs text-(--ui-red,var(--destructive))',
                  children: error || t('attempts', prompt.attempts)
                })
              : null,
            prompt.reason && prompt.kind !== 'confirm'
              ? jsx('div', {
                  className: 'text-[0.6875rem] text-(--ui-text-quaternary)',
                  children: prompt.kind === 'secret' ? t('secret_note') : t('safe_note')
                })
              : null
          ]
        }),
        jsxs(DialogFooter, {
          children: [
            jsx(Button, { type: 'button', variant: 'ghost', disabled: busy, onClick: decline, children: t('cancel') }),
            jsx(Button, {
              variant: danger ? 'destructive' : 'default',
              loading: busy,
              disabled: busy,
              onClick: () => answer(false),
              children: primary
            })
          ]
        })
      ]
    })
  })
}

function RevealDialog({ ticket, onClose }) {
  const [shown, setShown] = useState(false)
  const value = ticket.value
  return jsx(Dialog, {
    open: true,
    onOpenChange: open => !open && onClose(),
    children: jsxs(DialogContent, {
      className: 'sm:max-w-[28rem]',
      children: [
        jsxs(DialogHeader, {
          children: [
            jsxs(DialogTitle, { className: 'flex items-center gap-2', children: [jsx(Codicon, { name: 'key' }), t('reveal_title')] }),
            jsx(DialogDescription, { children: ticket.label })
          ]
        }),
        jsx('div', {
          className: 'select-all break-all rounded-[4px] border border-(--ui-stroke-secondary) px-3 py-2 font-mono text-sm',
          children: shown ? value : '•'.repeat(Math.min(24, Math.max(8, value.length)))
        }),
        jsx('div', { className: 'text-[0.6875rem] text-(--ui-text-quaternary)', children: t('reveal_note') }),
        jsxs(DialogFooter, {
          children: [
            jsx(Button, { variant: 'ghost', onClick: () => setShown(s => !s), children: shown ? t('hide') : t('reveal') }),
            jsx(Button, { onClick: () => copySecret(value, ticket.label, ticket.clear_after), children: t('copy') }),
            jsx(Button, { variant: 'secondary', onClick: onClose, children: t('done') })
          ]
        })
      ]
    })
  })
}

/* Only one DialogHost polls at a time. It is mounted twice (title bar center, which stays up
   when the status bar is hidden, and the status bar chip, which stays up when a plugin page
   owns the title bar); the first mounted instance owns the poll, the other takes over when
   it unmounts. */
let hostOwner = null
const hostWaiters = new Set()

function useHostOwnership() {
  const me = useRef(Symbol('warden-dialog-host'))
  const [owner, setOwner] = useState(false)
  useEffect(() => {
    const token = me.current
    const claim = () => {
      if (hostOwner === null || hostOwner === token) {
        hostOwner = token
        setOwner(true)
        return true
      }
      return false
    }
    const waiter = () => claim()
    if (!claim()) hostWaiters.add(waiter)
    return () => {
      hostWaiters.delete(waiter)
      if (hostOwner === token) {
        hostOwner = null
        for (const w of Array.from(hostWaiters)) if (w()) {
          hostWaiters.delete(w)
          break
        }
      }
    }
  }, [])
  return owner
}

function DialogHostSlot() {
  return useHostOwnership() ? jsx(DialogHost, {}) : null
}

/* Polls /pending; owns the masked dialogs and the delivery queue. */
function DialogHost() {
  const [prompt, setPrompt] = useState(null)
  const [reveal, setReveal] = useState(null)
  const handled = useRef(new Set())
  const promptRef = useRef(null)
  promptRef.current = prompt
  const qc = useQueryClient()

  const pending = useQuery({
    queryKey: [ID, 'pending'],
    queryFn: () => api(`/pending?surface=${encodeURIComponent(SURFACE)}`, { timeoutMs: 10000 }),
    refetchInterval: 1500,
    refetchIntervalInBackground: false,
    retry: false
  })

  useEffect(() => {
    const data = pending.data
    if (!data || !data.ok) return
    // Deliveries: claim each ticket once; clipboard ones copy at once, reveal ones open a dialog.
    const focused = typeof document.hasFocus === 'function' ? document.hasFocus() : true
    const visible = document.visibilityState !== 'hidden'
    for (const tk of data.tickets || []) {
      if (handled.current.has(tk.id)) continue
      // The window the user is looking at takes it; a visible but unfocused one waits 3 s first.
      const age = Date.now() / 1000 - (tk.created || 0)
      if (!visible || (!focused && age < 3)) continue
      handled.current.add(tk.id)
      post(`/tickets/${encodeURIComponent(tk.id)}/claim`).then(res => {
        if (!res || !res.ok || typeof res.value !== 'string') return
        if (res.mode === 'reveal') {
          setReveal({ ...res, id: tk.id })
        } else {
          copySecret(res.value, res.label, res.clear_after).then(okCopy => {
            if (!okCopy) setReveal({ ...res, id: tk.id })
          })
        }
      })
    }
    // Prompts: take the oldest one nobody else answers.
    const current = promptRef.current
    const list = data.prompts || []
    if (current) {
      if (current.finishing) return
      const fresh = list.find(p => p.id === current.id)
      if (!fresh) closePrompt(current.id, 'gone')
      else if (fresh.need !== current.need || fresh.attempts !== current.attempts || fresh.error !== current.error ||
               !!fresh.working !== !!current.working) setPrompt(fresh)
      return
    }
    // A hidden window leaves new dialogs to a visible one (or to the macOS dialog on the host).
    if (!visible) return
    const next = list.find(p => (!p.ack_by && !handled.current.has('p:' + p.id)) || p.ack_by === SURFACE)
    if (!next) return
    handled.current.add('p:' + next.id)
    post(`/prompts/${encodeURIComponent(next.id)}/ack`, { surface: SURFACE }).then(res => {
      if (res && res.ok) {
        setPrompt(res)
        try {
          window.focus()
        } catch {
          /* ignore */
        }
      }
    })
  }, [pending.data])

  function closePrompt(id, outcome, res) {
    if (outcome === 'next' && res) {
      setPrompt(res)
      return
    }
    const cur = promptRef.current
    if (outcome === 'gone' && cur && cur.id === id && (cur.kind === 'unlock' || cur.kind === 'login')) {
      // bw finished in the background. Keep the spinner until the tab's state has caught up
      // (a `bw status` round trip), so the user never sees a closed dialog over a stale "Locked".
      setPrompt({ ...cur, working: true, finishing: true })
      // Refetch until the tab's state agrees the vault is open (or 30 s pass).
      const deadline = Date.now() + 30000
      const isOpen = () => {
        const st = qc.getQueryData(STATE_KEY)
        return !!(st && st.status === 'unlocked' && st.session && st.session.unlocked)
      }
      const settle = async () => {
        while (Date.now() < deadline) {
          try {
            await qc.refetchQueries({ queryKey: STATE_KEY })
          } catch {
            /* keep trying until the deadline */
          }
          if (isOpen()) return
          await new Promise(resolve => setTimeout(resolve, 1000))
        }
      }
      settle()
        .catch(() => {})
        .finally(() => {
          setPrompt(p => (p && p.id === id ? null : p))
          const st = qc.getQueryData(STATE_KEY)
          if (st && st.status === 'unlocked') toast('success', t('s_unlocked'))
          qc.invalidateQueries({ queryKey: ITEMS_KEY })
        })
      return
    }
    setPrompt(null)
    qc.invalidateQueries({ queryKey: STATE_KEY })
    qc.invalidateQueries({ queryKey: ITEMS_KEY })
  }

  return jsxs(Fragment, {
    children: [
      prompt ? jsx(PromptDialog, { prompt, onClose: closePrompt }) : null,
      reveal ? jsx(RevealDialog, { ticket: reveal, onClose: () => setReveal(null) }) : null
    ]
  })
}

/* ------------------------------------------------------------------ status bar chip */

function LockChip() {
  const st = useWardenState(false)
  const s = st.data && st.data.status
  const unlocked = s === 'unlocked' && st.data.session && st.data.session.unlocked
  const label = st.data ? (unlocked ? t('s_unlocked') : statusLabel(s)) : '…'
  return jsxs(Fragment, {
    children: [
      jsx(DialogHostSlot, {}),
      jsxs('button', {
        type: 'button',
        title: `${t('title')}: ${label}`,
        'aria-label': `${t('title')}: ${label}`,
        className: 'flex items-center gap-1 px-1.5 text-[0.6875rem] text-(--ui-text-tertiary) hover:text-(--ui-text-primary)',
        onClick: () => host.navigate(ROUTE),
        children: [jsx(Codicon, { name: unlocked ? 'unlock' : 'lock', size: 12 }), jsx('span', { children: 'Warden' })]
      })
    ]
  })
}

/* ------------------------------------------------------------------ page */

function Section({ title, icon, children, right }) {
  return jsxs('section', {
    className: 'flex flex-col gap-3 rounded-[6px] border border-(--ui-stroke-secondary) p-4',
    children: [
      jsxs('div', {
        className: 'flex items-center justify-between gap-2',
        children: [
          jsxs('h2', {
            className: 'flex items-center gap-2 text-sm font-medium',
            children: [icon ? jsx(Codicon, { name: icon }) : null, title]
          }),
          right || null
        ]
      }),
      children
    ]
  })
}

function Step({ n, done, title, desc, children }) {
  return jsxs('div', {
    className: 'flex gap-3',
    children: [
      jsx('div', {
        className:
          'mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border text-[0.6875rem] ' +
          (done ? 'border-(--ui-accent) text-(--ui-accent)' : 'border-(--ui-stroke-secondary) text-(--ui-text-tertiary)'),
        children: done ? jsx(Codicon, { name: 'check', size: 11 }) : String(n)
      }),
      jsxs('div', {
        className: 'flex min-w-0 flex-1 flex-col gap-1.5',
        children: [
          jsx('div', { className: 'text-sm ' + (done ? 'text-(--ui-text-secondary)' : 'font-medium'), children: title }),
          jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: desc }),
          children ? jsx('div', { className: 'flex flex-wrap items-center gap-2 pt-0.5', children }) : null
        ]
      })
    ]
  })
}

function ExtLink({ href, children }) {
  return jsxs('a', {
    href,
    target: '_blank',
    rel: 'noreferrer noopener',
    className: 'inline-flex items-center gap-1 text-xs text-(--ui-accent) hover:underline',
    children: [children, ' ', jsx(Codicon, { name: 'link-external', size: 11 })]
  })
}

function useAction() {
  const qc = useQueryClient()
  const [busy, setBusy] = useState(null)
  async function run(key, fn, until) {
    setBusy(key)
    try {
      const res = await fn()
      if (res && res.ok === false) toast('error', res.error || t('err'))
      else if (until) {
        // The host answers before the tab's state has caught up: keep the spinner until it has.
        const deadline = Date.now() + 30000
        while (Date.now() < deadline) {
          try {
            await qc.refetchQueries({ queryKey: STATE_KEY })
          } catch {
            /* retry until the deadline */
          }
          if (until(qc.getQueryData(STATE_KEY))) break
          await new Promise(resolve => setTimeout(resolve, 1000))
        }
      }
      return res
    } catch (e) {
      toast('error', String((e && e.message) || e))
      return null
    } finally {
      setBusy(null)
      qc.invalidateQueries({ queryKey: STATE_KEY })
      qc.invalidateQueries({ queryKey: ITEMS_KEY })
    }
  }
  return [busy, run]
}

function SetupCard({ st }) {
  const [busy, run] = useAction()
  const [server, setServer] = useState('')
  const installed = !!st.installed
  const status = st.status
  const loggedIn = installed && status !== 'unauthenticated' && status !== 'not_installed'
  const unlocked = status === 'unlocked' && st.session && st.session.unlocked
  const installing = st.install && st.install.running
  const installResult = st.install && st.install.result
  const installers = st.installers || {}
  const via = installers.homebrew ? 'Homebrew' : installers.npm ? 'npm' : installers.official ? t('official_build') : null

  return jsx(Section, {
    title: t('title'),
    icon: 'shield',
    right: jsxs('div', {
      className: 'flex items-center gap-1.5 text-xs',
      children: [jsx(StatusDot, { tone: STATUS_TONE[unlocked ? 'unlocked' : status] || 'muted' }), statusLabel(unlocked ? 'unlocked' : status)]
    }),
    children: jsxs('div', {
      className: 'flex flex-col gap-4',
      children: [
        jsx(Step, {
          n: 1,
          done: installed,
          title: t('step_install'),
          desc: installed ? `bw ${st.version || ''} · ${st.path || ''}` : t('step_install_d'),
          children: installed
            ? null
            : [
                via
                  ? jsx(Button, {
                      key: 'i',
                      size: 'sm',
                      loading: installing,
                      disabled: installing,
                      onClick: () => run('install', () => post('/install')),
                      children: installing ? t('installing') : `${t('install')} (${t('via')} ${via})`
                    })
                  : jsx('span', { key: 'n', className: 'text-xs text-(--ui-text-tertiary)', children: t('no_installer') }),
                jsx(ExtLink, { key: 'd', href: st.site || 'https://bitwarden.com/download/#downloadable-cli', children: t('download') }),
                jsx(ExtLink, { key: 'h', href: st.docs || 'https://bitwarden.com/help/cli/', children: t('docs') }),
                installResult && !installResult.ok
                  ? jsx('span', { key: 'e', className: 'w-full text-xs text-(--ui-red,var(--destructive))', children: installResult.error })
                  : null
              ]
        }),
        jsx(Step, {
          n: 2,
          done: loggedIn,
          title: t('step_server'),
          desc: installed ? `${t('server')}: ${st.server || 'https://vault.bitwarden.com'}` : t('step_server_d'),
          children:
            installed && !loggedIn
              ? [
                  jsx(Button, { key: 'us', size: 'xs', variant: 'secondary', onClick: () => run('srv', () => post('/server', { url: 'bitwarden.com' })), children: 'bitwarden.com' }),
                  jsx(Button, { key: 'eu', size: 'xs', variant: 'secondary', onClick: () => run('srv', () => post('/server', { url: 'bitwarden.eu' })), children: 'bitwarden.eu' }),
                  jsx(Input, {
                    key: 'in',
                    className: 'h-6 w-56 text-xs',
                    placeholder: 'https://vault.example.com',
                    value: server,
                    onChange: e => setServer(e.target.value)
                  }),
                  jsx(Button, { key: 'set', size: 'xs', disabled: !server, onClick: () => run('srv', () => post('/server', { url: server })), children: t('set') })
                ]
              : null
        }),
        jsx(Step, {
          n: 3,
          done: loggedIn,
          title: t('step_login'),
          desc: loggedIn && st.account ? `${t('account')}: ${st.account}` : t('step_login_d'),
          children: installed
            ? loggedIn
              ? jsx(Button, { size: 'xs', variant: 'ghost', disabled: !!busy, onClick: () => run('logout', () => post('/session/logout')), children: t('logout') })
              : jsx(Button, { size: 'sm', disabled: !!busy, onClick: () => run('login', () => post('/session/login', { surface: SURFACE })), children: t('login') })
            : null
        }),
        jsx(Step, {
          n: 4,
          done: unlocked,
          title: t('step_unlock'),
          desc:
            unlocked && st.session.autolock_remaining != null
              ? `${t('autolock_in')} ${Math.ceil(st.session.autolock_remaining / 60)} min · ${t('last_sync')}: ${st.lastSync ? new Date(st.lastSync).toLocaleString() : '—'}`
              : t('step_unlock_d'),
          children: loggedIn
            ? unlocked
              ? [
                  jsx(Button, { key: 'l', size: 'sm', variant: 'secondary', disabled: !!busy, loading: busy === 'lock', onClick: () => run('lock', () => post('/session/lock'), st => !(st && st.status === 'unlocked' && st.session && st.session.unlocked)), children: [jsx(Codicon, { key: 'i', name: 'lock' }), t('lock')] }),
                  jsx(Button, { key: 's', size: 'sm', variant: 'ghost', loading: busy === 'sync', disabled: !!busy, onClick: () => run('sync', () => post('/session/sync', {}, 240000)), children: t('sync') })
                ]
              : jsx(Button, { size: 'sm', disabled: !!busy, loading: busy === 'unlock', onClick: () => run('unlock', () => post('/session/unlock', { surface: SURFACE })), children: [jsx(Codicon, { key: 'i', name: 'unlock' }), t('unlock')] })
            : null
        }),
        jsxs('div', {
          className: 'flex flex-wrap items-center gap-3 border-t border-(--ui-stroke-secondary) pt-3',
          children: [
            jsx(ExtLink, { href: 'https://bitwarden.com', children: t('site') }),
            jsx(ExtLink, { href: st.docs || 'https://bitwarden.com/help/cli/', children: t('docs') }),
            jsx('span', { className: 'text-[0.6875rem] text-(--ui-text-quaternary)', children: `Hermes Warden ${st.plugin_version || ''}` })
          ]
        })
      ]
    })
  })
}

function SettingsCard({ st }) {
  const [, run] = useAction()
  const sess = st.session || {}
  const auto = String(Math.round((sess.autolock_seconds || 900) / 60))
  const clip = String(sess.clipboard_clear_seconds ?? 30)
  const surf = sess.prompt_surface || 'auto'
  const serveOn = sess.serve && sess.serve.running
  const set = body => run('cfg', () => post('/session/settings', body))
  const row = (label, control) =>
    jsxs('div', {
      className: 'flex flex-wrap items-center justify-between gap-2',
      children: [jsx('span', { className: 'text-xs text-(--ui-text-secondary)', children: label }), control]
    })
  return jsx(Section, {
    title: t('settings'),
    icon: 'settings-gear',
    children: jsxs('div', {
      className: 'flex flex-col gap-3',
      children: [
        row(
          t('autolock'),
          jsx(SegmentedControl, {
            options: Array.from(new Set(['5', '15', '30', '60', auto]))
              .sort((a, b) => Number(a) - Number(b))
              .map(m => ({ id: m, label: `${m} min` })),
            value: auto,
            onChange: v => set({ autolock_minutes: Number(v) })
          })
        ),
        row(
          t('clip_clear'),
          jsx(SegmentedControl, {
            options: Array.from(new Set(['15', '30', '90', clip, '0']))
              .sort((a, b) => (a === '0') - (b === '0') || Number(a) - Number(b))
              .map(s => ({ id: s, label: s === '0' ? t('off') : `${s}s` })),
            value: clip,
            onChange: v => set({ clipboard_clear_seconds: Number(v) })
          })
        ),
        row(
          t('dialogs'),
          jsx(SegmentedControl, {
            options: [
              { id: 'auto', label: t('d_auto') },
              { id: 'desktop', label: t('d_desktop') },
              { id: 'host', label: t('d_host') }
            ],
            value: surf,
            onChange: v => set({ prompt_surface: v })
          })
        ),
        st.status === 'unlocked'
          ? row(
              jsxs('span', { children: [t('serve'), jsx('span', { className: 'block text-[0.6875rem] text-(--ui-text-quaternary)', children: serveOn ? `http://localhost:${sess.serve.port}` : t('serve_d') })] }),
              jsx(Button, {
                size: 'xs',
                variant: serveOn ? 'secondary' : 'ghost',
                onClick: () => run('serve', () => post(serveOn ? '/serve/stop' : '/serve/start', {})),
                children: serveOn ? t('stop') : t('start')
              })
            )
          : null
      ]
    })
  })
}

function ItemRow({ item, clearAfter }) {
  const [busy, setBusy] = useState(null)
  async function copy(field, label) {
    setBusy(field)
    try {
      const res = await post('/reveal', { item: item.id, field })
      if (res && res.ok && typeof res.value === 'string') {
        await copySecret(res.value, `${item.name}: ${label}`, res.clear_after ?? clearAfter)
        post('/session/lock').catch(() => {})
      }
      else toast('error', (res && res.error) || t('err'))
    } finally {
      setBusy(null)
    }
  }
  const has = key => Array.isArray(item.has_fields) && item.has_fields.includes(key)
  const icon = { login: 'globe', card: 'credit-card', identity: 'account', secure_note: 'note', ssh_key: 'key',
    bank_account: 'library', drivers_license: 'credit-card', passport: 'globe' }[item.type] || 'circle-small'
  // `word` (optional) puts a short label beside the icon, for the copies people use most.
  // `noun` names the field in the "copied" toast ("GitHub: Password copied"); defaults to `label`.
  const iconBtn = (field, label, name, word, noun) =>
    jsx(Button, {
      size: word ? 'xs' : 'icon-xs',
      variant: 'ghost',
      title: label,
      'aria-label': label,
      loading: busy === field,
      disabled: !!busy,
      onClick: () => copy(field, noun || label),
      children: word ? [jsx(Codicon, { key: 'i', name }), word] : jsx(Codicon, { name })
    })
  return jsxs('div', {
    className: 'group flex items-center gap-2 rounded-[4px] px-2 py-1.5 hover:bg-(--ui-row-hover,transparent)',
    children: [
      jsx(Codicon, { name: icon, className: 'text-(--ui-text-tertiary)' }),
      jsxs('div', {
        className: 'flex min-w-0 flex-1 flex-col',
        children: [
          jsxs('span', {
            className: 'truncate text-sm',
            children: [item.name, item.favorite ? jsx(Codicon, { name: 'star-full', size: 10, className: 'ml-1 text-(--ui-text-quaternary)' }) : null]
          }),
          jsx('span', { className: 'truncate text-[0.6875rem] text-(--ui-text-tertiary)', children: [item.username, item.uri || item.card].filter(Boolean).join(' · ') })
        ]
      }),
      jsxs('div', {
        className: 'flex shrink-0 items-center gap-0.5',
        children: [
          item.username ? iconBtn('username', t('copy_user'), 'person', t('btn_user'), t('username')) : null,
          item.has_password ? iconBtn('password', t('copy_pass'), 'key', t('btn_pass'), t('password')) : null,
          item.has_totp ? iconBtn('totp', t('copy_totp'), 'watch', null, 'TOTP') : null,
          item.type === 'card' ? iconBtn('card_number', 'Card number', 'credit-card') : null,
          item.type === 'secure_note' ? iconBtn('notes', 'Notes', 'note') : null,
          has('bankAccount.accountNumber') ? iconBtn('account_number', 'Account number', 'library') : null,
          has('bankAccount.iban') ? iconBtn('iban', 'IBAN', 'library') : null,
          has('driversLicense.licenseNumber') ? iconBtn('license_number', 'License number', 'credit-card') : null,
          has('passport.passportNumber') ? iconBtn('passport_number', 'Passport number', 'globe') : null
        ]
      })
    ]
  })
}

function VaultCard({ st }) {
  const [search, setSearch] = useState('')
  const [debounced, setDebounced] = useState('')
  useEffect(() => {
    const h = setTimeout(() => setDebounced(search.trim()), 250)
    return () => clearTimeout(h)
  }, [search])
  const unlocked = st.status === 'unlocked' && st.session && st.session.unlocked
  const q = useQuery({
    queryKey: [...ITEMS_KEY, debounced],
    queryFn: () => api(`/items?search=${encodeURIComponent(debounced)}&limit=200`),
    enabled: !!unlocked,
    staleTime: 15000
  })
  const items = (q.data && q.data.items) || []
  return jsx(Section, {
    title: t('vault'),
    icon: 'database',
    right: unlocked && q.data && q.data.ok ? jsx(Badge, { variant: 'muted', children: String(q.data.count) }) : null,
    children: unlocked
      ? jsxs('div', {
          className: 'flex flex-col gap-2',
          children: [
            jsx(SearchField, { placeholder: t('search'), value: search, onChange: setSearch, loading: q.isFetching }),
            jsx('div', {
              className: 'flex max-h-[26rem] flex-col overflow-y-auto',
              children: items.length
                ? items.map(it => jsx(ItemRow, { key: it.id, item: it, clearAfter: st.session.clipboard_clear_seconds }))
                : q.isFetching
                ? jsxs('div', {
                    role: 'status',
                    className: 'flex items-center justify-center gap-1.5 py-6 text-xs text-(--ui-text-tertiary)',
                    children: [jsx(Codicon, { key: 'i', name: 'loading', size: 12, className: 'animate-spin' }), t('loading_vault')]
                  })
                : jsx('div', { className: 'py-6 text-center text-xs text-(--ui-text-tertiary)', children: (q.data && q.data.error) || t('no_items') })
            })
          ]
        })
      : jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: t('locked_hint') })
  })
}

function GeneratorCard({ st }) {
  const [kind, setKind] = useState('password')
  const [length, setLength] = useState('24')
  const [value, setValue] = useState('')
  const [shown, setShown] = useState(false)
  const [busy, setBusy] = useState(false)
  useEffect(() => () => setValue(''), [])
  async function gen() {
    setBusy(true)
    try {
      const options = kind === 'passphrase' ? { passphrase: true, words: 5, separator: '-', capitalize: true, include_number: true } : { length: Number(length), special: true }
      const res = await post('/generate', { options })
      if (res && res.ok) {
        setValue(res.value)
        setShown(false)
      } else toast('error', (res && res.error) || t('err'))
    } finally {
      setBusy(false)
    }
  }
  if (!st.installed) return null
  return jsx(Section, {
    title: t('generator'),
    icon: 'symbol-key',
    children: jsxs('div', {
      className: 'flex flex-col gap-2',
      children: [
        jsxs('div', {
          className: 'flex flex-wrap items-center gap-2',
          children: [
            jsx(SegmentedControl, {
              options: [
                { id: 'password', label: t('password') },
                { id: 'passphrase', label: t('passphrase') }
              ],
              value: kind,
              onChange: setKind
            }),
            kind === 'password'
              ? jsx(SegmentedControl, {
                  options: ['16', '24', '32', '48'].map(n => ({ id: n, label: n })),
                  value: length,
                  onChange: setLength
                })
              : null,
            jsx(Button, { size: 'sm', loading: busy, disabled: busy, onClick: gen, children: t('generate') })
          ]
        }),
        value
          ? jsxs('div', {
              className: 'flex items-center gap-2',
              children: [
                jsx('code', {
                  className: 'min-w-0 flex-1 truncate rounded-[4px] border border-(--ui-stroke-secondary) px-2 py-1 font-mono text-xs',
                  children: shown ? value : '•'.repeat(Math.min(32, value.length))
                }),
                jsx(Button, { size: 'xs', variant: 'ghost', onClick: () => setShown(s => !s), children: shown ? t('hide') : t('reveal') }),
                jsx(Button, { size: 'xs', onClick: () => { copySecret(value, t('password'), (st.session && st.session.clipboard_clear_seconds) ?? 30).finally(() => post('/session/lock').catch(() => {})) }, children: t('copy') })
              ]
            })
          : null
      ]
    })
  })
}

function WardenPage() {
  const st = useWardenState(true)
  const data = st.data
  return jsx('div', {
    className: 'h-full overflow-y-auto',
    children: jsxs('div', {
      className: 'mx-auto flex w-full max-w-[52rem] flex-col gap-4 p-6',
      children: [
        jsxs('header', {
          className: 'flex items-center gap-3',
          children: [
            jsx(Codicon, { name: 'lock', size: 22, className: 'text-(--ui-accent)' }),
            jsxs('div', {
              children: [
                jsx('h1', { className: 'text-lg font-semibold', children: t('title') }),
                jsx('p', { className: 'text-xs text-(--ui-text-tertiary)', children: t('subtitle') })
              ]
            })
          ]
        }),
        !data
          ? jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: st.error ? String(st.error.message || st.error) : '…' })
          : jsxs(Fragment, {
              children: [
                data.ok === false && data.error ? jsx('div', { role: 'alert', className: 'text-xs text-(--ui-red,var(--destructive))', children: data.error }) : null,
                jsx(SetupCard, { st: data }),
                data.installed ? jsx(VaultCard, { st: data }) : null,
                jsx(GeneratorCard, { st: data }),
                data.installed ? jsx(SettingsCard, { st: data }) : null,
                jsx(Section, {
                  title: t('agent'),
                  icon: 'hubot',
                  children: jsx('p', { className: 'text-xs text-(--ui-text-secondary)', children: t('agent_d') })
                })
              ]
            })
      ]
    })
  })
}

/* ------------------------------------------------------------------ registration */

export default {
  id: ID,
  name: 'Hermes Warden',
  register(ctx) {
    rest = ctx.rest || null
    if (ctx.i18n && typeof ctx.i18n.register === 'function') {
      ctx.i18n.register(STRINGS)
      i18n = ctx.i18n
    }
    ctx.register({ id: 'page', area: ROUTES_AREA, data: { path: ROUTE }, render: () => jsx(WardenPage, {}) })
    ctx.register({ id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: ROUTE, label: 'Warden', codicon: 'lock' } })
    ctx.register({ id: 'chip', area: STATUSBAR_AREAS.right, order: 140, render: () => jsx(LockChip, {}) })
    // center, not left/right: a left/right contribution makes every plugin page "own" the title bar.
    ctx.register({ id: 'dialogs', area: TITLEBAR_AREAS.center, order: 999, render: () => jsx(DialogHostSlot, {}) })
    const cmd = (id, label, run, keywords) => ctx.register({ id, area: PALETTE_AREA, data: { id: `${ID}.${id}`, label, run, keywords: ['bitwarden', 'warden', 'vault', ...(keywords || [])] } })
    cmd('open', t('open'), () => host.navigate(ROUTE), ['lock', 'password'])
    cmd('unlock', `Hermes Warden: ${t('unlock')}`, () => post('/session/unlock', { surface: SURFACE }), ['unlock'])
    cmd('lock', `Hermes Warden: ${t('lock')}`, () => post('/session/lock').then(() => toast('info', t('s_locked'))), ['lock'])
    cmd('sync', `Hermes Warden: ${t('sync')}`, () => post('/session/sync', {}, 240000).then(r => r && r.ok && toast('success', t('done'))), ['sync'])
  }
}
