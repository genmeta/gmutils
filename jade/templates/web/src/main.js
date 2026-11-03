import './style.css';

// The frontend-only template has no API. Fullstack reads the verified caller in Rust.
const apiPath = __JADE_API__;
const projectName = '__JADE_NAME__';
const root = document.documentElement;
const name = document.querySelector('#identity-name');
const identity = document.querySelector('.identity');
const status = document.querySelector('.status');
const retry = document.querySelector('.retry');
const toggle = document.querySelector('.language-toggle');
const storageKey = `${projectName}-language`;
const copy = {
  en: {
    skip: 'Skip to content', eyebrow: 'Your name is', checking: 'Checking…',
    authenticated: 'Identity verified by DHTTP', anonymous: 'No name identity provided',
    loading: 'Reading your name identity', error: 'Unable to read your identity',
    unavailable: 'Unavailable', retry: 'Try again',
    headline: 'One name. A world of possibilities.',
    introduction: 'Welcome to your new application. Start with a name, make it your own, and share it with the world.',
    explore: 'Explore DHTTP ↗', identityTitle: 'A name you can verify',
    identityCopy: 'The server reads your identity from the authenticated connection.',
    connectionTitle: 'A simple connection', connectionCopy: 'This page calls a Rust API running in Pishoo.',
    startTitle: 'A place to begin', startCopy: 'Change this page and build something of your own.',
    webEyebrow: 'Hello, world', webStatus: 'Your application is ready',
    webIdentityCopy: 'Give your application a home on DHTTP.',
    webConnectionCopy: 'A lightweight frontend, ready for your ideas.',
  },
  zh: {
    skip: '跳到正文', eyebrow: '您的名字是', checking: '正在识别…',
    authenticated: '身份已由 DHTTP 验证', anonymous: '未提供名字身份',
    loading: '正在读取您的名字身份', error: '无法读取您的身份',
    unavailable: '暂时不可用', retry: '重试',
    headline: '一个名字，无限可能。',
    introduction: '欢迎来到您的新应用。从一个名字开始，让想法在这里生长，再与世界分享。',
    explore: '了解 DHTTP ↗', identityTitle: '可以验证的名字',
    identityCopy: '服务端从已认证的连接中读取您的身份。',
    connectionTitle: '简单直接的连接', connectionCopy: '这个页面正在调用运行于 Pishoo 的 Rust API。',
    startTitle: '从这里开始', startCopy: '修改这个页面，创造属于您的应用。',
    webEyebrow: '你好，世界', webStatus: '您的应用已就绪',
    webIdentityCopy: '为您的应用在 DHTTP 上安个家。',
    webConnectionCopy: '轻量的前端，等待您的创意。',
  },
};
let language = 'en';
try {
  const saved = localStorage.getItem(storageKey);
  if (saved === 'en' || saved === 'zh') language = saved;
} catch { /* Language switching still works without storage. */ }
let state = { kind: 'loading', name: null };

function render() {
  const text = copy[language];
  root.lang = language === 'zh' ? 'zh-CN' : 'en';
  document.querySelectorAll('[data-i18n]').forEach(element => {
    element.textContent = text[element.dataset.i18n];
  });
  toggle.textContent = language === 'zh' ? 'English' : '中文';
  toggle.lang = language === 'zh' ? 'en' : 'zh-CN';
  toggle.setAttribute('aria-label', language === 'zh' ? 'Switch to English' : '切换到中文');
  if (apiPath) {
    const displayName = state.name?.replace(/\.dhttp\.net$/, '');
    name.textContent = displayName ?? (state.kind === 'error' ? text.unavailable : text.checking);
    status.textContent = text[state.kind];
  } else {
    name.textContent = projectName;
    document.querySelector('.eyebrow').textContent = text.webEyebrow;
    document.querySelector('[data-i18n="identityCopy"]').textContent = text.webIdentityCopy;
    document.querySelector('[data-i18n="connectionCopy"]').textContent = text.webConnectionCopy;
    status.textContent = text.webStatus;
  }
  status.dataset.state = apiPath ? state.kind : 'ready';
  identity.setAttribute('aria-busy', String(Boolean(apiPath) && state.kind === 'loading'));
  retry.hidden = !apiPath || state.kind !== 'error';
}

async function loadIdentity() {
  state = { kind: 'loading', name: null };
  render();
  try {
    const response = await fetch(apiPath, {
      cache: 'no-store', headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    if (typeof payload.name !== 'string' || !payload.name.trim()) throw new Error('Invalid identity');
    state = { kind: payload.name === 'anonymous' ? 'anonymous' : 'authenticated', name: payload.name };
  } catch {
    state = { kind: 'error', name: null };
  }
  render();
}

toggle.addEventListener('click', () => {
  language = language === 'zh' ? 'en' : 'zh';
  try { localStorage.setItem(storageKey, language); } catch { /* Optional preference. */ }
  render();
});
retry.addEventListener('click', loadIdentity);
toggle.hidden = false;
render();
if (apiPath) {
  const link = document.querySelector('.api-link');
  link.href = apiPath;
  link.hidden = false;
  loadIdentity();
}
