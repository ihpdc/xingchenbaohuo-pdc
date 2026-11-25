// 登录模块：TeleAgent（天翼星辰）账号密码登录 → 换取 operationToken（JWT）
//
// 平台 2026-11 改成「登录流（loginFlow）」授权：accountNameLogin 返回的 code 只有在同一个
// uc_login_flow 会话里兑换才会绑定用户；否则 /cowork/auth 会 302 回 /teleagent，并种一个
// 空的 operationToken（面板日志里 operationToken:0 就是这个）。
// 而且这条链跨 teleai.com.cn / www.teleai.com.cn / agent.teleai.com.cn 三个域，
// 必须用「按域匹配」的 cookie jar 串起来，旧代码的扁平对象 + 新建空 jar 正是断点。
//
//   1. GET  /aicloud-api/upms/public/auth/authorize   建立 loginFlow（Set-Cookie: uc_login_flow）
//   2. GET  /master-auth                              登录页落地，补齐 uc_browser_context / uc_route_seed
//   3. GET  /teleai-api/upms/public/auth/getRsaPublicKey   取 RSA 公钥 + keyId
//   4. POST /teleai-api/upms/public/captcha/get       blockPuzzle 滑块（本地解码缺口，自动通过）
//   5. POST /teleai-api/upms/public/auth/accountNameLogin  密码装在 AES-128-GCM 密文里（密钥经 RSA-OAEP 封装）
//   6. GET  登录返回的 redirectUri（带 code）          → Set-Cookie: operationToken
//
// 密码本地加密存储：AES-256-GCM（密钥 = data/.secret，随机生成，data/ 不入库）
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const API = 'https://www.teleai.com.cn/teleai-api';
const UPMS = 'https://www.teleai.com.cn/aicloud-api';
const SUPER_CLIENT_ID = 'Z2veLLEHhZfq3hb5hWIwqJuPajIuasYi';
// agent 域 BFF 的规范回跳地址：新版前端固定用 ?appVersion=（source/state 已废弃）
const SUPER_REDIRECT = 'https://agent.teleai.com.cn/superCowork/sapi/cowork/auth?appVersion=';
const CALLBACK_ORIGIN = new URL(SUPER_REDIRECT).origin;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/137.0.0.0';
const REFERER = 'https://www.teleai.com.cn/master-auth';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64 = (b) => Buffer.from(b).toString('base64');

function validateCallbackUrl(value, base) {
  let url;
  try {
    url = new URL(value, base);
  } catch {
    throw new Error('服务端返回的回跳地址无效');
  }
  if (url.protocol !== 'https:' || url.origin !== CALLBACK_ORIGIN || url.username || url.password) {
    throw new Error('服务端返回的回跳地址不在受信任的来源内');
  }
  return url;
}

// 跳转链兜底：只允许 teleai 自家域，且必须是 https（防止被重定向到外站）
function validateHopUrl(value, base) {
  let url;
  try {
    url = new URL(value, base);
  } catch {
    throw new Error('跳转链地址无效');
  }
  const host = url.hostname.toLowerCase();
  const ok = ['teleai.com.cn', 'teleai.com.cn.', 'agent.teleai.com.cn', 'www.teleai.com.cn'];
  const trusted = ok.includes(host) || host.endsWith('.teleai.com.cn');
  if (url.protocol !== 'https:' || !trusted || url.username || url.password) {
    throw new Error('跳转链跳到了非受信域名');
  }
  return url;
}

// 判断拿到的是不是真票据（防止把空值/占位串当凭据落盘）。
// 注意：operationToken 实测是 376 字符的不透明串，不是 JWT，别按 JWT 三段式校验。
function looksLikeToken(v) {
  const s = String(v || '').trim();
  if (s.length < 64) return false;
  if (/\s/.test(s)) return false;
  return !['undefined', 'null', 'false', '0'].includes(s.toLowerCase());
}

// 极简「按域匹配」cookie jar。
// 登录流 cookie 分散在 teleai.com.cn（Domain=teleai.com.cn）、www.teleai.com.cn（host-only）
// 和 agent.teleai.com.cn 三处；扁平对象会互相覆盖，也不会按域回送。
class CookieJar {
  constructor() { this.items = []; }

  static parse(line, reqUrl) {
    const parts = String(line).split(';');
    const nv = parts.shift() || '';
    const eq = nv.indexOf('=');
    if (eq <= 0) return null;
    const name = nv.slice(0, eq).trim();
    const value = nv.slice(eq + 1).trim();
    const host = new URL(reqUrl).hostname.toLowerCase();
    let domain = host;
    let hostOnly = true;
    let cookiePath = '/';
    let expires = 0;
    for (const p of parts) {
      const i = p.indexOf('=');
      const k = (i < 0 ? p : p.slice(0, i)).trim().toLowerCase();
      const v = i < 0 ? '' : p.slice(i + 1).trim();
      if (k === 'domain' && v) { domain = v.replace(/^\./, '').toLowerCase(); hostOnly = false; }
      else if (k === 'path' && v) cookiePath = v;
      else if (k === 'max-age') { const n = parseInt(v, 10); if (!Number.isNaN(n)) expires = Date.now() + n * 1000; }
      else if (k === 'expires') { const t = Date.parse(v); if (!Number.isNaN(t)) expires = t; }
    }
    return { name, value, domain, hostOnly, path: cookiePath, expires };
  }

  absorb(res, reqUrl) {
    const lines = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    const accepted = [];
    for (const line of lines) {
      const c = CookieJar.parse(line, reqUrl);
      if (!c) continue;
      const same = (x) => x.name === c.name && x.domain === c.domain && x.path === c.path;
      // 空值 = 服务端在清除这个 cookie（换票成功后它会清掉 uc_login_flow，并往 agent 域
      // 种一个 operationToken= 空值）。只清掉对应域的那条，绝不覆盖别处的有效票据。
      if (!c.value) {
        this.items = this.items.filter((x) => !same(x));
        continue;
      }
      this.items = this.items.filter((x) => !same(x));
      if (c.expires && c.expires <= Date.now()) continue;
      this.items.push(c);
      accepted.push(c);
    }
    return accepted;
  }

  header(url) {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    const p = u.pathname || '/';
    return this.items
      .filter((c) => {
        if (c.expires && c.expires <= Date.now()) return false;
        const domOk = c.hostOnly ? host === c.domain : (host === c.domain || host.endsWith('.' + c.domain));
        return domOk && p.startsWith(c.path);
      })
      .map((c) => `${c.name}=${c.value}`)
      .join('; ');
  }

  // 取有效值：同名多域时优先非空、其次最长（空值/占位串一律视为无效）
  get(name) {
    const list = this.items.filter((c) => c.name === name && c.value);
    if (!list.length) return '';
    return list.map((c) => c.value).sort((a, b) => b.length - a.length)[0];
  }

  // 日志用：只打名字和长度，不打值
  describe() {
    if (!this.items.length) return 'none';
    return this.items.map((c) => `${c.name}:${String(c.value).length}@${c.domain}`).join(',');
  }
}

class Login {
  constructor(dataDir, log) {
    this.dataDir = dataDir;
    this.log = log;
    this.jar = new CookieJar();
  }

  jwtPath() { return path.join(this.dataDir, 'jwt.txt'); }

  // ---------- HTTP（所有请求共用同一 jar，自动带 Cookie / 收 Set-Cookie） ----------
  async req(url, { method = 'POST', body, headers = {}, redirect } = {}) {
    const target = new URL(url);
    const isAgent = target.hostname.endsWith('agent.teleai.com.cn');
    const h = {
      'User-Agent': UA,
      Accept: 'application/json, text/plain, */*',
      Referer: isAgent ? 'https://agent.teleai.com.cn/teleagent' : REFERER,
      ...headers,
    };
    // 浏览器只在跨域 XHR 带 Origin；对 agent 域顶层跳转带上官网 Origin 反而更像异常流量
    if (!isAgent && !h.Origin) h.Origin = 'https://www.teleai.com.cn';
    const cookie = this.jar.header(url);
    if (cookie && !h.Cookie) h.Cookie = cookie;
    if (body !== undefined) h['Content-Type'] = 'application/json';
    try {
      const res = await fetch(target.toString(), {
        method,
        headers: h,
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: redirect || 'follow',
        signal: AbortSignal.timeout(20000),
      });
      this.jar.absorb(res, url);
      return res;
    } catch (e) {
      if (e.name === 'TimeoutError' || e.name === 'AbortError') {
        throw new Error(`请求超时（20s）：${target.host}，部署机到该域名网络不通或过慢`);
      }
      if (e.cause && e.cause.code) throw new Error(`网络错误 ${e.cause.code}: ${target.host}`);
      throw e;
    }
  }

  async postJson(p, body) {
    const res = await this.req(API + p, { body });
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch (e) {
      throw new Error(`${p} 响应非 JSON（HTTP ${res.status}）`);
    }
  }

  // ---------- 登录流：先 authorize，拿到 uc_login_flow 等 cookie ----------
  async startLoginFlow() {
    const url = `${UPMS}/upms/public/auth/authorize?client_id=${encodeURIComponent(SUPER_CLIENT_ID)}`
      + `&redirect_uri=${encodeURIComponent(SUPER_REDIRECT)}`;
    let current = url;
    for (let hop = 0; hop < 4 && current; hop++) {
      const host = new URL(current).host;
      const res = await this.req(current, {
        method: 'GET',
        redirect: 'manual',
        headers: { Accept: 'text/html,application/xhtml+xml,*/*;q=0.8', Referer: 'https://agent.teleai.com.cn/' },
      });
      this.log.info('Login', `登录流第 ${hop + 1} 跳 ${host} status=${res.status} cookie=[${this.jar.describe()}]`);
      const loc = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && loc) {
        current = new URL(loc, current).toString();
        continue;
      }
      break;
    }
    if (!this.jar.get('uc_login_flow')) {
      // 不致命：平台以后可能换实现，留痕便于排查
      this.log.warn('Login', '未拿到 uc_login_flow，按兼容路径继续登录');
    }
  }

  // ---------- 极简 PNG 解码（8bit 非隔行 RGB/RGBA，够用于滑块图） ----------
  decodePng(buf) {
    if (buf.readUInt32BE(0) !== 0x89504e47) throw new Error('不是 PNG');
    let off = 8;
    let width = 0, height = 0, bitDepth = 0, colorType = 0;
    const idat = [];
    while (off < buf.length) {
      const len = buf.readUInt32BE(off);
      const type = buf.toString('ascii', off + 4, off + 8);
      const data = buf.slice(off + 8, off + 8 + len);
      if (type === 'IHDR') {
        width = data.readUInt32BE(0); height = data.readUInt32BE(4);
        bitDepth = data[8]; colorType = data[9];
        if (data[12] !== 0) throw new Error('不支持隔行 PNG');
      } else if (type === 'IDAT') idat.push(data);
      else if (type === 'IEND') break;
      off += 12 + len;
    }
    if (bitDepth !== 8 || (colorType !== 2 && colorType !== 6)) throw new Error('不支持的 PNG 格式');
    const ch = colorType === 6 ? 4 : 3;
    const raw = zlib.inflateSync(Buffer.concat(idat));
    const stride = width * ch;
    const out = Buffer.alloc(height * stride);
    let pos = 0;
    for (let y = 0; y < height; y++) {
      const filter = raw[pos++];
      const line = raw.slice(pos, pos + stride); pos += stride;
      const cur = out.slice(y * stride, (y + 1) * stride);
      const prev = y > 0 ? out.slice((y - 1) * stride, y * stride) : Buffer.alloc(stride);
      for (let x = 0; x < stride; x++) {
        const a = x >= ch ? cur[x - ch] : 0;
        const b = prev[x];
        const c = x >= ch ? prev[x - ch] : 0;
        let v = line[x];
        if (filter === 1) v += a;
        else if (filter === 2) v += b;
        else if (filter === 3) v += (a + b) >> 1;
        else if (filter === 4) {
          const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
          v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
        }
        cur[x] = v & 0xff;
      }
    }
    return { width, height, ch, data: out };
  }

  // 找原图里白色描边的拼图缺口，返回拖拽距离（缺口左上角 x - 2）
  solveOffset(origPng) {
    const img = this.decodePng(origPng);
    const { width, height, ch, data } = img;
    const isWhite = (x, y) => {
      const i = (y * width + x) * ch;
      const r = data[i], g = data[i + 1], b = data[i + 2];
      return Math.min(r, g, b) > 225 && Math.max(r, g, b) - Math.min(r, g, b) < 18;
    };
    const seen = new Uint8Array(width * height);
    let best = null;
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        if (seen[y * width + x] || !isWhite(x, y)) continue;
        const stack = [[x, y]];
        seen[y * width + x] = 1;
        let n = 0, minX = x, minY = y;
        while (stack.length) {
          const [cx, cy] = stack.pop();
          n++;
          if (cx < minX) minX = cx;
          if (cy < minY) minY = cy;
          for (let dy = -1; dy <= 1; dy++) {
            for (let dx = -1; dx <= 1; dx++) {
              const nx = cx + dx, ny = cy + dy;
              if (nx < 0 || ny < 0 || nx >= width || ny >= height) continue;
              if (seen[ny * width + nx]) continue;
              if (!isWhite(nx, ny)) continue;
              seen[ny * width + nx] = 1;
              stack.push([nx, ny]);
            }
          }
        }
        if (n > 60 && (!best || n > best.n)) best = { n, x: minX, y: minY };
      }
    }
    if (!best) throw new Error('滑块图未识别到缺口');
    return Math.max(0, best.x - 2);
  }

  aesEcbBase64(key, plain) {
    const c = crypto.createCipheriv('aes-128-ecb', Buffer.from(key, 'utf8'), null);
    return b64(Buffer.concat([c.update(plain, 'utf8'), c.final()]));
  }

  // ---------- 滑块（最多 6 轮；间隔 2s 避免触发风控） ----------
  async solveCaptcha() {
    for (let i = 0; i < 6; i++) {
      if (i > 0) await sleep(2000);
      const r = await this.postJson('/upms/public/captcha/get', { captchaType: 'blockPuzzle' });
      const d = r && r.repData;
      if (!d || !d.originalImageBase64) throw new Error('验证码图获取失败');
      let x;
      try {
        x = this.solveOffset(Buffer.from(d.originalImageBase64, 'base64'));
      } catch (e) {
        this.log.warn('Login', `滑块图识别失败（第 ${i + 1} 次）：${e.message}，换一张`);
        continue;
      }
      const pointJson = JSON.stringify({ x, y: 5 });
      const check = await this.postJson('/upms/public/captcha/check', {
        captchaType: 'blockPuzzle',
        pointJson: this.aesEcbBase64(d.secretKey, pointJson),
        token: d.token,
      });
      if (check && check.repCode === '0000') {
        this.log.info('Login', `滑块已自动通过（x=${x}，第 ${i + 1} 次）`);
        return { captchaVerification: this.aesEcbBase64(d.secretKey, `${d.token}---${pointJson}`) };
      }
      this.log.warn('Login', `滑块校验未通过（x=${x}），换一张重试（第 ${i + 1} 次）`);
    }
    throw new Error('滑块连续 6 次未通过');
  }

  // ---------- 账号密码登录 → operationToken ----------
  async loginByPassword(account, password) {
    if (!account || !password) throw new Error('账号或密码为空');
    account = String(account).trim().toLowerCase();  // AAD 绑定：服务端按小写账号解密

    // 0) 建立登录流（顺序不能反：登录前就要有 uc_login_flow）
    this.jar = new CookieJar();
    await this.startLoginFlow();

    const keyRes = await this.req(`${API}/upms/public/auth/getRsaPublicKey`, { method: 'GET' }).then((r) => r.json());
    if (!keyRes || keyRes.code !== '10980001') throw new Error(`获取公钥失败: ${keyRes && keyRes.message}`);
    const { publicKey, keyId } = keyRes.data;

    const captcha = await this.solveCaptcha();

    const aesKey = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const timestamp = Date.now();
    const requestId = crypto.randomUUID();
    const aad = `loginName=${account}&keyId=${keyId}&timestamp=${timestamp}&requestId=${requestId}&clientId=${SUPER_CLIENT_ID}`;

    const gcm = crypto.createCipheriv('aes-128-gcm', aesKey, iv);
    gcm.setAAD(Buffer.from(aad, 'utf8'));
    const ct = Buffer.concat([gcm.update(password, 'utf8'), gcm.final()]);
    const tag = gcm.getAuthTag();

    const pub = crypto.createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' });
    const encryptedKeyIv = crypto.publicEncrypt(
      { key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.concat([aesKey, iv]),
    );

    const body = {
      loginName: account,
      keyId,
      timestamp,
      requestId,
      redirectUri: SUPER_REDIRECT,
      clientId: SUPER_CLIENT_ID,
      encryptedKeyIv: b64(encryptedKeyIv),
      ciphertext: b64(ct),
      tag: b64(tag),
      invitationCode: '',
      captchaCheckResult: captcha,
      publicKey,
    };

    const loginRes = await this.req(`${API}/upms/public/auth/accountNameLogin`, {
      method: 'POST',
      body,
      headers: { Origin: 'https://www.teleai.com.cn', Referer: REFERER },
    });
    const login = await loginRes.json().catch(() => null);
    this.log.info('Login', `登录响应 cookie=[${this.jar.describe()}]`);
    if (!login || login.code !== '10980001') {
      const msg = (login && login.message) || '登录失败';
      const code = login && login.code;
      const err = new Error(code ? `${msg}（code=${code}）` : msg);
      err.code = code;
      throw err;
    }
    const data = login.data || {};
    this.log.info('Login', `密码校验通过，账号 ${account}`);

    // 服务端返回 data.redirectUri = superCowork 入口 + ?code=xxx（一次性票据，绑在登录流上）
    const redirect = validateCallbackUrl(data.redirectUri || SUPER_REDIRECT);
    this.log.info('Login', `回跳地址 ${redirect.host}${redirect.pathname} 带 code=${redirect.searchParams.has('code')}`);

    const token = await this.exchangeCodeForToken(redirect.toString());
    if (!looksLikeToken(token)) {
      throw new Error('换票失败：服务端没有返回有效的 operationToken（登录流 cookie 未生效）');
    }
    // 真正判据：拿票据打一次平台接口。换票成功但票据不可用，会在这一步暴露，
    // 而不是等到几分钟后保活报 401 才发现。
    const usable = await this.verifyToken(token);
    if (!usable.ok) {
      throw new Error(`换票得到的 operationToken 不可用（${usable.reason}），请稍后重试`);
    }
    this.log.info('Login', `已换取 operationToken（长度 ${token.length}）`);
    return { operationToken: token, expiresAt: data.expiresAt || 0, refreshToken: data.refreshToken || '' };
  }

  // 用票据调一次平台接口，确认它真的能用（不记录票据本身）
  async verifyToken(token) {
    try {
      const res = await fetch('https://agent.teleai.com.cn/teleagent-manager/v1/service/status', {
        method: 'GET',
        headers: {
          'User-Agent': UA,
          'Content-Type': 'application/json',
          Cookie: `operationToken=${token}`,
          'x-client-platform': 'web',
          Referer: 'https://agent.teleai.com.cn/teleagent',
        },
        signal: AbortSignal.timeout(20000),
      });
      const text = await res.text();
      if (res.ok) return { ok: true };
      return { ok: false, reason: `HTTP ${res.status} ${String(text).slice(0, 80)}` };
    } catch (e) {
      return { ok: false, reason: e.message };
    }
  }

  // 用 code 换 operationToken：先直接 GET 回跳地址，必要时顺跳转链
  async exchangeCodeForToken(startUrl) {
    const first = await this.req(startUrl, { method: 'GET', redirect: 'manual' });
    const direct = this.jar.get('operationToken');
    this.log.info('Login', `回跳 status=${first.status} cookie=[${this.jar.describe()}]`);
    if (looksLikeToken(direct)) return direct;

    const loc = first.headers.get('location');
    if (!(first.status >= 300 && first.status < 400 && loc)) {
      const html = await first.text().catch(() => '');
      const m = html.match(/window\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]/)
        || html.match(/location\.replace\(\s*['"]([^'"]+)['"]\s*\)/);
      if (!m) return '';
      return this.followRedirectForToken(new URL(m[1], startUrl).toString());
    }
    return this.followRedirectForToken(new URL(loc, startUrl).toString());
  }

  // 跟随跳转链 → operationToken（同一 jar 跨跳累积 cookie）
  async followRedirectForToken(startUrl) {
    let current = validateHopUrl(startUrl);
    for (let hop = 0; hop < 10 && current; hop++) {
      const host = new URL(current).host;
      let res;
      try {
        res = await this.req(current, {
          method: 'GET',
          redirect: 'manual',
          headers: { Accept: 'text/html,application/xhtml+xml,*/*;q=0.8' },
        });
      } catch {
        throw new Error(`跳转链请求失败（${host}）`);
      }
      const token = this.jar.get('operationToken');
      this.log.info('Login', `跳转链第 ${hop + 1} 跳 ${host} status=${res.status} cookie=[${this.jar.describe()}]`);
      if (looksLikeToken(token)) return token;
      const loc = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && loc) {
        current = validateHopUrl(loc, current);
        continue;
      }
      const html = await res.text().catch(() => '');
      const m = html.match(/window\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]/)
        || html.match(/location\.replace\(\s*['"]([^'"]+)['"]\s*\)/);
      if (m) {
        current = validateHopUrl(m[1], current);
        continue;
      }
      break;
    }
    return this.jar.get('operationToken');
  }

  // ---------- 本地密码加密存储（AES-256-GCM，密钥在 data/.secret） ----------
  // 读已存在的密钥；readOnly=true 时绝不新建（否则会把「密钥丢了」伪装成「密码错误」）
  readSecret(readOnly) {
    const f = path.join(this.dataDir, '.secret');
    try {
      const hex = fs.readFileSync(f, 'utf8').trim();
      if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error('密钥文件损坏');
      return Buffer.from(hex, 'hex');
    } catch (e) {
      if (readOnly) {
        throw new Error('data/.secret 缺失或损坏，已保存的密码无法解密，请在面板重新登录一次');
      }
      const k = crypto.randomBytes(32);
      fs.mkdirSync(this.dataDir, { recursive: true });
      fs.writeFileSync(f, k.toString('hex'), { mode: 0o600 });
      return k;
    }
  }

  encryptPassword(plain) {
    if (!plain) return '';
    const key = this.readSecret(false);
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return ['v1', b64(iv), b64(ct), b64(c.getAuthTag())].join(':');
  }

  decryptPassword(blob) {
    if (!blob) return '';
    const [ver, ivB, ctB, tagB] = String(blob).split(':');
    if (ver !== 'v1') return '';
    const key = this.readSecret(true);
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB, 'base64'));
    d.setAuthTag(Buffer.from(tagB, 'base64'));
    try {
      return Buffer.concat([d.update(Buffer.from(ctB, 'base64')), d.final()]).toString('utf8');
    } catch {
      throw new Error('已保存的密码解密失败（data/.secret 与密文不匹配），请在面板重新登录一次');
    }
  }

}

module.exports = Login;
