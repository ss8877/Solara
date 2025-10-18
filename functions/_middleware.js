export async function onRequest({ request, next, env }) {
  // 配置参数（可根据需求修改）
  const PASSWORD = env.ACCESS_PASSWORD; // 从环境变量读取密码
  const COOKIE_NAME = "cf_auth"; // Cookie 名称（自定义）
  const EXPIRY_HOURS = 168; // 免密有效期（单位：小时，例如 24 小时）

  // 第一步：检查是否有有效的认证 Cookie
  const authCookie = getCookie(request.headers, COOKIE_NAME);
  if (authCookie && isValidCookie(authCookie, PASSWORD, EXPIRY_HOURS)) {
    // Cookie 有效，直接放行
    return next();
  }

  // 第二步：Cookie 无效/不存在，进行密码验证
  const authHeader = request.headers.get("Authorization");
  if (!authHeader ||!authHeader.startsWith("Basic ")) {
    // 无密码信息，要求输入密码
    return new Response("请输入访问密码", {
      status: 401,
      headers: { "WWW-Authenticate": 'Basic realm="需要密码访问"' },
    });
  }

  // 解析密码并验证
  const [_, encodedPassword] = authHeader.split(" ");
  const decoded = atob(encodedPassword); // 解码 Basic 认证信息
  const [username, password] = decoded.split(":"); // 格式：username:password（忽略 username）

  if (password!== PASSWORD) {
    // 密码错误，拒绝访问
    return new Response("密码错误，请重新输入", {
      status: 401,
      headers: { "WWW-Authenticate": 'Basic realm="密码错误"' },
    });
  }

  // 第三步：密码验证通过，设置免密 Cookie
  const response = await next(); // 获取原始响应
  const cookieValue = createCookieValue(PASSWORD, EXPIRY_HOURS); // 生成带有效期的 Cookie 值
  setCookie(response.headers, COOKIE_NAME, cookieValue, EXPIRY_HOURS); // 写入 Cookie

  return response;
}

// 辅助函数：从请求头中获取指定 Cookie
function getCookie(headers, name) {
  const cookieHeader = headers.get("Cookie");
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split("; ").reduce((acc, cookie) => {
    const [key, value] = cookie.split("=");
    acc[key] = value;
    return acc;
  }, {});
  return cookies[name] || null;
}

// 辅助函数：验证 Cookie 是否有效
function isValidCookie(cookieValue, password, expiryHours) {
  try {
    const decoded = atob(cookieValue); // 解码 Cookie 值
    const [expiryTime, token] = decoded.split(":"); // 格式：过期时间戳:加密令牌
    // 检查是否过期 + 令牌是否匹配
    return Date.now() < Number(expiryTime) && token === btoa(password);
  } catch (error) {
    return false; // 格式错误或验证失败，视为无效
  }
}

// 辅助函数：生成 Cookie 值（包含过期时间和加密令牌）
function createCookieValue(password, expiryHours) {
  const expiryTime = Date.now() + expiryHours * 60 * 60 * 1000; // 计算过期时间戳（毫秒）
  const token = btoa(password); // 简单加密密码（生产环境可替换为更安全的方式）
  return btoa(`${expiryTime}:${token}`); // 整体编码为 Base64
}

// 辅助函数：向响应头添加 Cookie（含安全属性）
function setCookie(headers, name, value, expiryHours) {
  const maxAge = expiryHours * 3600; // 转换为秒（Max-Age 单位）
  headers.append(
    "Set-Cookie",
    `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`
  );
  // 说明：
  // - HttpOnly：防止 JS 读取 Cookie，减少 XSS 风险
  // - Secure：仅通过 HTTPS 传输（Cloudflare Pages 默认 HTTPS，放心启用）
  // - SameSite=Lax：防止 CSRF 攻击
}
