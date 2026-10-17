/* Download Hub API (chạy trên Render) - không cần cài thư viện nào.
   Biến môi trường cần đặt trong Render > Environment:
     JSONBIN_BIN_ID      : ID bin lưu bài
     JSONBIN_MASTER_KEY  : Master Key (hoặc key quyền Update) của JSONBin
     ADMIN_CODE          : mã admin do BẠN tự đặt (nên dài, khó đoán)
     ALLOWED_ORIGIN      : (tuỳ chọn) địa chỉ web của bạn, vd https://ten.github.io  (nhiều địa chỉ: cách nhau dấu phẩy)
*/
const http = require("http");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const BIN_ID = process.env.JSONBIN_BIN_ID || "";
const MASTER_KEY = process.env.JSONBIN_MASTER_KEY || "";
const ADMIN_CODE = process.env.ADMIN_CODE || "";
const ALLOWED = (process.env.ALLOWED_ORIGIN || "*").split(",").map(s => s.trim()).filter(Boolean);

if (!BIN_ID || !MASTER_KEY || !ADMIN_CODE) {
  console.error("THIẾU biến môi trường: cần JSONBIN_BIN_ID, JSONBIN_MASTER_KEY, ADMIN_CODE");
}

const JB_URL = "https://api.jsonbin.io/v3/b/" + BIN_ID;
const SECRET = crypto.createHash("sha256").update("tok:" + ADMIN_CODE + ":" + MASTER_KEY).digest();
const TOKEN_TTL_MS = 7 * 24 * 3600 * 1000;   // đăng nhập có hiệu lực 7 ngày
const CACHE_MS = 20 * 1000;                   // cache danh sách bài 20 giây để đỡ tốn request JSONBin
const MAX_BODY = 1024 * 1024;                 // 1MB

/* ---------- token đăng nhập (ký HMAC, không cần lưu DB) ---------- */
const b64u = buf => Buffer.from(buf).toString("base64url");
function sign(payload) { return crypto.createHmac("sha256", SECRET).update(payload).digest("base64url"); }
function makeToken() {
  const payload = b64u(JSON.stringify({ exp: Date.now() + TOKEN_TTL_MS }));
  return payload + "." + sign(payload);
}
function verifyToken(token) {
  if (!token || typeof token !== "string") return false;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return false;
  const expect = sign(payload);
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { return JSON.parse(Buffer.from(payload, "base64url").toString()).exp > Date.now(); }
  catch (e) { return false; }
}
function codeMatches(input) {
  const h = s => crypto.createHash("sha256").update(String(s)).digest();
  return crypto.timingSafeEqual(h(input), h(ADMIN_CODE));
}

/* ---------- chặn dò mật mã: tối đa 8 lần sai / 15 phút / IP ---------- */
const fails = new Map();
function clientIp(req) {
  return ((req.headers["x-forwarded-for"] || "").split(",")[0] || req.socket.remoteAddress || "?").trim();
}
function isBlocked(ip) {
  const f = fails.get(ip);
  if (!f) return false;
  if (Date.now() > f.reset) { fails.delete(ip); return false; }
  return f.count >= 8;
}
function addFail(ip) {
  const f = fails.get(ip);
  if (!f || Date.now() > f.reset) fails.set(ip, { count: 1, reset: Date.now() + 15 * 60 * 1000 });
  else f.count++;
}

/* ---------- JSONBin ---------- */
function toPosts(json) {
  const rec = json && json.record !== undefined ? json.record : json;
  if (rec === null || rec === undefined) return [];
  if (Array.isArray(rec)) return rec;
  if (Array.isArray(rec.posts)) return rec.posts;
  if (typeof rec === "object" && Object.keys(rec).length === 0) return [];
  throw new Error("Định dạng dữ liệu trong bin lạ");
}
let cache = null; // { posts, at }
async function readPosts() {
  if (cache && Date.now() - cache.at < CACHE_MS) return cache.posts;
  const r = await fetch(JB_URL + "/latest", { headers: { "X-Master-Key": MASTER_KEY } });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    const err = new Error("JSONBin đọc lỗi " + r.status + " " + t.slice(0, 150));
    err.status = r.status; throw err;
  }
  const posts = toPosts(await r.json());
  cache = { posts, at: Date.now() };
  return posts;
}
async function writePosts(posts) {
  const r = await fetch(JB_URL, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Master-Key": MASTER_KEY },
    body: JSON.stringify({ posts })
  });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    const err = new Error("JSONBin ghi lỗi " + r.status + " " + t.slice(0, 150));
    err.status = r.status; throw err;
  }
  cache = { posts, at: Date.now() };
}

/* ---------- http ---------- */
function cors(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED.includes("*")) res.setHeader("Access-Control-Allow-Origin", "*");
  else if (origin && ALLOWED.includes(origin)) { res.setHeader("Access-Control-Allow-Origin", origin); res.setHeader("Vary", "Origin"); }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Max-Age", "86400");
}
function send(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > MAX_BODY) { reject(new Error("Dữ liệu quá lớn")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}
function validPosts(posts) {
  if (!Array.isArray(posts) || posts.length > 500) return false;
  return posts.every(p => p && typeof p === "object" && !Array.isArray(p) &&
    (typeof p.id === "number" || typeof p.id === "string") && typeof p.title === "string");
}

const server = http.createServer(async (req, res) => {
  cors(req, res);
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
  const path = (req.url || "/").split("?")[0];

  try {
    if (req.method === "GET" && (path === "/" || path === "/health")) return send(res, 200, { ok: true });

    if (req.method === "GET" && path === "/api/posts") {
      return send(res, 200, await readPosts());
    }

    if (req.method === "POST" && path === "/api/login") {
      const ip = clientIp(req);
      if (isBlocked(ip)) return send(res, 429, { ok: false, error: "Thử sai quá nhiều lần, đợi 15 phút." });
      let body; try { body = JSON.parse(await readBody(req)); } catch (e) { return send(res, 400, { ok: false }); }
      if (ADMIN_CODE && body && typeof body.code === "string" && codeMatches(body.code)) {
        fails.delete(ip);
        return send(res, 200, { ok: true, token: makeToken() });
      }
      addFail(ip);
      return send(res, 401, { ok: false });
    }

    if (req.method === "POST" && path === "/api/posts") {
      if (!verifyToken(req.headers["x-admin-token"])) return send(res, 401, { ok: false, error: "Chưa đăng nhập hoặc hết hạn" });
      let body; try { body = JSON.parse(await readBody(req)); } catch (e) { return send(res, 400, { ok: false, error: "JSON không hợp lệ" }); }
      if (!body || !validPosts(body.posts)) return send(res, 400, { ok: false, error: "Danh sách bài không hợp lệ" });
      await writePosts(body.posts);
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { error: "Không tìm thấy" });
  } catch (e) {
    console.error(e.message);
    return send(res, 502, { ok: false, error: e.message });
  }
});

server.listen(PORT, () => console.log("API chạy ở cổng " + PORT));
