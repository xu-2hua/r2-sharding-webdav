import { AwsV4Signer } from 'aws4fetch';

// --- 全局变量 ---
let SHARDS = [];
const DEFAULT_USER = "admin";

// --- 助手函数 ---

async function loadConfig(env) {
    const config = await env.R2_CONFIG.get("R2_SHARDS");
    try {
        SHARDS = config ? JSON.parse(config) : [];
    } catch (e) {
        SHARDS = [];
    }
}

async function getShard(key, env, isWrite = false) {
    // 优先查 D1
    if (!isWrite) {
        const { results } = await env.DB.prepare("SELECT bucket_id FROM files WHERE path = ?").bind(key).all();
        if (results && results.length > 0) {
            const shard = SHARDS.find(s => s.id === results[0].bucket_id);
            if (shard) return shard;
        }
    }

    if (SHARDS.length === 0) return null;

    // 哈希分片
    const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
    const index = new Uint32Array(hashBuffer)[0] % SHARDS.length;
    return SHARDS[index];
}

const xmlRes = (content) => `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">${content}</D:multistatus>`;

// --- 远程 R2 请求签名助手 ---
async function fetchRemote(shard, method, path, headers, env, body = null) {
    // 从环境变量中读取密钥
    // 假设配置 JSON 里 bucket_id 叫 "REMOTE_1"，则环境变量需命名为 R2_REMOTE_1_ACCESS_KEY
    const envPrefix = `R2_${shard.id}_`; 
    const accessKeyId = env[envPrefix + "ACCESS_KEY"];
    const secretAccessKey = env[envPrefix + "SECRET_KEY"];
    const endpoint = env[envPrefix + "ENDPOINT"];
    const bucketName = shard.bucketName; //需要在配置里填

    if (!accessKeyId || !secretAccessKey || !endpoint) {
        throw new Error(`Missing env vars for remote shard: ${shard.id}`);
    }

    // 构造 S3 URL: endpoint/bucketName/path
    const url = new URL(`${endpoint}/${bucketName}${path}`);

    const signer = new AwsV4Signer({
        url: url.toString(),
        accessKeyId,
        secretAccessKey,
        method,
        headers,
        body,
        service: 's3',
        region: 'auto'
    });

    const signed = await signer.sign();
    return fetch(signed);
}

// --- 主逻辑 ---

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    let path = decodeURIComponent(url.pathname);
    if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);

    // 静态资源直通
    if (path === '/' || path.startsWith('/admin') || path === '/index.html' || path === '/favicon.ico') {
        if (!(path === '/' && request.method === 'PROPFIND')) return env.ASSETS.fetch(request);
    }

    await loadConfig(env);
    const SYSTEM_PASS = await env.R2_CONFIG.get("ADMIN_PASS") || "admin123";

    // API 管理
    if (path === '/api/admin/config') {
        if (request.headers.get("X-Admin-Pass") !== SYSTEM_PASS) return new Response("Unauthorized", { status: 401 });
        if (request.method === 'GET') return new Response(await env.R2_CONFIG.get("R2_SHARDS") || "[]");
        if (request.method === 'POST') {
            await env.R2_CONFIG.put("R2_SHARDS", JSON.stringify(await request.json()));
            return new Response("Saved", { status: 200 });
        }
    }

    // 认证
    const auth = request.headers.get("Authorization");
    if (!auth || auth !== "Basic " + btoa(`${DEFAULT_USER}:${SYSTEM_PASS}`)) {
        return new Response("Unauthorized", { status: 401, headers: { "WWW-Authenticate": 'Basic realm="CloudDisk"' } });
    }

    if (SHARDS.length === 0) return new Response("Not Configured", { status: 503 });

    const method = request.method;

    // 1. PROPFIND (列表) - 只查 D1，不用连 R2，所以不需要改动
    if (method === "PROPFIND") {
        const queryPath = path === "/" ? "/%" : path + "/%";
        const { results } = await env.DB.prepare(
            "SELECT path, bucket_id, is_dir, size, updated_at FROM files WHERE path = ? OR (path LIKE ? AND path NOT LIKE ?)"
        ).bind(path, queryPath, queryPath + "/%").all();

        if (!results || results.length === 0) return new Response("Not Found", { status: 404 });

        const responses = results.map(f => {
            let href = f.path === '/' ? '/' : encodeURI(f.path + (f.is_dir ? '/' : ''));
            return `<D:response>
                <D:href>${href}</D:href>
                <D:propstat><D:prop>
                    <D:displayname>${f.path === '/' ? 'root' : f.path.split('/').pop()}</D:displayname>
                    <D:getcontentlength>${f.size}</D:getcontentlength>
                    <D:resourcetype>${f.is_dir ? '<D:collection/>' : ''}</D:resourcetype>
                    <D:getlastmodified>${new Date(f.updated_at).toUTCString()}</D:getlastmodified>
                </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
            </D:response>`;
        }).join("");
        return new Response(xmlRes(responses), { status: 207, headers: { "Content-Type": "application/xml; charset=utf-8" } });
    }

    // 2. GET (下载)
    if (method === "GET") {
        const shard = await getShard(path, env, false);
        if (!shard) return new Response("File Not Found", { status: 404 });

        if (shard.type === "local") {
            const obj = await env[shard.id].get(path);
            if (!obj) return new Response("Not Found", { status: 404 });
            const h = new Headers(); obj.writeHttpMetadata(h); h.set("etag", obj.httpEtag);
            return new Response(obj.body, { headers: h });
        } else {
            // 远程调用
            const res = await fetchRemote(shard, 'GET', path, request.headers, env);
            // 远程可能返回 404 或 200，直接透传响应，但要处理一下 Header 避免 CORS 问题
            const newHeaders = new Headers(res.headers);
            newHeaders.set("Access-Control-Allow-Origin", "*"); 
            return new Response(res.body, { status: res.status, headers: newHeaders });
        }
    }

    // 3. PUT (上传)
    if (method === "PUT") {
        const shard = await getShard(path, env, true);
        const size = parseInt(request.headers.get("Content-Length") || "0");
        const contentType = request.headers.get("Content-Type");

        if (shard.type === "local") {
            await env[shard.id].put(path, request.body, { httpMetadata: { contentType } });
        } else {
            // 远程调用
            // 注意：Request body 只能被读取一次，如果这里报错需要 clone
            const res = await fetchRemote(shard, 'PUT', path, { 'Content-Type': contentType }, env, request.body);
            if (!res.ok) return new Response(`Remote Upload Failed: ${res.statusText}`, { status: 502 });
        }

        await env.DB.prepare("INSERT OR REPLACE INTO files (path, bucket_id, is_dir, size, updated_at) VALUES (?, ?, 0, ?, ?)").bind(path, shard.id, size, Date.now()).run();
        return new Response(null, { status: 201 });
    }

    // 4. DELETE (删除)
    if (method === "DELETE") {
        const shard = await getShard(path, env, false);
        if (shard) {
            if (shard.type === "local") await env[shard.id].delete(path);
            else await fetchRemote(shard, 'DELETE', path, {}, env);
        }
        await env.DB.prepare("DELETE FROM files WHERE path = ? OR path LIKE ?").bind(path, path + "/%").run();
        return new Response(null, { status: 204 });
    }

    // 5. MKCOL
    if (method === "MKCOL") {
        await env.DB.prepare("INSERT INTO files (path, bucket_id, is_dir, size, updated_at) VALUES (?, 'NONE', 1, 0, ?)").bind(path, Date.now()).run();
        return new Response(null, { status: 201 });
    }
    
    // 6. MOVE
    if (method === "MOVE") {
        const dest = decodeURIComponent(new URL(request.headers.get("Destination")).pathname);
        await env.DB.prepare("UPDATE files SET path = ? WHERE path = ?").bind(dest, path).run();
        return new Response(null, { status: 201 });
    }

    return new Response("Method Not Allowed", { status: 405 });
}
