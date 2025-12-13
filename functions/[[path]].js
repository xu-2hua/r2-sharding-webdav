import { AwsV4Signer } from 'aws4fetch';

// --- 全局变量 ---
const DEFAULT_USER = "admin"; // WebDAV 默认用户名
let SHARDS = [];

// --- 助手函数 ---

// 1. 加载配置
async function loadConfig(env) {
    const config = await env.R2_CONFIG.get("R2_SHARDS");
    try {
        SHARDS = config ? JSON.parse(config) : [];
    } catch (e) {
        SHARDS = [];
    }
}

// 2. 分片路由算法 (读操作查 D1，写操作算哈希)
async function getShard(key, env, isWrite = false) {
    // 优先从 D1 查找元数据，确定文件在哪个桶
    if (!isWrite) {
        const { results } = await env.DB.prepare("SELECT bucket_id FROM files WHERE path = ?").bind(key).all();
        if (results && results.length > 0) {
            const shard = SHARDS.find(s => s.id === results[0].bucket_id);
            if (shard) return shard;
        }
    }

    if (SHARDS.length === 0) return null;

    // 哈希分片逻辑：如果找不到元数据（新文件）或强制写入，则计算哈希
    const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
    const index = new Uint32Array(hashBuffer)[0] % SHARDS.length;
    return SHARDS[index];
}

// 3. WebDAV XML 生成器
const xmlRes = (content) => `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">${content}</D:multistatus>`;

// 4. 远程 R2 请求签名助手 (S3 API)
async function fetchRemote(shard, method, path, headers, env, body = null) {
    const envPrefix = `R2_${shard.id}_`;
    const accessKeyId = env[envPrefix + "ACCESS_KEY"];
    const secretAccessKey = env[envPrefix + "SECRET_KEY"];
    const endpoint = env[envPrefix + "ENDPOINT"];
    const bucketName = shard.bucketName;

    if (!accessKeyId || !secretAccessKey || !endpoint) {
        throw new Error(`Missing env vars for remote shard: ${shard.id}`);
    }

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

// --- 主请求处理 ---

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);

    // 路径处理：去除末尾斜杠 (根目录除外)
    let path = decodeURIComponent(url.pathname);
    if (path.length > 1 && path.endsWith('/')) {
        path = path.slice(0, -1);
    }

    // 0. 静态资源直通 (管理后台和首页)
    if (path === '/' || path.startsWith('/admin') || path === '/index.html' || path === '/favicon.ico') {
        if (!(path === '/' && request.method === 'PROPFIND')) {
            return env.ASSETS.fetch(request);
        }
    }

    // 加载分片配置
    await loadConfig(env);

    // --- 核心修复：密码自动化同步逻辑 ---
    let SYSTEM_PASS = await env.R2_CONFIG.get("ADMIN_PASS");
    if (!SYSTEM_PASS) {
        const ENV_PASS = env.ADMIN_PASS; 
        if (ENV_PASS) {
            await env.R2_CONFIG.put("ADMIN_PASS", ENV_PASS);
            SYSTEM_PASS = ENV_PASS;
        } else {
            SYSTEM_PASS = "admin123"; 
        }
    }
    // --- 密码读取结束 ---

    // --- API: 管理后台接口 ---
    if (path === '/api/admin/config') {
        if (request.headers.get("X-Admin-Pass") !== SYSTEM_PASS) return new Response("Unauthorized", { status: 401 });
        if (request.method === 'GET') return new Response(await env.R2_CONFIG.get("R2_SHARDS") || "[]", { headers: { "Content-Type": "application/json" } });
        if (request.method === 'POST') {
            try {
                const newConfig = await request.json();
                if (!Array.isArray(newConfig)) throw new Error("Config must be an array");
                await env.R2_CONFIG.put("R2_SHARDS", JSON.stringify(newConfig));
                return new Response("Saved", { status: 200 });
            } catch (e) {
                return new Response(e.message, { status: 400 });
            }
        }
        return new Response("Method Not Allowed", { status: 405 });
    }

    // --- WebDAV: 身份验证 (Basic Auth) ---
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || authHeader !== "Basic " + btoa(`${DEFAULT_USER}:${SYSTEM_PASS}`)) {
        return new Response("Unauthorized", {
            status: 401,
            headers: { "WWW-Authenticate": 'Basic realm="R2 CloudDisk"' }
        });
    }

    if (SHARDS.length === 0) {
        return new Response("System Not Configured. Please visit /admin/index.html", { status: 503 });
    }

    const method = request.method;

    // --- WebDAV: 方法实现 ---

    // 0. OPTIONS (WebDAV 客户端的握手)
    if (method === "OPTIONS") {
        return new Response(null, {
            status: 200,
            headers: {
                "Allow": "OPTIONS, HEAD, GET, PUT, DELETE, PROPFIND, MKCOL, MOVE",
                "DAV": "1, 2", 
                "Access-Control-Allow-Methods": "OPTIONS, HEAD, GET, PUT, DELETE, PROPFIND, MKCOL, MOVE",
                "Access-Control-Allow-Headers": "Authorization, Depth, Content-Type"
            }
        });
    }
    
    // 0b. HEAD (某些客户端的快速检查)
    if (method === "HEAD") {
        // HEAD 请求只需要返回 GET 请求的 Header，但没有 Body。
        // 我们只返回 200 OK，表示资源存在（简化处理）
        return new Response(null, { status: 200 }); 
    }

    // 1. PROPFIND (列出文件)
    if (method === "PROPFIND") {
        const queryPath = path === "/" ? "/%" : path + "/%";
        const { results } = await env.DB.prepare(
            "SELECT path, bucket_id, is_dir, size, updated_at FROM files WHERE path = ? OR (path LIKE ? AND path NOT LIKE ?)"
        ).bind(path, queryPath, queryPath + "/%").all();

        if (!results || results.length === 0) {
             return new Response("Not Found", { status: 404 });
        }

        let responses = results.map(f => {
            const isCollection = f.is_dir === 1;
            
            // 修正后的路径处理：目录路径必须以斜杠结尾
            let href = f.path;
            if (isCollection && !href.endsWith('/')) {
                href += '/';
            }
            if (f.path === '/') href = '/';
            
            href = encodeURI(href);
            
            const displayName = f.path === '/' ? 'root' : f.path.split('/').pop();
            const lastMod = new Date(f.updated_at).toUTCString();

            return `
            <D:response>
                <D:href>${href}</D:href>
                <D:propstat>
                    <D:prop>
                        <D:displayname>${displayName}</D:displayname>
                        <D:getcontentlength>${f.size}</D:getcontentlength>
                        <D:resourcetype>${isCollection ? '<D:collection/>' : ''}</D:resourcetype>
                        <D:getlastmodified>${lastMod}</D:getlastmodified>
                        <D:creationdate>${new Date(f.updated_at).toISOString()}</D:creationdate>
                    </D:prop>
                    <D:status>HTTP/1.1 200 OK</D:status>
                </D:propstat>
            </D:response>`;
        }).join("");

        return new Response(xmlRes(responses), { 
            status: 207, 
            headers: { "Content-Type": "application/xml; charset=utf-8" } 
        });
    }

    // 2. GET (下载文件)
    if (method === "GET") {
        const shard = await getShard(path, env, false);
        if (!shard) return new Response("File Not Found", { status: 404 });

        if (shard.type === "local") {
            const obj = await env[shard.id].get(path);
            if (!obj) return new Response("Object Not Found in R2", { status: 404 });
            
            const headers = new Headers();
            obj.writeHttpMetadata(headers);
            headers.set("etag", obj.httpEtag);
            
            return new Response(obj.body, { headers });
        } else {
            // 远程 R2 调用
            const res = await fetchRemote(shard, 'GET', path, request.headers, env);
            const newHeaders = new Headers(res.headers);
            // 必须设置 CORS 头
            newHeaders.set("Access-Control-Allow-Origin", "*"); 
            return new Response(res.body, { status: res.status, headers: newHeaders });
        }
    }

    // 3. PUT (上传文件)
    if (method === "PUT") {
        const shard = await getShard(path, env, true); 
        const contentType = request.headers.get("Content-Type");
        const size = parseInt(request.headers.get("Content-Length") || "0");

        if (shard.type === "local") {
            await env[shard.id].put(path, request.body, { httpMetadata: { contentType } });
        } else {
            // 远程 R2 调用
            const res = await fetchRemote(shard, 'PUT', path, { 'Content-Type': contentType }, env, request.body);
            if (!res.ok) return new Response(`Remote Upload Failed: ${res.statusText}`, { status: 502 });
        }

        // 写入或更新元数据
        await env.DB.prepare(
            "INSERT OR REPLACE INTO files (path, bucket_id, is_dir, size, updated_at) VALUES (?, ?, 0, ?, ?)"
        ).bind(path, shard.id, size, Date.now()).run();

        return new Response(null, { status: 201 });
    }

    // 4. MKCOL (创建文件夹)
    if (method === "MKCOL") {
        const { results } = await env.DB.prepare("SELECT path FROM files WHERE path = ?").bind(path).all();
        if (results.length > 0) return new Response("Already Exists", { status: 405 });

        await env.DB.prepare(
            "INSERT INTO files (path, bucket_id, is_dir, size, updated_at) VALUES (?, 'NONE', 1, 0, ?)"
        ).bind(path, Date.now()).run();
        
        return new Response(null, { status: 201 });
    }

    // 5. DELETE (删除文件/文件夹)
    if (method === "DELETE") {
        const shard = await getShard(path, env, false);
        
        if (shard) {
            if (shard.type === "local") await env[shard.id].delete(path);
            else await fetchRemote(shard, 'DELETE', path, {}, env);
        }
        
        // 删 D1 (如果是目录，删除自身和所有子记录)
        await env.DB.prepare("DELETE FROM files WHERE path = ? OR path LIKE ?").bind(path, path + "/%").run();
        
        return new Response(null, { status: 204 });
    }

    // 6. MOVE (重命名/移动)
    if (method === "MOVE") {
        const destinationHeader = request.headers.get("Destination");
        if (!destinationHeader) return new Response("Missing Destination", { status: 400 });
        
        const destPath = decodeURIComponent(new URL(destinationHeader).pathname);

        await env.DB.prepare(
            "UPDATE files SET path = ? WHERE path = ?"
        ).bind(destPath, path).run();

        return new Response(null, { status: 201 });
    }

    return new Response("Method Not Allowed", { status: 405 });
}
