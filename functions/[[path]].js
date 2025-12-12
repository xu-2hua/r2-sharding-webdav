import { AwsV4Signer } from 'aws4fetch';

// --- 全局变量 ---
let SHARDS = [];
const DEFAULT_USER = "admin";

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
    // 如果是写操作，或者 D1 没查到，就用哈希算法
    if (!isWrite) {
        const { results } = await env.DB.prepare("SELECT bucket_id FROM files WHERE path = ?").bind(key).all();
        if (results && results.length > 0) {
            const shard = SHARDS.find(s => s.id === results[0].bucket_id);
            if (shard) return shard;
        }
    }

    if (SHARDS.length === 0) return null;

    // 哈希分片逻辑
    const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
    const hashArray = new Uint32Array(hashBuffer);
    const index = hashArray[0] % SHARDS.length;
    return SHARDS[index];
}

// 3. WebDAV XML 生成器
const xmlRes = (content) => `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">${content}</D:multistatus>`;

// --- 主请求处理 ---

export async function onRequest(context) {
    const { request, env, waitUntil } = context;
    const url = new URL(request.url);
    
    // 路径处理：去除末尾斜杠 (根目录除外)
    let path = decodeURIComponent(url.pathname);
    if (path.length > 1 && path.endsWith('/')) {
        path = path.slice(0, -1);
    }

    // 0. 静态资源直通 (管理后台和首页)
    if (path === '/' || path.startsWith('/admin') || path === '/index.html' || path === '/favicon.ico') {
        // 如果是 WebDAV 客户端请求根目录 PROPFIND，不能返回 HTML，要往下走
        if (!(path === '/' && request.method === 'PROPFIND')) {
            return env.ASSETS.fetch(request);
        }
    }

    // 加载分片配置
    await loadConfig(env);

    // 获取系统密码
    const SYSTEM_PASS = await env.R2_CONFIG.get("ADMIN_PASS") || "admin123";

    // --- API: 管理后台接口 ---
    if (path === '/api/admin/config') {
        const apiAuth = request.headers.get("X-Admin-Pass");
        if (apiAuth !== SYSTEM_PASS) return new Response("Unauthorized", { status: 401 });

        if (request.method === 'GET') {
            const currentConfig = await env.R2_CONFIG.get("R2_SHARDS");
            return new Response(currentConfig || "[]", { headers: { "Content-Type": "application/json" } });
        }
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

    // 检查配置是否为空
    if (SHARDS.length === 0) {
        return new Response("System Not Configured. Please visit /admin/index.html", { status: 503 });
    }

    const method = request.method;

    // --- WebDAV: 方法实现 ---

    // 1. PROPFIND (列出文件)
    if (method === "PROPFIND") {
        // 查询当前目录下的文件 (SQL LIKE)
        // 注意：WebDAV 客户端通常会请求 Depth: 1
        const queryPath = path === "/" ? "/%" : path + "/%";
        // 查找自己 (为了返回目录属性) 和 子文件
        const { results } = await env.DB.prepare(
            "SELECT path, bucket_id, is_dir, size, updated_at FROM files WHERE path = ? OR (path LIKE ? AND path NOT LIKE ?)"
        ).bind(path, queryPath, queryPath + "/%").all(); // 简单的模拟 Depth: 1

        if (!results || results.length === 0) {
             return new Response("Not Found", { status: 404 });
        }

        let responses = results.map(file => {
            const isCollection = file.is_dir === 1;
            // 确保目录路径以 / 结尾
            let href = file.path;
            if (isCollection && !href.endsWith('/')) href += '/';
            
            // 根目录特殊处理
            if (file.path === '/') href = '/';
            else href = encodeURI(href);

            const displayName = file.path === '/' ? 'root' : file.path.split('/').pop();
            const lastMod = new Date(file.updated_at).toUTCString();

            return `
            <D:response>
                <D:href>${href}</D:href>
                <D:propstat>
                    <D:prop>
                        <D:displayname>${displayName}</D:displayname>
                        <D:getcontentlength>${file.size}</D:getcontentlength>
                        <D:resourcetype>${isCollection ? '<D:collection/>' : ''}</D:resourcetype>
                        <D:getlastmodified>${lastMod}</D:getlastmodified>
                        <D:creationdate>${new Date(file.updated_at).toISOString()}</D:creationdate>
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
        if (!shard) return new Response("File Metadata Not Found", { status: 404 });

        if (shard.type === "local") {
            const obj = await env[shard.id].get(path);
            if (!obj) return new Response("Object Not Found in R2", { status: 404 });
            
            const headers = new Headers();
            obj.writeHttpMetadata(headers);
            headers.set("etag", obj.httpEtag);
            
            return new Response(obj.body, { headers });
        }
        // 远程逻辑略，保持简洁
        return new Response("Remote bucket not implemented in this version", { status: 501 });
    }

    // 3. PUT (上传文件)
    if (method === "PUT") {
        // iOS 可能会先发一个 Expect: 100-continue，Cloudflare 自动处理
        const shard = await getShard(path, env, true); // 强制写模式（计算哈希）
        const contentType = request.headers.get("Content-Type") || "application/octet-stream";
        const size = parseInt(request.headers.get("Content-Length") || "0");

        if (shard.type === "local") {
            await env[shard.id].put(path, request.body, {
                httpMetadata: { contentType: contentType }
            });
        }

        // 写入元数据
        await env.DB.prepare(
            "INSERT OR REPLACE INTO files (path, bucket_id, is_dir, size, updated_at) VALUES (?, ?, 0, ?, ?)"
        ).bind(path, shard.id, size, Date.now()).run();

        return new Response(null, { status: 201 });
    }

    // 4. MKCOL (创建文件夹)
    if (method === "MKCOL") {
        // 检查是否存在
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
        
        // 如果是文件且存在，删 R2
        if (shard && shard.type === "local") {
            await env[shard.id].delete(path);
        }
        
        // 删 D1 (如果是目录，逻辑上应该递归删除，这里简化为只删除记录)
        await env.DB.prepare("DELETE FROM files WHERE path = ? OR path LIKE ?").bind(path, path + "/%").run();
        
        return new Response(null, { status: 204 });
    }

    // 6. MOVE (重命名/移动) - iOS 经常用
    if (method === "MOVE") {
        const destinationHeader = request.headers.get("Destination");
        if (!destinationHeader) return new Response("Missing Destination", { status: 400 });
        
        const destUrl = new URL(destinationHeader);
        let destPath = decodeURIComponent(destUrl.pathname);
        if (destPath.length > 1 && destPath.endsWith('/')) destPath = destPath.slice(0, -1);

        // 简单实现：只更新数据库路径，不移动 R2 实际对象（这是 R2 的优势，对象位置由 Key 决定，但分片逻辑依赖 Key 哈希...）
        // ⚠️ 注意：如果更改了文件名，哈希值变了，理论上应该移动到另一个桶。
        // 为了简化和性能，我们保持文件在原桶，只修改 D1 里的 path 映射。
        // 这就是为什么 getShard 里优先查 DB 的原因！

        await env.DB.prepare(
            "UPDATE files SET path = ? WHERE path = ?"
        ).bind(destPath, path).run();

        return new Response(null, { status: 201 });
    }

    return new Response("Method Not Allowed", { status: 405 });
}
