const API = "http://127.0.0.1:8000/api";

async function parse(res) {
    if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt);
    }
    return res.json();
}

export async function registerImage(file) {
    const fd = new FormData();
    fd.append("file", file);

    const res = await fetch(`${API}/register`, {
        method: "POST",
        body: fd,
    });

    return parse(res);
}

export async function gatewayCheck(file, platform) {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("platform", platform);

    const res = await fetch(`${API}/gateway-check`, {
        method: "POST",
        body: fd,
    });

    return parse(res);
}

export async function recoverCase(caseId) {
    const res = await fetch(`${API}/recover/${caseId}`, {
        method: "POST",
    });

    return parse(res);
}

export async function fetchResults() {
    const res = await fetch(`${API}/results`);
    return parse(res);
}

export async function fetchPlatforms() {
    const res = await fetch(`${API}/platforms`);
    return parse(res);
}

export function downloadUrl(type, name) {
    return `${API}/download/${type}/${encodeURIComponent(name)}`;
}