#!/usr/bin/env python3
"""按 registry Bearer challenge 读取 CNB 制品并核验 linux/amd64。"""

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REGISTRY = "https://docker.cnb.cool"
TOKEN_URL = REGISTRY + "/service/token"
MANIFEST_ACCEPT = ", ".join([
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
])


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise ValueError("registry 重定向必须使用 HTTPS")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header("Authorization")
        return redirected


class Registry:
    def __init__(self, credential="", open_url=None):
        self.credential = credential
        self.open_url = open_url or urllib.request.build_opener(SafeRedirect()).open
        self.tokens = {}

    def request(self, url, accept, authorization=None):
        headers = {"Accept": accept}
        if authorization:
            headers["Authorization"] = authorization
        with self.open_url(urllib.request.Request(url, headers=headers), timeout=60) as response:
            return json.load(response), response.headers

    def json(self, name, path, accept):
        url = REGISTRY + "/v2/" + name + "/" + path
        bearer = self.tokens.get(name)
        try:
            return self.request(url, accept, "Bearer " + bearer if bearer else None)
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise
            challenge = error.headers.get("WWW-Authenticate", "")
        scheme, _, fields = challenge.partition(" ")
        params = urllib.request.parse_keqv_list(urllib.request.parse_http_list(fields))
        scope = "repository:" + name + ":pull"
        # 不向 challenge 中任意指定的主机发送仓库凭据。
        if (scheme.lower() != "bearer" or params.get("realm") != TOKEN_URL
                or params.get("service") != "cnb-registry" or params.get("scope") != scope):
            raise ValueError("CNB registry 返回了非预期的 Bearer challenge")
        query = urllib.parse.urlencode({"service": params["service"], "scope": scope})
        # 公开制品先使用匿名 pull token；私有制品才向固定 token 服务认证。
        for authenticated in ([False, True] if self.credential else [False]):
            authorization = None
            if authenticated:
                basic = base64.b64encode(("cnb:" + self.credential).encode()).decode()
                authorization = "Basic " + basic
            try:
                data, _ = self.request(TOKEN_URL + "?" + query, "application/json", authorization)
                token = data.get("token") or data.get("access_token")
                if not isinstance(token, str) or not token:
                    raise ValueError("CNB token 服务未返回 pull token")
                result = self.request(url, accept, "Bearer " + token)
            except urllib.error.HTTPError as error:
                if error.code in (401, 403) and not authenticated and self.credential:
                    continue
                raise
            self.tokens[name] = token
            return result
        raise ValueError("CNB registry 认证失败")


def verify_image(registry, name, version):
    manifest, headers = registry.json(name, "manifests/" + version, MANIFEST_ACCEPT)
    digest = headers.get("Docker-Content-Digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError(name + " 清单未返回有效 digest")
    if "manifests" in manifest:
        candidates = [item for item in manifest["manifests"]
                      if item.get("platform", {}).get("architecture") == "amd64"
                      and item.get("platform", {}).get("os") == "linux"]
        if not candidates:
            raise ValueError(name + " 清单没有 linux/amd64")
        manifest, _ = registry.json(name, "manifests/" + candidates[0]["digest"], MANIFEST_ACCEPT)
    config_digest = manifest.get("config", {}).get("digest")
    if not config_digest:
        raise ValueError(name + " 没有 config digest")
    config, _ = registry.json(name, "blobs/" + config_digest, "application/json")
    if (config.get("os"), config.get("architecture")) != ("linux", "amd64"):
        raise ValueError(name + " 镜像 config 不是 linux/amd64")
    return digest, config_digest


def main(args):
    if len(args) < 3:
        raise ValueError("用法：verify-cnb-images.py VERSION CNB_REPO SERVICE...")
    version, repo, *services = args
    registry = Registry(os.environ.get("CNB_TOKEN", ""))
    for service in services:
        digest, config_digest = verify_image(registry, repo + "/" + service, version)
        print(service, "digest", digest, "config", config_digest, "platform linux/amd64")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except urllib.error.HTTPError as error:
        sys.exit("CNB registry/token 请求失败 HTTP " + str(error.code))
    except (ValueError, urllib.error.URLError) as error:
        sys.exit(str(error))
