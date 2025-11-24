// 硬编码参数版本
log(`🚀🚀 开始`)

// 硬编码参数 - 在这里修改配置
const type = null;           // 订阅类型：组合订阅 或 null
const name = "feiniaoyun";              // 订阅名称
const url = null;                      // 订阅URL，设为null使用本地订阅
const outbound = "🕳🎈 自动选择🕳🇭🇰 香港节点🏷^(?=.*(港|HK|hk|Hong Kong|HongKong|hongkong)).*$🕳🇹🇼 台湾节点🏷^(?=.*(台|新北|彰化|TW|Taiwan)).*$🕳🇯🇵 日本节点🏷^(?=.*(日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|Japan)).*$🕳🇸🇬 新加坡节点🏷^(?=.*(新加坡|坡|狮城|SG|Singapore)).*$🕳🇺🇸 美国节点🏷^(?=.*(美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|US|United States)).*$🕳🧭 其它地区🏷^(?!.*(港|HK|hk|Hong Kong|HongKong|hongkong|日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|Japan|美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|US|United States|台|新北|彰化|TW|Taiwan|新加坡|坡|狮城|SG|Singapore|灾|网易|Netease|套餐|重置|剩余|到期|订阅|群|账户|流量|有效期|时间|官网)).*$";
const includeUnsupportedProxy = false;  // 是否包含不支持的协议

// 原脚本：
// https://gh-proxy.org/https://github.com/xream/scripts/raw/refs/heads/main/surge/modules/sub-store-scripts/sing-box/template.js#name=feiniaoyun&outbound=🕳⚡ 延迟最低🕳🇭🇰 香港节点🏷^(?=.*(港|HK|hk|Hong Kong|HongKong|hongkong)).*$🕳🇹🇼 台湾节点🏷^(?=.*(台|新北|彰化|TW|Taiwan)).*$🕳🇯🇵 日本节点🏷^(?=.*(日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|Japan)).*$🕳🇸🇬 新加坡节点🏷^(?=.*(新加坡|坡|狮城|SG|Singapore)).*$🕳🇺🇸 美国节点🏷^(?=.*(美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|US|United States)).*$🕳🧭 其它地区🏷^(?!.*(港|HK|hk|Hong Kong|HongKong|hongkong|日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|Japan|美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|US|United States|台|新北|彰化|TW|Taiwan|新加坡|坡|狮城|SG|Singapore|灾|网易|Netease|套餐|重置|剩余|到期|订阅|群|账户|流量|有效期|时间|官网)).*$

log(`硬编码参数 type: ${type}, name: ${name}, outbound: ${outbound}`)

const parsedType = /^1$|col|组合/i.test(type) ? 'collection' : 'subscription';

const parser = ProxyUtils.JSON5 || JSON
log(`① 使用 ${ProxyUtils.JSON5 ? 'JSON5' : 'JSON'} 解析配置文件`)
let config
try {
  config = parser.parse($content ?? $files[0])
} catch (e) {
  log(`${e.message ?? e}`)
  throw new Error(`配置文件不是合法的 ${ProxyUtils.JSON5 ? 'JSON5' : 'JSON'} 格式`)
}
log(`② 获取订阅`)

let proxies
if (url) {
  log(`直接从 URL ${url} 读取订阅`)
  proxies = await produceArtifact({
    name,
    type: parsedType,
    platform: 'sing-box',
    produceType: 'internal',
    produceOpts: {
      'include-unsupported-proxy': includeUnsupportedProxy,
    },
    subscription: {
      name,
      url,
      source: 'remote',
    },
  })
} else {
  log(`将读取名称为 ${name} 的 ${parsedType === 'collection' ? '组合' : ''}订阅`)
  proxies = await produceArtifact({
    name,
    type: parsedType,
    platform: 'sing-box',
    produceType: 'internal',
    produceOpts: {
      'include-unsupported-proxy': includeUnsupportedProxy,
    },
  })
}

log(`③ outbound 规则解析`)
const outbounds = outbound
  .split('🕳')
  .filter(i => i)
  .map(i => {
    let [outboundPattern, tagPattern = '.*'] = i.split('🏷')
    const tagRegex = createTagRegExp(tagPattern)
    log(`匹配 🏷 ${tagRegex} 的节点将插入匹配 🕳 ${createOutboundRegExp(outboundPattern)} 的 outbound 中`)
    return [outboundPattern, tagRegex]
  })

log(`④ outbound 插入节点`)
config.outbounds.map(outbound => {
  outbounds.map(([outboundPattern, tagRegex]) => {
    const outboundRegex = createOutboundRegExp(outboundPattern)
    if (outboundRegex.test(outbound.tag)) {
      if (!Array.isArray(outbound.outbounds)) {
        outbound.outbounds = []
      }
      const tags = getTags(proxies, tagRegex)
      log(`🕳 ${outbound.tag} 匹配 ${outboundRegex}, 插入 ${tags.length} 个 🏷 匹配 ${tagRegex} 的节点`)
      outbound.outbounds.push(...tags)
    }
  })
})

const compatible_outbound = {
  tag: 'COMPATIBLE',
  type: 'direct',
}

let compatible
log(`⑤ 空 outbounds 检查`)
config.outbounds.map(outbound => {
  outbounds.map(([outboundPattern, tagRegex]) => {
    const outboundRegex = createOutboundRegExp(outboundPattern)
    if (outboundRegex.test(outbound.tag)) {
      if (!Array.isArray(outbound.outbounds)) {
        outbound.outbounds = []
      }
      if (outbound.outbounds.length === 0) {
        if (!compatible) {
          config.outbounds.push(compatible_outbound)
          compatible = true
        }
        log(`🕳 ${outbound.tag} 的 outbounds 为空, 自动插入 COMPATIBLE(direct)`)
        outbound.outbounds.push(compatible_outbound.tag)
      }
    }
  })
})

config.outbounds.push(...proxies)

$content = JSON.stringify(config, null, 2)

function getTags(proxies, regex) {
  return (regex ? proxies.filter(p => regex.test(p.tag)) : proxies).map(p => p.tag)
}
function log(v) {
  console.log(`[📦 sing-box 模板脚本] ${v}`)
}
function createTagRegExp(tagPattern) {
  return new RegExp(tagPattern.replace('ℹ️', ''), tagPattern.includes('ℹ️') ? 'i' : undefined)
}
function createOutboundRegExp(outboundPattern) {
  return new RegExp(outboundPattern.replace('ℹ️', ''), outboundPattern.includes('ℹ️') ? 'i' : undefined)
}

log(`🔚 结束`)