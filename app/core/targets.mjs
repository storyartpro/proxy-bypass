// Target validation for the blocked list: a target is a domain, an IP address
// or a CIDR subnet. The same rules are used by the API, the router and the
// server push, so the UI and the daemons agree on what is allowed.

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i;
const IPV4_CIDR_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;

export function isIpv4(value) {
  return IPV4_RE.test(String(value || "").trim());
}

export function isIpv4Cidr(value) {
  return IPV4_CIDR_RE.test(String(value || "").trim());
}

export function isDomain(value) {
  return DOMAIN_RE.test(String(value || "").trim().replace(/\.$/, ""));
}

/** IPv4 as an unsigned 32-bit number, or null. */
export function ipv4ToNumber(value) {
  if (!isIpv4(value)) return null;
  return String(value)
    .trim()
    .split(".")
    .reduce((acc, part) => (acc * 256 + Number(part)) >>> 0, 0) >>> 0;
}

function cidrToRange(cidr) {
  const [address, bitsText] = String(cidr).trim().split("/");
  const base = ipv4ToNumber(address);
  if (base === null) return null;
  const bits = Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : ((0xffffffff << (32 - bits)) >>> 0);
  const network = (base & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return { network, broadcast };
}

/** True when the IPv4 address belongs to the CIDR subnet. */
export function ipInCidr(ip, cidr) {
  const address = ipv4ToNumber(ip);
  const range = cidrToRange(cidr);
  if (address === null || !range) return false;
  return address >= range.network && address <= range.broadcast;
}

/**
 * Validate and normalise one blocked-list entry.
 * @returns {{kind:'domain'|'ip'|'cidr', value:string}}
 */
export function normalizeTarget(input) {
  const raw = String(input ?? "").trim().replace(/\.$/, "");
  if (!raw) throw new Error("пустое значение");
  const lower = raw.toLowerCase();
  if (isIpv4(lower)) return { kind: "ip", value: lower };
  if (isIpv4Cidr(lower)) {
    const [address, bits] = lower.split("/");
    const range = cidrToRange(`${address}/${bits}`);
    if (!range) throw new Error("некорректная подсеть");
    return { kind: "cidr", value: `${address}/${bits}` };
  }
  if (isDomain(lower)) return { kind: "domain", value: lower };
  throw new Error("нужен домен, IPv4-адрес или подсеть вида 10.0.0.0/24");
}

/** Split a blocked list into the parts each server command understands. */
export function splitTargets(entries) {
  const domains = [];
  const subnets = [];
  for (const entry of entries || []) {
    try {
      const target = normalizeTarget(entry);
      if (target.kind === "domain") domains.push(target.value);
      else if (target.kind === "ip") subnets.push(`${target.value}/32`);
      else subnets.push(target.value);
    } catch {
      /* skip legacy/invalid entries instead of failing the push */
    }
  }
  return { domains, subnets };
}
