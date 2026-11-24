import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { PAGE_TEMPLATE_CONFIG } from '@/lib/config/post-types';
import { getLegacyRedirectTarget } from '@/lib/config/url-redirects';

type Redirect = {
  origin: string;
  target: string;
  type: 301 | 302;
};

let redirectsCache: Redirect[] = [];
let lastFetch = 0;
// Cache redirects for 30 minutes — same window as page ISR — so the
// middleware never re-queries WordPress more than twice per hour per instance.
const CACHE_DURATION_MS = 30 * 60 * 1000; // 30 minutes

// ─────────────────────────────────────────────────────────────
// Page-template → current WP slug map (for slug-rename handling)
// Plus CPT slug set used as a collision guard so a renamed template
// slug never hijacks an existing service / industry URL.
//
// This slug map is a GraphQL POST, and middleware runs on EVERY request.
// Next.js only caches GET fetches in its Data Cache — a POST is never
// cached — so `next: { revalidate }` alone would let this query hit
// WordPress on every single page view. We therefore mirror getRedirects()
// and keep a process-memory TTL (CACHE_DURATION_MS) so WP is queried at
// most ~twice per hour per instance. Trade-off: editor slug renames take
// up to 30 min to surface, since module memory can't be purged by the
// `wordpress` revalidation tag.
// ─────────────────────────────────────────────────────────────
type SlugRoutingData = {
  templateSlugMap: Record<string, string>;
  reservedCptSlugs: Set<string>;
};

const EMPTY_SLUG_DATA: SlugRoutingData = {
  templateSlugMap: {},
  reservedCptSlugs: new Set(),
};

let slugRoutingCache: SlugRoutingData = EMPTY_SLUG_DATA;
let slugLastFetch = 0;

function basicAuthHeader(): string | null {
  if (process.env.WP_AUTH_USER && process.env.WP_AUTH_PASSWORD) {
    return `Basic ${btoa(`${process.env.WP_AUTH_USER}:${process.env.WP_AUTH_PASSWORD}`)}`;
  }
  return null;
}

// Fetch a WP endpoint preferring no auth (so public REST endpoints aren't
// rejected by WP's auth handler when Basic creds happen to be set), and
// only retry with Basic auth on 401 — that handles staging environments
// fronted by nginx Basic Auth without breaking public REST endpoints.
async function fetchWpWithFallback(
  url: string,
  init: RequestInit,
): Promise<Response> {
  const baseHeaders = { 'Content-Type': 'application/json', ...(init.headers as Record<string, string> | undefined) };
  const noAuthRes = await fetch(url, { ...init, headers: baseHeaders });
  if (noAuthRes.status !== 401) return noAuthRes;
  const auth = basicAuthHeader();
  if (!auth) return noAuthRes;
  return fetch(url, { ...init, headers: { ...baseHeaders, Authorization: auth } });
}

async function getSlugRoutingData(): Promise<SlugRoutingData> {
  const now = Date.now();

  // Honor the cache window even on empty/failure so we never hammer WP on
  // every request (this is a POST, which Next's Data Cache won't cache).
  if (slugLastFetch > 0 && now - slugLastFetch < CACHE_DURATION_MS) {
    return slugRoutingCache;
  }

  const wpApiUrl = (process.env.WP_API_URL || process.env.WORDPRESS_GRAPHQL_URL);
  if (!wpApiUrl) {
    slugLastFetch = now;
    return slugRoutingCache;
  }
  try {
    const res = await fetchWpWithFallback(wpApiUrl, {
      method: 'POST',
      body: JSON.stringify({
        query: `{
          pages(first: 100, where: { status: PUBLISH }) { nodes { slug headlessTemplate } }
          services(first: 200) { nodes { slug } }
          industries(first: 200) { nodes { slug } }
        }`,
      }),
      // @ts-ignore - Next.js extends RequestInit with `next`
      next: { revalidate: 1800, tags: ['wordpress'] },
    });
    if (!res.ok) {
      slugLastFetch = now;
      return slugRoutingCache;
    }
    const json = await res.json();
    const templateSlugMap: Record<string, string> = {};
    for (const node of json?.data?.pages?.nodes || []) {
      if (node?.headlessTemplate && node?.slug) {
        templateSlugMap[node.headlessTemplate] = node.slug;
      }
    }
    const reservedCptSlugs = new Set<string>();
    for (const node of json?.data?.services?.nodes || []) {
      if (node?.slug) reservedCptSlugs.add(node.slug);
    }
    for (const node of json?.data?.industries?.nodes || []) {
      if (node?.slug) reservedCptSlugs.add(node.slug);
    }
    slugRoutingCache = { templateSlugMap, reservedCptSlugs };
    slugLastFetch = now;
    return slugRoutingCache;
  } catch (error) {
    console.error('[TemplateSlugs] Failed to fetch slug routing data:', error);
    slugLastFetch = now;
    return slugRoutingCache;
  }
}

async function getRedirects(): Promise<Redirect[]> {
  const now = Date.now();

  // Honor cache window even when empty/fail, so we don't hammer WP on every request
  if (lastFetch > 0 && now - lastFetch < CACHE_DURATION_MS) {
    return redirectsCache;
  }

  const wpApiUrl = (process.env.WP_API_URL || process.env.WORDPRESS_GRAPHQL_URL);
  if (!wpApiUrl) {
    lastFetch = now;
    return redirectsCache;
  }

  // Get WordPress base URL (without /graphql)
  const wpBaseUrl = wpApiUrl.replace(/\/graphql\/?$/, '');
  const redirectsEndpoint = `${wpBaseUrl}/wp-json/headless/v1/redirects`;

  try {
    // Try without Basic auth first (public endpoint), only fall back to
    // Basic auth on 401 — that handles staging-nginx-protected installs
    // without breaking public WP REST endpoints which would otherwise
    // reject any wrong/extra auth header with 401.
    const response = await fetchWpWithFallback(redirectsEndpoint, {
      // @ts-ignore - Next.js extends RequestInit with `next`
      next: { revalidate: 1800, tags: ['wordpress-redirects'] },
    });

    if (!response.ok) {
      console.warn(`[Redirects] API returned ${response.status}`);
      lastFetch = now;
      return redirectsCache;
    }

    const data = await response.json();
    
    // Support both formats:
    // 1. Headless Tools plugin format: { from_path, to_url, status }
    // 2. Redirection plugin format: { items: [{ url, action_data: { url }, action_code, enabled }] }
    let items: Redirect[] = [];
    
    if (Array.isArray(data)) {
      // Headless Tools plugin format - direct array
      items = data.map((r: { from_path: string; to_url: string; status: number }) => ({
        origin: r.from_path.startsWith('/') ? r.from_path : `/${r.from_path}`,
        target: r.to_url,
        type: (r.status || 301) as 301 | 302,
      }));
    } else if (data.items && Array.isArray(data.items)) {
      // Redirection plugin format - { items: [...] }
      items = data.items
        .filter((r: { enabled: boolean }) => r.enabled)
        .map((r: { url: string; action_data: { url?: string }; action_code: number }) => ({
          origin: r.url.startsWith('/') ? r.url : `/${r.url}`,
          target: r.action_data?.url || '/',
          type: (r.action_code || 301) as 301 | 302,
        }));
    }
    
    redirectsCache = items;
    
    lastFetch = now;
    console.log(`[Redirects] Fetched ${redirectsCache.length} redirects from WordPress`);
  } catch (error) {
    console.error('[Redirects] Failed to fetch redirects:', error);
    lastFetch = now;
  }
  
  return redirectsCache;
}

// ─────────────────────────────────────────────────────────────
// RSC flight-response cache poisoning guard.
// Next.js distinguishes RSC payloads from HTML only via
// `Vary: rsc, next-router-state-tree, ...`, but Cloudflare ignores Vary
// on HTML responses. Both variants otherwise share the same public
// `s-maxage` Cache-Control, so the CDN can cache a `text/x-component`
// flight payload under the plain page URL and serve raw payload text as
// the document (observed live on /services). Detect RSC requests and
// force a non-shared-cacheable Cache-Control on their responses; normal
// HTML keeps its existing caching.
// ─────────────────────────────────────────────────────────────
function isRscRequest(request: NextRequest): boolean {
  return (
    request.headers.get('rsc') === '1' ||
    request.headers.has('next-router-state-tree') ||
    request.headers.has('next-router-prefetch') ||
    request.headers.has('next-router-segment-prefetch') ||
    request.nextUrl.searchParams.has('_rsc')
  );
}

function withRscCacheGuard(request: NextRequest, response: NextResponse): NextResponse {
  if (isRscRequest(request)) {
    response.headers.set('Cache-Control', 'private, no-store, must-revalidate');
  }
  return response;
}

export async function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname;

  // ─────────────────────────────────────────────────────────────
  // Host canonicalization. The deployment answers on BOTH the apex
  // (tenthrock.com) and www (www.tenthrock.com) with 200s, which produces
  // duplicate content across the entire site. 301 the non-www apex → www,
  // preserving path + query, BEFORE any WordPress lookup so it's instant and
  // never depends on WP being reachable. Dev/preview hosts (localhost,
  // *.replit.dev, *.replit.app) are left untouched.
  // ─────────────────────────────────────────────────────────────
  const CANONICAL_HOST = 'www.tenthrock.com';
  const requestHost = (
    request.headers.get('x-forwarded-host') ||
    request.headers.get('host') ||
    ''
  ).toLowerCase();
  const hostname = requestHost.split(':')[0];
  if (hostname === 'tenthrock.com') {
    const target = new URL(
      `${request.nextUrl.pathname}${request.nextUrl.search}`,
      `https://${CANONICAL_HOST}`,
    );
    return NextResponse.redirect(target, 301);
  }

  // ─────────────────────────────────────────────────────────────
  // Site-wide slug restructure (front-end only). 301 legacy URLs to
  // their new homes BEFORE any WordPress lookup so these are instant and
  // never depend on WP being reachable:
  //   /<service-wp-slug>            → /services/<public-slug>
  //   /<industry-wp-slug>           → /industries/<public-slug>
  //   /locations/<state>            → /locations/<state>-junk-removal
  // ─────────────────────────────────────────────────────────────
  const legacyTarget = getLegacyRedirectTarget(path);
  if (legacyTarget && legacyTarget !== path) {
    const url = request.nextUrl.clone();
    url.pathname = legacyTarget;
    // Preserve any existing query string on the redirect.
    return NextResponse.redirect(url, 301);
  }

  // Run both WordPress fetches concurrently so middleware blocks on the
  // slower of the two rather than the sum. Both are tagged `wordpress`
  // (or `wordpress-redirects`) so webhook-driven revalidation still works.
  const [redirects, slugRoutingData] = await Promise.all([
    getRedirects(),
    getSlugRoutingData(),
  ]);

  // Check for exact match or match without trailing slash
  const match = redirects.find(r => 
    r.origin === path || 
    r.origin === path.replace(/\/$/, '') ||
    r.origin + '/' === path
  );

  if (match) {
    const destination = match.target.startsWith('http')
      ? match.target
      : new URL(match.target, request.url).toString();

    // Loop guard: skip a WP-managed redirect whose destination is itself
    // redirected straight back to this path by a legacy alias or another
    // WP rule (e.g. WP sends /locations → /nationwide-waste-management-disposal
    // while LEGACY_ALIASES sends that slug back to /locations → infinite 301s).
    const normalizePath = (p: string) => (p !== '/' && p.endsWith('/') ? p.slice(0, -1) : p);
    // Resolve any redirect target (relative or absolute, with query/fragment)
    // to a bare pathname when it points at this site; null for external
    // origins, which can never re-enter this middleware and so cannot loop.
    const toLocalPath = (target: string): string | null => {
      try {
        const u = new URL(target, request.url);
        const reqOrigin = new URL(request.url);
        const isLocal =
          u.hostname === reqOrigin.hostname ||
          u.hostname === CANONICAL_HOST ||
          u.hostname === hostname;
        return isLocal ? normalizePath(u.pathname) : null;
      } catch {
        return null;
      }
    };
    const destPath = toLocalPath(destination);
    const from = normalizePath(path);
    const legacyBack = destPath !== null ? getLegacyRedirectTarget(destPath) : null;
    const wpBack = destPath !== null
      ? redirects.find(r => normalizePath(r.origin) === destPath)
      : undefined;
    const wpBackPath = wpBack ? toLocalPath(wpBack.target) : null;
    const bouncesBack =
      (legacyBack !== null && normalizePath(legacyBack) === from) ||
      (wpBackPath !== null && wpBackPath === from);
    if (bouncesBack) {
      console.warn(`[Redirects] Skip ${path} -> ${destination}: destination redirects back — would loop.`);
    } else {
      console.log(`[Redirects] ${path} -> ${destination} (${match.type})`);
      return NextResponse.redirect(destination, match.type);
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Page-template slug rename handling.
  // For each registered page template, compare the WP slug against the
  // canonical front-end folder route. If they differ:
  //   • Visiting the WP slug   → rewrite to the canonical folder so the
  //                              existing route renders (URL stays as WP slug).
  //   • Visiting the canonical → 301 redirect to the WP slug, so the public
  //                              URL follows what the editor set in WP.
  //                              (Skipped when canonical is "/" — homepage
  //                               must always remain at root.)
  // Templates with dynamic routes (containing "[slug]") are skipped.
  // Collision guard: if the WP slug matches an existing service or
  // industry CPT slug, we skip — never hijack a CPT URL.
  // ─────────────────────────────────────────────────────────────
  const { templateSlugMap, reservedCptSlugs } = slugRoutingData;
  if (Object.keys(templateSlugMap).length > 0) {
    const normalize = (p: string) => (p !== '/' && p.endsWith('/') ? p.slice(0, -1) : p);
    const reqPath = normalize(path);

    for (const config of Object.values(PAGE_TEMPLATE_CONFIG)) {
      if (config.route.includes('[slug]')) continue;
      const wpSlug = templateSlugMap[config.wpTemplate];
      if (!wpSlug) continue;

      const canonical = normalize(config.route);
      const wpPath = `/${wpSlug}`;
      if (wpPath === canonical) continue; // no rename, nothing to do

      if (reservedCptSlugs.has(wpSlug)) {
        console.warn(`[TemplateSlugs] Skip ${config.wpTemplate}: WP slug "${wpSlug}" collides with an existing service/industry CPT slug.`);
        continue;
      }

      // Loop guard: if a redirect (WP-managed or legacy alias) already 301s
      // the WP slug somewhere (typically back to the canonical route),
      // following the slug rename would create an infinite redirect loop:
      //   canonical → wpPath (this leg) → canonical (redirect) → …
      // Seen live on /locations ↔ /nationwide-waste-management-disposal,
      // /services ↔ /commercial-waste, /about-us ↔ /about. Skip both legs:
      // the canonical route serves 200 directly, and the WP-slug URL keeps
      // its single existing 301.
      const legacyTargetForWpPath = getLegacyRedirectTarget(wpPath);
      const wpPathRedirected = redirects.some(r =>
        r.origin === wpPath || r.origin === `${wpPath}/`,
      ) || (legacyTargetForWpPath !== null && legacyTargetForWpPath !== wpPath);
      if (wpPathRedirected) {
        console.warn(`[TemplateSlugs] Skip ${config.wpTemplate}: WP slug path "${wpPath}" is itself redirected — following the rename would loop.`);
        continue;
      }

      // Request hits the WP slug → rewrite to the canonical folder route.
      if (reqPath === wpPath) {
        const url = request.nextUrl.clone();
        url.pathname = canonical;
        console.log(`[TemplateSlugs] rewrite ${path} -> ${canonical} (template ${config.wpTemplate})`);
        return withRscCacheGuard(request, NextResponse.rewrite(url));
      }

      // Request hits the canonical folder route → 301 to the new WP slug,
      // so the public URL reflects the editor's slug change.
      // (Don't redirect away from the homepage.)
      if (canonical !== '/' && reqPath === canonical) {
        const url = request.nextUrl.clone();
        url.pathname = wpPath;
        console.log(`[TemplateSlugs] redirect ${path} -> ${wpPath} (template ${config.wpTemplate})`);
        return NextResponse.redirect(url, 301);
      }
    }
  }

  return withRscCacheGuard(request, NextResponse.next());
}

export const config = {
  matcher: [
    // Match all paths except static files and API routes
    '/((?!api|_next/static|_next/image|favicon.ico|.*\\..*).*)',
  ],
};
