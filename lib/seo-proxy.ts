import { headers } from 'next/headers';
import { getLegacyRedirectTarget } from '@/lib/config/url-redirects';

function getWordPressBaseUrl(): string {
  const wpApiUrl = (process.env.WP_API_URL || process.env.WORDPRESS_GRAPHQL_URL) || '';
  return wpApiUrl.replace(/\/graphql\/?$/, '');
}

function shouldUseBasicAuth(): boolean {
  const enabled = process.env.WP_BASIC_AUTH_ENABLED;
  if (enabled === 'false' || enabled === '0') {
    return false;
  }
  return !!(process.env.WP_AUTH_USER && process.env.WP_AUTH_PASSWORD);
}

function getWordPressAuthHeaders(): Record<string, string> {
  const authHeaders: Record<string, string> = {};
  if (shouldUseBasicAuth()) {
    const credentials = Buffer.from(
      `${process.env.WP_AUTH_USER}:${process.env.WP_AUTH_PASSWORD}`
    ).toString('base64');
    authHeaders['Authorization'] = `Basic ${credentials}`;
  }
  return authHeaders;
}

export async function getFrontendUrl(): Promise<string> {
  if (process.env.FRONTEND_URL) {
    return process.env.FRONTEND_URL.replace(/\/$/, '');
  }
  
  const headersList = await headers();
  const host = headersList.get('x-forwarded-host') || headersList.get('host') || '';
  const protocol = headersList.get('x-forwarded-proto') || 'https';
  return `${protocol}://${host}`;
}

function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export async function proxyWordPressFile(
  wpPath: string, 
  frontendUrl: string,
  rewritePaths = false
): Promise<{ content: string; contentType: string } | null> {
  const wpBaseUrl = getWordPressBaseUrl();
  if (!wpBaseUrl) {
    return null;
  }

  try {
    const authHeaders = getWordPressAuthHeaders();
    const response = await fetch(`${wpBaseUrl}${wpPath}`, { 
      headers: authHeaders,
      next: { revalidate: 1800, tags: ['wordpress'] }
    });
    
    if (!response.ok) {
      return null;
    }

    let content = await response.text();
    const contentType = response.headers.get('content-type') || 'text/plain';

    const wpUrl = new URL(wpBaseUrl);
    const wpDomain = wpUrl.origin;
    const wpHost = wpUrl.host;
    const frontendUrlObj = new URL(frontendUrl);
    const frontendHost = frontendUrlObj.host;
    
    content = content.replace(new RegExp(escapeRegExp(wpDomain), 'g'), frontendUrl);
    content = content.replace(new RegExp(`//${escapeRegExp(wpHost)}`, 'g'), `//${frontendHost}`);

    // Sitemap/loc URL path rewriting: after the host has been swapped to the
    // frontend, rewrite any legacy service/industry/location path to its new
    // canonical home so crawled URLs never 301-bounce. Only enabled for XML
    // sitemaps (CSS/other proxied files have no such paths).
    if (rewritePaths) {
      const feOrigin = frontendUrlObj.origin;
      content = content.replace(
        new RegExp(escapeRegExp(feOrigin) + '(/[^<>"\\s]*)', 'g'),
        (_full: string, p: string) => {
          const hadTrailing = p.length > 1 && p.endsWith('/');
          const lookup = hadTrailing ? p.slice(0, -1) : p;
          // Resolve any legacy service/industry/location path to its new home;
          // otherwise keep the path (already slash-stripped above for non-root).
          const finalPath = getLegacyRedirectTarget(lookup) || lookup;
          // Emit the final, non-redirecting URL. trailingSlash is false, so Next
          // 308s "/path/" -> "/path"; listing the slash-stripped form keeps every
          // sitemap <loc> a 200 that matches its self-canonical. The homepage "/"
          // is preserved because its lookup stays "/".
          return `${feOrigin}${finalPath}`;
        }
      );
    }

    return { content, contentType };
  } catch (error) {
    console.error(`Error fetching ${wpPath} from WordPress:`, error);
    return null;
  }
}
